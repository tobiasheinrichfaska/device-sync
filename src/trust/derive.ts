// The trust derivation (docs/wire-format.md, "Trust derivation"). One engine, written as a generator
// that asks for signature checks, so the same code runs asynchronously (`deriveAsync`, real checks) and
// synchronously for decisions about this device's own log (`deriveSync`, the log counts as judged).
import { importPublicKey, isPoint, verifyText } from '../core/index.ts';
import {
  changeCheckValue,
  changeSigningText,
  isNewer,
  liveRecords,
  type Change,
  type DeviceId,
  type Replica,
} from '../log/index.ts';
import { LogCache } from '../log/logCache.ts';
import { resolveValidators } from './ids.ts';
import { byName } from './known.ts';
import type {
  KnownDevice,
  Trust,
  TrustedDevice,
  TrustOptions,
  TrustReason,
  Validators,
} from './types.ts';

/** Default name of the reserved collection that holds the device list. */
export const DEVICE_COLLECTION = 'device';
/** The fields of an entry that say who the device is. */
const IDENTITY = ['name', 'sig', 'dh', 'role', 'relayId', 'private'] as const;
const FIELDS = [...IDENTITY, 'removed'] as const;

/** One write of one field of an entry, with the change it came in. */
export interface Write {
  readonly value: unknown;
  readonly device: DeviceId;
  readonly seq: number;
  readonly clock: number;
  readonly change: Change;
}

/** The writes to the entries of the device list, by entry and field (newest first), built in one pass. */
export interface EntryIndex {
  readonly targets: Map<string, Map<string, Write[]>>;
  /** Per writer the entries it wrote identity fields of. */
  readonly byWriter: Map<string, Set<string>>;
}

const newestFirst = (a: Write, b: Write): number =>
  isNewer(a, b) ? -1 : isNewer(b, a) ? 1 : a.seq - b.seq;

function buildIndex(replica: Replica, collection: string): EntryIndex {
  const live = new Set(liveRecords(replica, collection).map((r) => r.id));
  const targets = new Map<string, Map<string, Write[]>>();
  const byWriter = new Map<string, Set<string>>();
  for (const change of replica.log) {
    if (change.kind !== 'set' || change.collection !== collection || !change.fields) continue;
    if (!live.has(change.id)) continue;
    for (const field of FIELDS) {
      if (!Object.hasOwn(change.fields, field)) continue;
      let fields = targets.get(change.id);
      if (!fields) targets.set(change.id, (fields = new Map()));
      let writes = fields.get(field);
      if (!writes) fields.set(field, (writes = []));
      writes.push({
        value: change.fields[field],
        device: change.device,
        seq: change.seq,
        clock: change.clock,
        change,
      });
      if (field !== 'removed' && change.device !== change.id) {
        let set = byWriter.get(change.device);
        if (!set) byWriter.set(change.device, (set = new Set()));
        set.add(change.id);
      }
    }
  }
  for (const fields of targets.values())
    for (const writes of fields.values()) writes.sort(newestFirst);
  return { targets, byWriter };
}

const pointMemo = new Map<string, boolean>();
/** `isPoint` remembered (decoding a key is the dearest step of a derivation that runs per replica state). */
const isKey = (v: unknown): v is string => {
  if (typeof v !== 'string') return false;
  let known = pointMemo.get(v);
  if (known === undefined) {
    if (pointMemo.size >= 20_000) pointMemo.clear();
    pointMemo.set(v, (known = isPoint(v)));
  }
  return known;
};

const indexes = new LogCache<Map<string, EntryIndex>>();

/** The index of a replica's device list, kept per log array (a log is never changed after a merge made it). */
export function entryIndex(replica: Replica, collection: string): EntryIndex {
  const perLog = indexes.getOrBuild(replica.log, () => new Map());
  let index = perLog.get(collection);
  if (!index) perLog.set(collection, (index = buildIndex(replica, collection)));
  return index;
}

/** A request for a signature check: is this write signed by this key? */
export interface Need {
  readonly write: Write;
  readonly sigKey: string;
}
type Gen<T> = Generator<Need, T, boolean>;

interface Member {
  entry: TrustedDevice;
  voucher: boolean;
  /** The entry as the log vouches for it (for a met device it may be missing or differ from `entry`). */
  logEntry: TrustedDevice | undefined;
}
type Members = Map<string, Member>;

interface Ctx {
  readonly replica: Replica;
  readonly own: DeviceId;
  readonly o: TrustOptions;
  readonly valid: Validators;
  readonly roleCounts: (role: string, replica: Replica) => boolean;
  readonly index: EntryIndex;
  readonly direct: readonly KnownDevice[];
  readonly directById: ReadonlyMap<string, KnownDevice>;
  readonly memo: Map<Change, Map<string, boolean>>;
}

function* verified(ctx: Ctx, write: Write, sigKey: string): Gen<boolean> {
  let per = ctx.memo.get(write.change);
  if (!per) ctx.memo.set(write.change, (per = new Map()));
  const known = per.get(sigKey);
  if (known !== undefined) return known;
  const result = yield { write, sigKey };
  per.set(sigKey, result);
  return result;
}

const sameEntry = (a: TrustedDevice, b: TrustedDevice): boolean =>
  a.name === b.name &&
  a.sig === b.sig &&
  a.dh === b.dh &&
  a.role === b.role &&
  a.roleVouched === b.roleVouched &&
  a.relayId === b.relayId &&
  a.private === b.private;

/** The newest valid value of a field that a vouching device wrote (this device's own writes count unchecked). */
function* pick(
  ctx: Ctx,
  members: Members,
  target: string,
  field: (typeof FIELDS)[number],
  accept: (value: unknown) => boolean,
): Gen<unknown> {
  for (const w of ctx.index.targets.get(target)?.get(field) ?? []) {
    if (w.device === target) continue;
    if (w.device !== ctx.own) {
      const m = members.get(w.device);
      if (!m?.voucher || !(yield* verified(ctx, w, m.entry.sig))) continue;
    }
    if (accept(w.value)) return w.value;
  }
  return undefined;
}

function learnedEntry(ctx: Ctx, b: KnownDevice): TrustedDevice {
  const roleOk = b.role !== undefined && ctx.valid.role(b.role);
  const { role: _role, ...rest } = b;
  return {
    ...rest,
    ...(roleOk && ctx.roleCounts(b.role as string, ctx.replica) ? { role: b.role as string } : {}),
    ...(roleOk ? { roleVouched: b.role as string } : {}),
    removed: false,
    private: false,
  };
}

function* evaluate(
  ctx: Ctx,
  members: Members,
  t: string,
): Gen<{ entry: TrustedDevice; logEntry: TrustedDevice | undefined } | undefined> {
  const { valid } = ctx;
  const name = yield* pick(ctx, members, t, 'name', (v) => typeof v === 'string' && valid.name(v));
  const sig = yield* pick(ctx, members, t, 'sig', isKey);
  const dh = yield* pick(ctx, members, t, 'dh', isKey);
  // name, sig and dh were checked while picking; the rest of `parseIntroduction`:
  const intro =
    valid.deviceId(t) && typeof name === 'string' && isKey(sig) && isKey(dh) && sig !== dh
      ? { device: t, name, sig, dh }
      : undefined;
  let logEntry: TrustedDevice | undefined;
  if (intro) {
    const role = yield* pick(
      ctx,
      members,
      t,
      'role',
      (v) => typeof v === 'string' && valid.role(v),
    );
    const relay = yield* pick(
      ctx,
      members,
      t,
      'relayId',
      (v) => typeof v === 'string' && valid.relayId(v),
    );
    const priv = yield* pick(ctx, members, t, 'private', () => true);
    const roleOk = typeof role === 'string';
    logEntry = {
      ...intro,
      ...(roleOk && ctx.roleCounts(role, ctx.replica) ? { role } : {}),
      ...(roleOk ? { roleVouched: role } : {}),
      ...(typeof relay === 'string' ? { relayId: relay } : {}),
      removed: false,
      private: priv === true,
    };
  }
  const learned = ctx.directById.get(t);
  if (!learned) return logEntry ? { entry: logEntry, logEntry } : undefined;
  // A device met in person keeps the keys learned in person; a role it lacks may come from the log.
  let entry = learnedEntry(ctx, learned);
  if (!entry.role && logEntry?.role && logEntry.sig === learned.sig && logEntry.dh === learned.dh) {
    entry = { ...entry, role: logEntry.role, roleVouched: logEntry.role };
  }
  return { entry, logEntry };
}

const byDevice = (a: readonly [string, unknown], b: readonly [string, unknown]): number =>
  a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;

/**
 * Potential trust: the least fixpoint from the devices met in person (rule 1), in synchronous rounds.
 * A round looks only at the state at its start and adds its results together, so the result does not
 * depend on any order. `excluded` devices never join (met ones that are excluded are left out too).
 */
function* closure(ctx: Ctx, excluded: ReadonlySet<string>): Gen<Members> {
  const members: Members = new Map();
  const entries: TrustedDevice[] = [];
  const position = new Map<string, number>();
  const can = (entry: TrustedDevice): boolean => {
    try {
      return ctx.o.voucher.canVouch(entry, entries) === true;
    } catch {
      return false;
    }
  };
  for (const d of ctx.direct) {
    if (excluded.has(d.device) || members.has(d.device)) continue;
    const entry = learnedEntry(ctx, d);
    members.set(d.device, { entry, voucher: false, logEntry: undefined });
    position.set(d.device, entries.length);
    entries.push(entry);
  }
  let dirty = new Set<string>(members.keys());
  for (const [id, m] of members) {
    m.voucher = can(m.entry);
    if (m.voucher) for (const t of ctx.index.byWriter.get(id) ?? []) dirty.add(t);
  }
  for (const t of ctx.index.byWriter.get(ctx.own) ?? []) dirty.add(t);
  const maxRounds = 64 + 4 * (ctx.index.targets.size + ctx.direct.length);
  for (let round = 0; dirty.size > 0 && round < maxRounds; round += 1) {
    const staged: [string, { entry: TrustedDevice; logEntry: TrustedDevice | undefined }][] = [];
    for (const t of dirty) {
      if (t === ctx.own || excluded.has(t)) continue;
      const found = yield* evaluate(ctx, members, t);
      if (found) staged.push([t, found]);
    }
    staged.sort(byDevice);
    const changed: string[] = [];
    for (const [t, found] of staged) {
      const there = members.get(t);
      if (!there) {
        members.set(t, { entry: found.entry, voucher: false, logEntry: found.logEntry });
        position.set(t, entries.length);
        entries.push(found.entry);
        changed.push(t);
      } else {
        there.logEntry = found.logEntry;
        if (!sameEntry(there.entry, found.entry)) {
          there.entry = found.entry;
          entries[position.get(t) as number] = found.entry;
          changed.push(t);
        }
      }
    }
    const next = new Set<string>();
    for (const t of changed) {
      const m = members.get(t) as Member;
      const was = m.voucher;
      m.voucher = can(m.entry);
      if (was || m.voucher) for (const w of ctx.index.byWriter.get(t) ?? []) next.add(w);
    }
    dirty = next;
  }
  return members;
}

const NONE: ReadonlySet<string> = new Set();

interface Analysis {
  readonly keyConflict: Set<string>;
  readonly keyMismatch: Set<string>;
  readonly relayConflict: Set<string>;
}

/** Rule 2: all values vouching devices ever wrote for the keys and the relay id of each entry. */
function* analyse(ctx: Ctx, members: Members): Gen<Analysis> {
  const out: Analysis = {
    keyConflict: new Set(),
    keyMismatch: new Set(),
    relayConflict: new Set(),
  };
  const kinds = [
    ['sig', isKey],
    ['dh', isKey],
    ['relayId', (v: string) => ctx.valid.relayId(v)],
  ] as const;
  for (const [t, fields] of ctx.index.targets) {
    if (t === ctx.own) continue;
    const seen = { sig: new Set<string>(), dh: new Set<string>(), relayId: new Set<string>() };
    for (const [field, fine] of kinds) {
      for (const w of fields.get(field) ?? []) {
        if (w.device === t || typeof w.value !== 'string' || !fine(w.value)) continue;
        if (w.device !== ctx.own) {
          const m = members.get(w.device);
          if (!m?.voucher || !(yield* verified(ctx, w, m.entry.sig))) continue;
        }
        seen[field].add(w.value);
      }
    }
    const learned = ctx.directById.get(t);
    if (learned) {
      if (
        [...seen.sig].some((s) => s !== learned.sig) ||
        [...seen.dh].some((d) => d !== learned.dh)
      ) {
        out.keyMismatch.add(t);
      }
    } else {
      if (seen.sig.size > 1 || seen.dh.size > 1) out.keyConflict.add(t);
      if (seen.relayId.size > 1) out.relayConflict.add(t);
    }
  }
  return out;
}

/** Rule 3: the effective removals, evaluated statically on the potential trust (never on the shrinking result). */
function* removalsOf(ctx: Ctx, members: Members): Gen<Map<string, number[]>> {
  const removed = new Map<string, number[]>();
  const adjacent = new Map<string, string[]>();
  const reaches = new Map<string, Set<string>>();
  const vouches = (id: string): boolean => id === ctx.own || members.get(id)?.voucher === true;

  /** The entries a voucher wrote (verified) identity fields of, that are in the potential trust. */
  function* edges(u: string): Gen<string[]> {
    const known = adjacent.get(u);
    if (known) return known;
    const found: string[] = [];
    for (const w of ctx.index.byWriter.get(u) ?? []) {
      if (!members.has(w)) continue;
      let wrote = false;
      for (const field of IDENTITY) {
        for (const write of ctx.index.targets.get(w)?.get(field) ?? []) {
          if (write.device !== u) continue;
          if (
            u === ctx.own ||
            (yield* verified(ctx, write, (members.get(u) as Member).entry.sig))
          ) {
            wrote = true;
            break;
          }
        }
        if (wrote) break;
      }
      if (wrote) found.push(w);
    }
    adjacent.set(u, found);
    return found;
  }

  /** Everything reachable from the met devices (and this device) without passing through `avoid`. */
  function* reachAvoiding(avoid: string): Gen<Set<string>> {
    const known = reaches.get(avoid);
    if (known) return known;
    const seen = new Set<string>();
    const queue: string[] = [];
    const roots = [ctx.own, ...ctx.direct.map((d) => d.device)].filter(
      (id) => members.has(id) || id === ctx.own,
    );
    for (const id of roots) {
      if (id !== avoid && !seen.has(id)) {
        seen.add(id);
        queue.push(id);
      }
    }
    for (let i = 0; i < queue.length; i += 1) {
      const u = queue[i] as string;
      if (!vouches(u)) continue;
      for (const w of yield* edges(u)) {
        if (w !== avoid && !seen.has(w)) {
          seen.add(w);
          queue.push(w);
        }
      }
    }
    reaches.set(avoid, seen);
    return seen;
  }

  for (const [t, fields] of ctx.index.targets) {
    const writes = fields.get('removed');
    if (!writes) continue;
    const spoken = new Set<string>();
    for (const w of writes) {
      // Per writer only its newest "true" counts; nobody takes a removal back by writing "false".
      if (w.value !== true || spoken.has(w.device)) continue;
      spoken.add(w.device);
      if (w.device === t || !vouches(w.device)) continue;
      if (
        w.device !== ctx.own &&
        !(yield* verified(ctx, w, (members.get(w.device) as Member).entry.sig))
      ) {
        continue;
      }
      if (!(yield* reachAvoiding(t)).has(w.device)) continue;
      const list = removed.get(t) ?? [];
      const last = w.change.fields?.lastSeq;
      if (Number.isSafeInteger(last) && (last as number) >= 0) list.push(last as number);
      removed.set(t, list);
    }
  }
  return removed;
}

export interface Derived {
  readonly trust: Trust;
  /** For the trusted devices: the entry as the log vouches for it (differs from the trusted entry for a met device). */
  readonly logEntries: ReadonlyMap<string, TrustedDevice>;
}

/** The whole derivation (rules 1 to 5), see `docs/wire-format.md`. */
export function* derive(
  replica: Replica,
  direct: readonly KnownDevice[],
  o: TrustOptions,
): Gen<Derived> {
  const sorted = [...direct].sort((a, b) =>
    a.device < b.device ? -1 : a.device > b.device ? 1 : 0,
  );
  const ctx: Ctx = {
    replica,
    own: replica.device,
    o,
    valid: resolveValidators(o.valid),
    roleCounts: o.roleCounts ?? (() => true),
    index: entryIndex(replica, o.collection ?? DEVICE_COLLECTION),
    direct: sorted,
    directById: new Map(sorted.map((d) => [d.device, d])),
    memo: new Map(),
  };
  const p0 = yield* closure(ctx, NONE);
  const analysis = yield* analyse(ctx, p0);
  const p1 = analysis.keyConflict.size === 0 ? p0 : yield* closure(ctx, analysis.keyConflict);
  const removals = yield* removalsOf(ctx, p1);
  const removedIds = [...removals.keys()].filter((id) => id !== ctx.own).sort();
  const t =
    removedIds.length === 0
      ? p1
      : yield* closure(ctx, new Set([...analysis.keyConflict, ...removedIds]));

  const dropRelay = (id: string, e: TrustedDevice): TrustedDevice => {
    if (!analysis.relayConflict.has(id) || e.relayId === undefined) return e;
    const { relayId: _relay, ...rest } = e;
    return rest;
  };
  const trusted = [...t].map(([id, m]) => dropRelay(id, m.entry)).sort(byName);
  const gone: TrustedDevice[] = [];
  for (const id of removedIds) {
    const m = p1.get(id);
    if (m) gone.push({ ...dropRelay(id, m.entry), removed: true });
  }
  const checkable = [...trusted, ...gone].sort(byName);
  const cutoffs = new Map<string, number>();
  for (const id of removedIds) {
    const list = removals.get(id) ?? [];
    if (list.length > 0) cutoffs.set(id, Math.min(...list));
  }
  const reasons = new Map<string, TrustReason[]>();
  const add = (id: string, reason: TrustReason): void => {
    const list = reasons.get(id);
    if (list) list.push(reason);
    else reasons.set(id, [reason]);
  };
  for (const id of [...analysis.keyConflict].sort()) add(id, 'key-conflict');
  for (const id of [...analysis.keyMismatch].sort()) add(id, 'key-mismatch');
  for (const id of [...analysis.relayConflict].sort()) add(id, 'relay-conflict');
  for (const id of removedIds) add(id, 'removed');
  return {
    trust: {
      trusted,
      checkable,
      removed: removedIds,
      selfRemoved: removals.has(ctx.own),
      checkableById: new Map(checkable.map((d) => [d.device, d])),
      cutoffs,
      reasons,
    },
    logEntries: new Map(
      [...t].flatMap(([id, m]) => (m.logEntry ? [[id, m.logEntry] as const] : [])),
    ),
  };
}

/** Synchronous run: the log counts as judged (it was taken through `readChanges`), nothing is verified again. */
export function deriveSync(
  replica: Replica,
  direct: readonly KnownDevice[],
  o: TrustOptions,
): Derived {
  const run = derive(replica, direct, o);
  let step = run.next(true);
  while (!step.done) step = run.next(true);
  return step.value;
}

const verdicts = new WeakMap<Change, Map<string, boolean>>();

/** Asynchronous run with real signature checks; a verdict is kept per change object across runs. */
export async function deriveAsync(
  replica: Replica,
  direct: readonly KnownDevice[],
  o: TrustOptions,
): Promise<Derived> {
  const scope = `${o.appId}\u0000${o.dataSet}\u0000`;
  const keys = new Map<string, Promise<CryptoKey | undefined>>();
  const keyOf = (sig: string): Promise<CryptoKey | undefined> => {
    let key = keys.get(sig);
    if (!key) keys.set(sig, (key = importPublicKey(sig, 'sig')));
    return key;
  };
  const check = async ({ write, sigKey }: Need): Promise<boolean> => {
    const { change } = write;
    let per = verdicts.get(change);
    if (!per) verdicts.set(change, (per = new Map()));
    const memo = `${scope}${sigKey}`;
    const known = per.get(memo);
    if (known !== undefined) return known;
    let result = false;
    if (
      change.kind === 'set' &&
      change.sig &&
      change.check &&
      changeCheckValue(change) === change.check
    ) {
      const key = await keyOf(sigKey);
      result =
        key !== undefined &&
        (await verifyText(key, changeSigningText(o.appId, change, o.dataSet), change.sig));
    }
    per.set(memo, result);
    return result;
  };
  const run = derive(replica, direct, o);
  let step = run.next();
  while (!step.done) {
    const memo = `${scope}${step.value.sigKey}`;
    const known = verdicts.get(step.value.write.change)?.get(memo);
    step = run.next(known ?? (await check(step.value)));
  }
  return step.value;
}
