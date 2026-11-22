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
/**
 * The most signing keys one entry's own writes are tried under (the newest distinct ones that counting
 * writes gave it). A voucher can write any number of keys into an entry; without a bound the cost of
 * checking an entry's writes would be keys times writes.
 */
export const MAX_CANDIDATE_KEYS = 8;
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
  /**
   * The signing keys the device's own writes may verify under: the one learned in person for a met
   * device, else every signing key a counting write ever gave the entry. A voucher that writes
   * another key into the entry cannot make the device's own writes unverifiable by it.
   */
  keys: ReadonlySet<string>;
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
  /** Per set of candidate keys the one that verified last: tried first next time. */
  readonly lastHit: Map<ReadonlySet<string>, string>;
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

/** Whether the write verifies under any of the keys. */
function* verifiedBy(ctx: Ctx, write: Write, keys: ReadonlySet<string>): Gen<boolean> {
  const first = ctx.lastHit.get(keys);
  if (first !== undefined && (yield* verified(ctx, write, first))) return true;
  for (const key of keys) {
    if (key === first) continue;
    if (yield* verified(ctx, write, key)) {
      ctx.lastHit.set(keys, key);
      return true;
    }
  }
  return false;
}

/** A write counts when its writer is this device (it holds its own log) or a vouching member whose keys verify it. */
function* counts(ctx: Ctx, members: Members, w: Write): Gen<boolean> {
  if (w.device === ctx.own) return true;
  const m = members.get(w.device);
  return m?.voucher === true && (yield* verifiedBy(ctx, w, m.keys));
}

const sameEntry = (a: TrustedDevice, b: TrustedDevice): boolean =>
  a.name === b.name &&
  a.sig === b.sig &&
  a.dh === b.dh &&
  a.role === b.role &&
  a.roleVouched === b.roleVouched &&
  a.relayId === b.relayId &&
  a.private === b.private;

const sameKeys = (a: ReadonlySet<string>, b: ReadonlySet<string>): boolean =>
  a.size === b.size && [...a].every((k) => b.has(k));

/** The valid values of a field that counting writes wrote, newest first, each once (only the newest unless `all`). */
function* gather(
  ctx: Ctx,
  members: Members,
  target: string,
  field: (typeof FIELDS)[number],
  accept: (value: unknown) => boolean,
  all = false,
): Gen<unknown[]> {
  const out: unknown[] = [];
  for (const w of ctx.index.targets.get(target)?.get(field) ?? []) {
    if (w.device === target || !accept(w.value) || out.includes(w.value)) continue;
    if (!(yield* counts(ctx, members, w))) continue;
    out.push(w.value);
    if (!all) break;
  }
  return out;
}

function* pick(
  ctx: Ctx,
  members: Members,
  target: string,
  field: (typeof FIELDS)[number],
  accept: (value: unknown) => boolean,
): Gen<unknown> {
  return (yield* gather(ctx, members, target, field, accept))[0];
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

interface Found {
  entry: TrustedDevice;
  logEntry: TrustedDevice | undefined;
  keys: ReadonlySet<string>;
}

function* evaluate(ctx: Ctx, members: Members, t: string): Gen<Found | undefined> {
  const { valid } = ctx;
  const name = yield* pick(ctx, members, t, 'name', (v) => typeof v === 'string' && valid.name(v));
  const sigs = (yield* gather(ctx, members, t, 'sig', isKey, true)) as string[];
  const sig = sigs[0];
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
  if (!learned) {
    return logEntry
      ? { entry: logEntry, logEntry, keys: new Set(sigs.slice(0, MAX_CANDIDATE_KEYS)) }
      : undefined;
  }
  // A device met in person keeps the keys learned in person; a role it lacks may come from the log.
  let entry = learnedEntry(ctx, learned);
  if (!entry.role && logEntry?.role && logEntry.sig === learned.sig && logEntry.dh === learned.dh) {
    entry = { ...entry, role: logEntry.role, roleVouched: logEntry.role };
  }
  return { entry, logEntry, keys: new Set([learned.sig]) };
}

const byDevice = (a: readonly [string, unknown], b: readonly [string, unknown]): number =>
  a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;

/**
 * The devices that vouch from the start: the ones met in person. `excluded` devices never join (met
 * ones that are excluded are left out too).
 *
 * Potential trust (rule 1): in synchronous rounds a device joins when its entry, as the counting
 * writes give it, is valid. A round looks only at the state at its start and adds its results
 * together, so the result does not depend on any order. Membership only grows (a device that joined
 * stays), the voucher flag follows the newest entry (a later write of another role can withdraw it);
 * the number of rounds is bounded.
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
    members.set(d.device, {
      entry,
      voucher: false,
      logEntry: undefined,
      keys: new Set([d.sig]),
    });
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
    const staged: [string, Found][] = [];
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
        members.set(t, {
          entry: found.entry,
          voucher: false,
          logEntry: found.logEntry,
          keys: found.keys,
        });
        position.set(t, entries.length);
        entries.push(found.entry);
        changed.push(t);
      } else {
        there.logEntry = found.logEntry;
        const keysChanged = !sameKeys(there.keys, found.keys);
        there.keys = found.keys;
        if (!sameEntry(there.entry, found.entry)) {
          there.entry = found.entry;
          entries[position.get(t) as number] = found.entry;
          changed.push(t);
        } else if (keysChanged) changed.push(t);
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

/**
 * Rule 2 and 3: the effective removals, rank by rank, on the potential trust. Every device of the
 * potential trust that is reachable from the met devices (and this device) gets a RANK, its distance
 * in the vouching graph (met devices and this device: 0). The ranks act in ascending order, and all
 * devices of one rank act at the same time. A device acts when it is not removed by a device of a
 * STRICTLY lower rank, when it vouches and when it is reachable by a chain that does not pass through
 * the target: it removes every device it wrote a verified `removed: true` into. There is no
 * tie-break by device id (a joining device chooses its own id): two devices of one rank that remove
 * each other are both removed. A removal persists after the remover itself is removed by a device of
 * the same or a higher rank; only a device of lower rank can undo it (by removing the remover first).
 * This device itself never loses the right to remove (it holds its own log).
 */
function* removalsOf(ctx: Ctx, members: Members): Gen<Set<string>> {
  const adjacent = new Map<string, string[]>();
  const reaches = new Map<string, Set<string>>();
  const vouches = (id: string): boolean => id === ctx.own || members.get(id)?.voucher === true;
  const wroteBy = function* (u: string, write: Write): Gen<boolean> {
    return u === ctx.own || (yield* verifiedBy(ctx, write, members.get(u)?.keys ?? NONE));
  };

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
          if (yield* wroteBy(u, write)) {
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

  const roots = [ctx.own, ...ctx.direct.map((d) => d.device)].filter(
    (id) => members.has(id) || id === ctx.own,
  );

  /** Everything reachable from the roots without passing through `avoid`, and (for no `avoid`) the distances. */
  function* walk(avoid: string | undefined): Gen<Map<string, number>> {
    const rank = new Map<string, number>();
    const queue: string[] = [];
    for (const id of roots) {
      if (id !== avoid && !rank.has(id)) {
        rank.set(id, 0);
        queue.push(id);
      }
    }
    for (let i = 0; i < queue.length; i += 1) {
      const u = queue[i] as string;
      if (!vouches(u)) continue;
      for (const w of yield* edges(u)) {
        if (w !== avoid && !rank.has(w)) {
          rank.set(w, (rank.get(u) as number) + 1);
          queue.push(w);
        }
      }
    }
    return rank;
  }
  function* reachAvoiding(avoid: string): Gen<Set<string>> {
    const known = reaches.get(avoid);
    if (known) return known;
    const set = new Set((yield* walk(avoid)).keys());
    reaches.set(avoid, set);
    return set;
  }

  // The `removed: true` writes per writer and target (a write by the target itself counts for nothing).
  const claims = new Map<string, Map<string, Write[]>>();
  for (const [t, fields] of ctx.index.targets) {
    for (const w of fields.get('removed') ?? []) {
      if (w.value !== true || w.device === t) continue;
      let perWriter = claims.get(w.device);
      if (!perWriter) claims.set(w.device, (perWriter = new Map()));
      const list = perWriter.get(t);
      if (list) list.push(w);
      else perWriter.set(t, [w]);
    }
  }

  const removed = new Set<string>();
  const byRank = new Map<number, string[]>();
  for (const [id, rank] of yield* walk(undefined)) {
    const list = byRank.get(rank);
    if (list) list.push(id);
    else byRank.set(rank, [id]);
  }
  for (const level of [...byRank.keys()].sort((a, b) => a - b)) {
    // All devices of one rank act at once: what they remove takes effect after the whole rank was
    // looked at, so no device of this rank is stopped by another one of the same rank.
    const effective: string[] = [];
    for (const r of (byRank.get(level) as string[]).sort()) {
      if (r !== ctx.own && removed.has(r)) continue;
      if (!vouches(r)) continue;
      for (const [t, writes] of claims.get(r) ?? []) {
        if (removed.has(t)) continue;
        let said = false;
        // Only a verified write counts: an unverifiable newer one does not shadow a verified older one.
        for (const w of writes) {
          if (yield* wroteBy(r, w)) {
            said = true;
            break;
          }
        }
        if (said && (yield* reachAvoiding(t)).has(r)) effective.push(t);
      }
    }
    for (const t of effective) removed.add(t);
  }
  return removed;
}

interface Analysis {
  readonly keyConflict: Set<string>;
  readonly keyMismatch: Set<string>;
  readonly relayConflict: Set<string>;
}

/**
 * Rule 4: all values vouching devices that were not removed ever wrote for the keys and the relay id
 * of each entry. A device that is removed, or whose removal this derivation could not see, carries no
 * authority: what a removed device wrote does not count for a conflict.
 */
function* analyse(ctx: Ctx, members: Members, removed: ReadonlySet<string>): Gen<Analysis> {
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
          if (!m?.voucher || removed.has(w.device) || !(yield* verifiedBy(ctx, w, m.keys))) {
            continue;
          }
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
    lastHit: new Map(),
  };
  const p0 = yield* closure(ctx, NONE);
  const removals = yield* removalsOf(ctx, p0);
  const removedIds = [...removals].filter((id) => id !== ctx.own).sort();
  const analysis = yield* analyse(ctx, p0, removals);
  const t =
    removedIds.length === 0 && analysis.keyConflict.size === 0
      ? p0
      : yield* closure(ctx, new Set([...analysis.keyConflict, ...removedIds]));

  const dropRelay = (id: string, e: TrustedDevice): TrustedDevice => {
    if (!analysis.relayConflict.has(id) || e.relayId === undefined) return e;
    const { relayId: _relay, ...rest } = e;
    return rest;
  };
  const trusted = [...t].map(([id, m]) => dropRelay(id, m.entry)).sort(byName);
  // Checkable = every device whose key was ever validly vouched (a member of P) and that has no key
  // conflict, trusted or not: a device that fell out of T (removed, or vouched only through a removed
  // or conflicted device) keeps its signed changes verifiable, so the honest devices that took them
  // are not blocked by them for ever. The entry is read as the vouchers that were not removed give
  // it; where only removed devices vouched, the entry as P has it, unless those disagree on the key.
  const sanitized: Members = new Map(
    [...p0].map(([id, m]) => [id, removals.has(id) ? { ...m, voucher: false } : m]),
  );
  const gone: TrustedDevice[] = [];
  for (const [id, member] of [...p0].sort(byDevice)) {
    if (t.has(id) || analysis.keyConflict.has(id)) continue;
    let entry = (yield* evaluate(ctx, sanitized, id))?.entry;
    if (!entry) {
      if (member.keys.size > 1 && !ctx.directById.has(id)) continue;
      entry = member.entry;
    }
    gone.push({ ...dropRelay(id, entry), removed: removals.has(id) });
  }
  const checkable = [...trusted, ...gone].sort(byName);
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
