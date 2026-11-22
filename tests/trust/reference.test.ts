// Differential test: the trust derivation (src/trust/derive.ts) against an INDEPENDENT reference
// written from the rules in docs/wire-format.md ("Trust derivation"), in the plainest way: naive
// loops, no entry index, no worklists, no generators. 3000+ random scenarios (7 devices, vouchers,
// cycles, mutual removals, key and relay conflicts, devices met in person, adversarial writers, the
// reading device's own writes), the derivation is run on the log in a random order, the reference on
// the plain list of writes. Signatures are not part of this test (the log counts as judged, as in
// `deriveSync`): they are covered with real keys in `review5.test.ts`.
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys, isPoint, publicKeys } from '../../src/core/index.ts';
import { emptyReplica, merge, write, type Change, type Replica } from '../../src/log/index.ts';
import {
  DEVICE_COLLECTION,
  newDeviceId,
  vouchAll,
  vouchAnyRole,
  vouchRoles,
  type KnownDevice,
  type TrustedDevice,
  type Voucher,
} from '../../src/trust/index.ts';
import { deriveSync } from '../../src/trust/derive.ts';
import { known, opts, prng, type Dev } from './helpers.ts';

const SCENARIOS = 3200;
const POOL = 7;
const OWN = 'device-' + 'e'.repeat(32);
const ROLES = ['admin', 'member', 'guest'];

// ---------------------------------------------------------------------------------------------
// The reference
// ---------------------------------------------------------------------------------------------
interface W {
  readonly writer: string;
  readonly target: string;
  readonly field: string;
  readonly value: unknown;
  readonly clock: number;
  readonly seq: number;
}
interface Entry {
  name: string;
  sig: string;
  dh: string;
  role?: string;
  roleVouched?: string;
  relayId?: string;
  private: boolean;
}
interface Member {
  entry: Entry;
  vouches: boolean;
}
type Members = Map<string, Member>;
interface Outcome {
  trusted: string[];
  checkable: string[];
  removed: string[];
  selfRemoved: boolean;
  reasons: string[];
}

const IDENTITY = ['name', 'sig', 'dh', 'role', 'relayId', 'private'];

function reference(
  changes: readonly Change[],
  own: string,
  met: readonly KnownDevice[],
  voucher: Voucher,
): Outcome {
  // the writes, as plain records; a write to the own entry of the writer counts for nothing later on
  const writes: W[] = [];
  for (const c of changes) {
    if (c.kind !== 'set' || c.collection !== DEVICE_COLLECTION) continue;
    for (const [field, value] of Object.entries(c.fields ?? {})) {
      writes.push({ writer: c.device, target: c.id, field, value, clock: c.clock, seq: c.seq });
    }
  }
  const newer = (a: W, b: W): boolean =>
    a.clock !== b.clock
      ? a.clock > b.clock
      : a.writer !== b.writer
        ? a.writer > b.writer
        : a.seq > b.seq;
  const targets = [...new Set(writes.map((w) => w.target))].sort();
  const metById = new Map(met.map((m) => [m.device, m]));

  const okName = (v: unknown): v is string =>
    typeof v === 'string' && /^[\p{L}\p{N} ._-]{1,40}$/u.test(v);
  const okRole = (v: unknown): v is string =>
    typeof v === 'string' && /^[a-z][a-z0-9:_-]{0,79}$/.test(v);
  const okRelay = (v: unknown): v is string =>
    typeof v === 'string' && v.length >= 1 && v.length <= 80 && !/\p{Cc}/u.test(v);
  const okKey = (v: unknown): v is string => typeof v === 'string' && isPoint(v);
  const okId = (v: string): boolean => /^device-[0-9a-f]{32}$/.test(v);

  const learned = (m: KnownDevice): Entry => ({
    name: m.name,
    sig: m.sig,
    dh: m.dh,
    ...(m.role !== undefined && okRole(m.role) ? { role: m.role, roleVouched: m.role } : {}),
    ...(m.relayId !== undefined ? { relayId: m.relayId } : {}),
    private: false,
  });

  /** Whether a write counts: its writer is this device, or a member of `view` that vouches. */
  const counts = (w: W, view: Members): boolean =>
    w.writer === own || view.get(w.writer)?.vouches === true;

  /** The newest valid value of a field among the writes that count, `all` = every distinct one. */
  const values = (
    t: string,
    field: string,
    ok: (v: unknown) => boolean,
    view: Members,
  ): unknown[] =>
    writes
      .filter(
        (w) =>
          w.target === t && w.field === field && w.writer !== t && ok(w.value) && counts(w, view),
      )
      .sort((a, b) => (newer(a, b) ? -1 : newer(b, a) ? 1 : 0))
      .map((w) => w.value)
      .filter((v, i, all) => all.indexOf(v) === i);

  /** The entry of `t` as the writes that count give it (or undefined when they give none). */
  const evaluate = (t: string, view: Members): Entry | undefined => {
    const name = values(t, 'name', okName, view)[0];
    const sig = values(t, 'sig', okKey, view)[0];
    const dh = values(t, 'dh', okKey, view)[0];
    let fromLog: Entry | undefined;
    if (okId(t) && name !== undefined && sig !== undefined && dh !== undefined && sig !== dh) {
      const role = values(t, 'role', okRole, view)[0] as string | undefined;
      const relay = values(t, 'relayId', okRelay, view)[0] as string | undefined;
      const priv = values(t, 'private', () => true, view)[0];
      fromLog = {
        name: name as string,
        sig: sig as string,
        dh: dh as string,
        ...(role !== undefined ? { role, roleVouched: role } : {}),
        ...(relay !== undefined ? { relayId: relay } : {}),
        private: priv === true,
      };
    }
    const m = metById.get(t);
    if (!m) return fromLog;
    const entry = learned(m);
    if (
      entry.role === undefined &&
      fromLog?.role !== undefined &&
      fromLog.sig === m.sig &&
      fromLog.dh === m.dh
    ) {
      entry.role = fromLog.role;
      entry.roleVouched = fromLog.role;
    }
    return entry;
  };

  const same = (a: Entry, b: Entry): boolean => JSON.stringify(a) === JSON.stringify(b);
  const asDevice = (id: string, e: Entry): TrustedDevice => ({ device: id, ...e, removed: false });

  /** Potential trust, synchronous rounds; devices in `excluded` never join. */
  const closure = (excluded: ReadonlySet<string>): Members => {
    const members: Members = new Map();
    for (const m of met)
      if (!excluded.has(m.device)) members.set(m.device, { entry: learned(m), vouches: false });
    const refresh = (): void => {
      for (const [id, m] of members) {
        const list = [...members].map(([i, x]) => asDevice(i, x.entry));
        m.vouches = voucher.canVouch(asDevice(id, m.entry), list) === true;
      }
    };
    refresh();
    const max = 64 + 4 * (targets.length + met.length);
    for (let round = 0; round < max; round += 1) {
      const staged: [string, Entry][] = [];
      for (const t of targets) {
        if (t === own || excluded.has(t)) continue;
        const e = evaluate(t, members);
        if (e) staged.push([t, e]);
      }
      for (const m of met) {
        if (!excluded.has(m.device) && !targets.includes(m.device)) {
          const e = evaluate(m.device, members);
          if (e) staged.push([m.device, e]);
        }
      }
      let changed = false;
      for (const [t, e] of staged) {
        const there = members.get(t);
        if (!there) {
          members.set(t, { entry: e, vouches: false });
          changed = true;
        } else if (!same(there.entry, e)) {
          there.entry = e;
          changed = true;
        }
      }
      refresh();
      if (!changed) break;
    }
    return members;
  };

  // --- rule 1
  const p0 = closure(new Set());

  // --- rule 3: rank and removals
  const vouchesIn = (id: string): boolean => id === own || p0.get(id)?.vouches === true;
  const wroteIdentity = (u: string, w: string): boolean =>
    writes.some((x) => x.writer === u && x.target === w && IDENTITY.includes(x.field));
  const edgesOf = (u: string): string[] =>
    [...p0.keys()].filter((w) => w !== u && wroteIdentity(u, w));
  const roots = [own, ...met.map((m) => m.device)].filter((id) => id === own || p0.has(id));
  const walk = (avoid: string | undefined): Map<string, number> => {
    const dist = new Map<string, number>();
    let frontier = roots.filter((id) => id !== avoid);
    for (const id of frontier) dist.set(id, 0);
    for (let d = 0; frontier.length > 0; d += 1) {
      const next: string[] = [];
      for (const u of frontier) {
        if (!vouchesIn(u)) continue;
        for (const w of edgesOf(u)) {
          if (w !== avoid && !dist.has(w)) {
            dist.set(w, d + 1);
            next.push(w);
          }
        }
      }
      frontier = next;
    }
    return dist;
  };
  const rank = walk(undefined);
  const order = [...rank.keys()].sort((a, b) =>
    (rank.get(a) as number) !== (rank.get(b) as number)
      ? (rank.get(a) as number) - (rank.get(b) as number)
      : a < b
        ? -1
        : a > b
          ? 1
          : 0,
  );
  const removed = new Set<string>();
  for (const r of order) {
    if (r !== own && removed.has(r)) continue;
    if (!vouchesIn(r)) continue;
    const said = writes.filter(
      (w) => w.writer === r && w.field === 'removed' && w.value === true && w.target !== r,
    );
    for (const t of new Set(said.map((w) => w.target))) {
      if (!removed.has(t) && walk(t).has(r)) removed.add(t);
    }
  }
  const removedIds = [...removed].filter((id) => id !== own).sort();

  // --- rule 4: key consistency among the vouchers that were not removed
  const conflict = new Set<string>();
  const mismatch = new Set<string>();
  const relayConflict = new Set<string>();
  const authors = (t: string, field: string, ok: (v: unknown) => boolean): string[] => [
    ...new Set(
      writes
        .filter(
          (w) =>
            w.target === t &&
            w.field === field &&
            w.writer !== t &&
            ok(w.value) &&
            (w.writer === own || (p0.get(w.writer)?.vouches === true && !removed.has(w.writer))),
        )
        .map((w) => w.value as string),
    ),
  ];
  for (const t of targets) {
    if (t === own) continue;
    const sigs = authors(t, 'sig', okKey);
    const dhs = authors(t, 'dh', okKey);
    const relays = authors(t, 'relayId', okRelay);
    const m = metById.get(t);
    if (m) {
      if (sigs.some((s) => s !== m.sig) || dhs.some((d) => d !== m.dh)) mismatch.add(t);
    } else {
      if (sigs.length > 1 || dhs.length > 1) conflict.add(t);
      if (relays.length > 1) relayConflict.add(t);
    }
  }

  // --- rule 5
  const t = closure(new Set([...conflict, ...removedIds]));
  const view: Members = new Map(
    [...p0].map(([id, m]) => [id, removed.has(id) ? { ...m, vouches: false } : m]),
  );
  const gone = removedIds.filter(
    (id) => p0.has(id) && !conflict.has(id) && evaluate(id, view) !== undefined,
  );
  const reasons: string[] = [];
  for (const id of [...conflict].sort()) reasons.push(`${id}:key-conflict`);
  for (const id of [...mismatch].sort()) reasons.push(`${id}:key-mismatch`);
  for (const id of [...relayConflict].sort()) reasons.push(`${id}:relay-conflict`);
  for (const id of removedIds) reasons.push(`${id}:removed`);
  const describe = (id: string, e: Entry, drop: boolean): string =>
    JSON.stringify([
      id,
      e.name,
      e.sig,
      e.dh,
      e.role,
      e.roleVouched,
      drop ? undefined : e.relayId,
      e.private,
    ]);
  const trusted = [...t].map(([id, m]) => describe(id, m.entry, relayConflict.has(id)));
  const checkable = [
    ...trusted,
    ...gone.map((id) => describe(id, evaluate(id, view) as Entry, relayConflict.has(id))),
  ];
  return {
    trusted: trusted.sort(),
    checkable: checkable.sort(),
    removed: removedIds,
    selfRemoved: removed.has(own),
    reasons,
  };
}

// ---------------------------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------------------------
let pool: Dev[];
const extraKeys: string[] = [];
beforeAll(async () => {
  pool = [];
  for (let i = 0; i < POOL; i += 1) {
    const id = newDeviceId(new Uint8Array(16).fill(0x40 + i));
    const keys = await generateDeviceKeys();
    pool.push({
      id,
      name: `P${i}`,
      keys,
      intro: { device: id, name: `P${i}`, ...(await publicKeys(keys)) },
    });
  }
  for (let i = 0; i < 3; i += 1) extraKeys.push((await publicKeys(await generateDeviceKeys())).sig);
}, 60_000);

interface Scenario {
  readonly changes: Change[];
  readonly met: KnownDevice[];
  readonly voucher: Voucher;
  readonly strategy: string;
}

/** The entry of the reading device itself: others may write about it (and remove it). */
const ownEntry = {
  id: OWN,
  name: 'Own',
  get intro() {
    return { device: OWN, name: 'Own', sig: extraKeys[0] as string, dh: (pool[0] as Dev).intro.dh };
  },
};

function scenario(seed: number): Scenario {
  const rnd = prng(seed);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(rnd() * list.length)] as T;
  const writers = new Map<string, Replica>(
    [...pool.map((d) => d.id), OWN].map((id) => [id, emptyReplica(id)]),
  );
  const met = pool.filter(() => rnd() < 0.25);
  if (met.length === 0 || rnd() < 0.1) met.push(pick(pool));
  const metUnique = [...new Map(met.map((d) => [d.id, d])).values()];
  const steps = 6 + Math.floor(rnd() * 22);
  for (let i = 0; i < steps; i += 1) {
    const roll = rnd();
    const w = roll < 0.08 ? OWN : roll < 0.6 ? pick(metUnique).id : pick(pool).id;
    let mine = writers.get(w) as Replica;
    if (rnd() < 0.55)
      mine = merge(mine, (writers.get(pick([...writers.keys()])) as Replica).log).replica;
    const target: Pick<Dev, 'id' | 'name' | 'intro'> =
      rnd() < 0.05
        ? ownEntry
        : rnd() < 0.07 && w !== OWN
          ? (pool.find((d) => d.id === w) as Dev)
          : pick(pool);
    const what = rnd();
    const role = rnd() < 0.03 ? 'Bad Role' : pick(ROLES);
    let fields: Record<string, unknown>;
    if (what < 0.4)
      fields = { name: target.name, sig: target.intro.sig, dh: target.intro.dh, role };
    else if (what < 0.47) fields = { sig: pick([...pool.map((d) => d.intro.sig), ...extraKeys]) };
    else if (what < 0.52) fields = { dh: pick(pool).intro.dh };
    else if (what < 0.57) fields = { relayId: pick(['relay-1', 'relay-2', 'relay-3']) };
    else if (what < 0.62) fields = { role };
    else if (what < 0.65) fields = { private: rnd() < 0.5 };
    else if (what < 0.67) fields = { sig: 'junk' };
    else if (what < 0.69) fields = { name: 'bad|name' };
    else if (what < 0.93) fields = { removed: true };
    else fields = { removed: false };
    const out = write(mine, DEVICE_COLLECTION, target.id, fields, {});
    if (out.ok) writers.set(w, out.replica);
  }
  const changes: Change[] = [];
  for (const r of writers.values()) changes.push(...r.log.filter((c) => c.device === r.device));
  const strategies: [string, Voucher][] = [
    ['roles', vouchRoles(['admin'])],
    ['roles', vouchRoles(['admin'])],
    ['any', vouchAnyRole()],
    ['all', vouchAll()],
  ];
  const [strategy, voucher] = pick(strategies);
  const metList = metUnique.map((d) =>
    known(d, rnd() < 0.7 ? 'admin' : rnd() < 0.8 ? pick(ROLES) : undefined),
  );
  return { changes, met: metList, voucher, strategy };
}

const shuffled = <T>(list: readonly T[], rnd: () => number): T[] => {
  const out = [...list];
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rnd() * (i + 1));
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
};

const entryText = (d: TrustedDevice): string =>
  JSON.stringify([d.device, d.name, d.sig, d.dh, d.role, d.roleVouched, d.relayId, d.private]);

describe('differential: derivation against an independent reference', () => {
  it(`${SCENARIOS} random scenarios: identical trusted, checkable, removed, reasons`, () => {
    const seen = {
      removals: 0,
      mutual: 0,
      conflicts: 0,
      mismatch: 0,
      relay: 0,
      deep: 0,
      own: 0,
      selfRemoved: 0,
      gone: 0,
    };
    let disagreements = 0;
    for (let n = 0; n < SCENARIOS; n += 1) {
      const sc = scenario(70_000 + n);
      const rnd = prng(n + 1);
      const view = merge(emptyReplica(OWN), shuffled(sc.changes, rnd)).replica;
      const o = opts(sc.voucher);
      const got = deriveSync(view, sc.met, o).trust;
      const want = reference(sc.changes, OWN, sc.met, sc.voucher);
      const mine: Outcome = {
        trusted: got.trusted.map(entryText).sort(),
        checkable: got.checkable.map(entryText).sort(),
        removed: [...got.removed],
        selfRemoved: got.selfRemoved,
        reasons: [...got.reasons].flatMap(([id, list]) => list.map((r) => `${id}:${r}`)),
      };
      const normal = (x: Outcome): string =>
        JSON.stringify({
          ...x,
          reasons: [...x.reasons].sort(),
          checkable: x.checkable.map((c) => c),
        });
      // `removed` entries of checkable carry removed: true in the derivation: compare ids and entries without it
      if (normal(mine) !== normal(want)) {
        disagreements += 1;
        expect(normal(mine), `scenario ${70_000 + n} (${sc.strategy})`).toBe(normal(want));
      }
      if (got.removed.length > 0) seen.removals += 1;
      if (got.removed.length > 1) seen.mutual += 1;
      if ([...got.reasons.values()].some((l) => l.includes('key-conflict'))) seen.conflicts += 1;
      if ([...got.reasons.values()].some((l) => l.includes('key-mismatch'))) seen.mismatch += 1;
      if ([...got.reasons.values()].some((l) => l.includes('relay-conflict'))) seen.relay += 1;
      if (got.trusted.length > sc.met.length + 1) seen.deep += 1;
      if (sc.changes.some((c) => c.device === OWN)) seen.own += 1;
      if (got.selfRemoved) seen.selfRemoved += 1;
      if (got.checkable.length > got.trusted.length) seen.gone += 1;
    }
    process.stderr.write(
      `\ndifferential: ${SCENARIOS} scenarios, ${disagreements} disagreements; with removals ${seen.removals}, several removed ${seen.mutual}, key conflicts ${seen.conflicts}, key mismatches ${seen.mismatch}, relay conflicts ${seen.relay}, trust beyond the met devices ${seen.deep}, own writes ${seen.own}, self removed ${seen.selfRemoved}, removed but checkable ${seen.gone}\n`,
    );
    expect(disagreements).toBe(0);
    // the scenarios are not vacuous
    expect(seen.removals).toBeGreaterThan(600);
    expect(seen.mutual).toBeGreaterThan(150);
    expect(seen.conflicts).toBeGreaterThan(150);
    expect(seen.mismatch).toBeGreaterThan(50);
    expect(seen.relay).toBeGreaterThan(20);
    expect(seen.selfRemoved).toBeGreaterThan(20);
    expect(seen.deep).toBeGreaterThan(800);
    expect(seen.own).toBeGreaterThan(100);
    expect(seen.gone).toBeGreaterThan(300);
  }, 120_000);
});
