// Property tests: random multi-device schedules with a tiny seeded PRNG, exchanged in random orders
// with duplicates and re-deliveries. Same seed, same run.
import { describe, expect, it } from 'vitest';
import {
  changeCheckValue,
  emptyReplica,
  findRecord,
  historyOf,
  merge,
  missingFor,
  restore,
  softDelete,
  undo,
  unionVector,
  write,
  type Change,
  type Replica,
} from '../../src/log/index.ts';
import { COL, prng, written, removed } from './helpers.ts';

const DEVICES = ['A', 'B', 'C'] as const;
const IDS = ['r1', 'r2'];
const FIELDS = ['f1', 'f2'];

type Rnd = () => number;
const pick = <T>(rnd: Rnd, xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)]!;

function shuffle<T>(rnd: Rnd, xs: readonly T[]): T[] {
  const out = [...xs];
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rnd() * (i + 1));
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

/** A random batch: a shuffled subset of `from`, some changes twice. */
function noisy(rnd: Rnd, changes: readonly Change[]): Change[] {
  const subset = changes.filter(() => rnd() < 0.7);
  return shuffle(rnd, [...subset, ...subset.filter(() => rnd() < 0.3)]);
}

const keyOf = (c: Change) => `${c.device}#${c.seq}`;

/** The state that must be equal on all replicas once they hold the same changes. */
function state(r: Replica) {
  return {
    clock: r.clock,
    vector: r.vector,
    collections: r.collections,
    log: [...r.log].sort((a, b) => (keyOf(a) < keyOf(b) ? -1 : 1)),
    notices: [...r.notices].sort((a, b) =>
      `${a.collection}/${a.id}/${a.field}` < `${b.collection}/${b.id}/${b.field}` ? -1 : 1,
    ),
  };
}

/** Delivers `pool` again and again until nothing more applies (held changes get released). */
function settle(replica: Replica, pool: readonly Change[], rnd?: Rnd): Replica {
  let r = replica;
  for (let i = 0; i < pool.length + 2; i += 1) {
    const result = merge(r, rnd ? noisy(rnd, pool) : pool);
    r = result.replica;
    if (!rnd && result.applied === 0) break;
  }
  return merge(r, pool).replica;
}

interface Options {
  readonly removals: boolean;
  /** Soft delete, restore and undo write booleans / old values, so they are off where all values must be equal. */
  readonly hiding?: boolean;
  readonly values: readonly string[];
}

/** Runs random local operations and partial exchanges; returns all replicas. */
function schedule(rnd: Rnd, steps: number, options: Options): Record<string, Replica> {
  const reps: Record<string, Replica> = Object.fromEntries(
    DEVICES.map((d) => [d, emptyReplica(d)]),
  );
  for (let step = 0; step < steps; step += 1) {
    const d = pick(rnd, DEVICES);
    const r = reps[d]!;
    const roll = rnd();
    const id = pick(rnd, IDS);
    if (roll < 0.45) {
      const fields = { [pick(rnd, FIELDS)]: pick(rnd, options.values) };
      const res = write(r, COL, id, fields);
      if (res.ok) reps[d] = res.replica;
    } else if (roll < 0.52 && options.removals) {
      reps[d] = removed(r, COL, id);
    } else if (roll < 0.6 && options.hiding !== false) {
      const res = rnd() < 0.5 ? softDelete(r, COL, id) : restore(r, COL, id);
      if (res.ok) reps[d] = res.replica;
    } else if (roll < 0.68 && options.hiding !== false) {
      const history = historyOf(r, COL, id);
      const target = history.length > 0 ? pick(rnd, history) : undefined;
      if (target) {
        const res = undo(r, COL, id, target);
        if (res.ok) reps[d] = res.replica;
      }
    } else {
      const from = reps[pick(rnd, DEVICES)]!;
      const to = pick(rnd, DEVICES);
      reps[to] = merge(reps[to]!, noisy(rnd, missingFor(from, reps[to]!.vector))).replica;
    }
  }
  return reps;
}

const allChanges = (reps: Record<string, Replica>): Change[] => {
  const byKey = new Map<string, Change>();
  for (const r of Object.values(reps)) for (const c of r.log) byKey.set(keyOf(c), c);
  return [...byKey.values()];
};

describe('convergence', () => {
  it('all replicas reach the same state after random exchanges (300 schedules)', () => {
    for (let seed = 1; seed <= 300; seed += 1) {
      const rnd = prng(seed);
      const reps = schedule(rnd, 30, { removals: seed % 3 === 0, values: ['x', 'y', 'z'] });
      const pool = allChanges(reps);
      const settled = DEVICES.map((d) => settle(reps[d]!, pool, rnd));
      for (const s of settled) expect(state(s)).toEqual(state(settled[0]!));
    }
  });

  it('the order of arrival does not matter: fresh replicas fed in random orders agree (300 schedules)', () => {
    for (let seed = 1000; seed < 1300; seed += 1) {
      const rnd = prng(seed);
      const pool = allChanges(
        schedule(rnd, 30, { removals: seed % 2 === 0, values: ['x', 'y', 'z'] }),
      );
      const a = settle(emptyReplica('P'), pool, rnd);
      const b = settle(emptyReplica('Q'), shuffle(rnd, pool), rnd);
      expect(state(a)).toEqual(state(b));
      // and the result is what the ordered delivery gives
      expect(state(settle(emptyReplica('R'), pool))).toEqual(state(a));
    }
  });

  it('merge is idempotent on the resulting state', () => {
    for (let seed = 2000; seed < 2100; seed += 1) {
      const rnd = prng(seed);
      const pool = allChanges(schedule(rnd, 30, { removals: true, values: ['x', 'y'] }));
      const once = settle(emptyReplica('P'), pool);
      const again = merge(once, shuffle(rnd, pool));
      expect(again.applied).toBe(0);
      expect(again.held).toEqual([]);
      expect(again.replica).toEqual(once);
    }
  });

  it('merge is commutative and associative on the resulting state', () => {
    for (let seed = 3000; seed < 3100; seed += 1) {
      const rnd = prng(seed);
      const pool = allChanges(
        schedule(rnd, 30, { removals: seed % 2 === 0, values: ['x', 'y', 'z'] }),
      );
      const third = Math.floor(pool.length / 3);
      const [x, y, z] = [pool.slice(0, third), pool.slice(third, 2 * third), pool.slice(2 * third)];
      const e = emptyReplica('P');
      const m = (r: Replica, c: readonly Change[]) => settle(r, c);
      // (x then y then z) vs (z then (y then x)) vs ((y with z) then x)
      const s1 = m(m(m(e, x), y), z);
      const s2 = m(m(m(e, z), y), x);
      const s3 = m(m(e, [...y, ...z]), x);
      // the pool is only complete together: settle with everything at the end
      const full = (r: Replica) => settle(r, pool);
      expect(state(full(s1))).toEqual(state(full(s2)));
      expect(state(full(s2))).toEqual(state(full(s3)));
    }
  });
});

describe('held changes', () => {
  it('a change arriving before its predecessors is held and released when they arrive', () => {
    let a = emptyReplica('A');
    for (let i = 0; i < 6; i += 1) a = written(a, 'r1', { f1: `v${i}` });
    const [c1, c2, c3, c4, c5, c6] = a.log as [Change, Change, Change, Change, Change, Change];
    const late = merge(emptyReplica('B'), [c6, c5, c4, c3]);
    expect([late.applied, late.held.length, late.replica.log.length]).toEqual([0, 4, 0]);
    const partly = merge(late.replica, [c2, c1, ...late.held]);
    expect(partly.applied).toBe(6);
    expect(partly.held).toEqual([]);
    expect(partly.replica.vector).toEqual({ A: 6 });
    expect(findRecord(partly.replica, COL, 'r1')?.fields.f1?.value).toBe('v5');
  });

  it('shuffled single deliveries of a long log always end complete (random)', () => {
    for (let seed = 4000; seed < 4050; seed += 1) {
      const rnd = prng(seed);
      let a = emptyReplica('A');
      for (let i = 0; i < 12; i += 1) a = written(a, pick(rnd, IDS), { f1: String(i) });
      let b = emptyReplica('B');
      let held: readonly Change[] = [];
      for (const c of shuffle(rnd, a.log)) {
        const result = merge(b, [c, ...held]);
        b = result.replica;
        held = result.held;
      }
      expect(held).toEqual([]);
      expect(b.vector).toEqual({ A: 12 });
      expect(b.collections).toEqual(a.collections);
    }
  });
});

describe('conflict notices', () => {
  it('no notice ever appears when every write carries the same value (200 schedules)', () => {
    for (let seed = 5000; seed < 5200; seed += 1) {
      const rnd = prng(seed);
      const reps = schedule(rnd, 30, { removals: false, hiding: false, values: ['same'] });
      for (const r of Object.values(reps)) expect(r.notices).toEqual([]);
      const pool = allChanges(reps);
      for (const d of DEVICES) expect(settle(reps[d]!, pool).notices).toEqual([]);
    }
  });

  it('a write on a replica that holds everything resolves every notice (200 schedules)', () => {
    let withNotices = 0;
    for (let seed = 6000; seed < 6200; seed += 1) {
      const rnd = prng(seed);
      const reps = schedule(rnd, 30, { removals: false, values: ['x', 'y', 'z'] });
      const pool = allChanges(reps);
      let top = settle(reps.A!, pool);
      if (top.notices.length > 0) withNotices += 1;
      for (const n of top.notices) {
        if (findRecord(top, n.collection, n.id)?.deleted) continue;
        top = written(top, n.id, { [n.field]: 'resolved' });
      }
      expect(top.notices).toEqual([]);
      // and the resolution travels: everybody ends without notices
      for (const d of ['B', 'C']) {
        const other = settle(reps[d]!, allChanges({ top, ...reps }));
        expect(other.notices).toEqual([]);
        expect(state(other)).toEqual(state(top));
      }
    }
    // the generator must really produce conflicts, or this test proves nothing
    expect(withNotices).toBeGreaterThan(20);
  });

  it('writes that knew each other leave no notice, however they arrive', () => {
    for (let seed = 7000; seed < 7100; seed += 1) {
      const rnd = prng(seed);
      // a strict chain: every write happens after fully syncing with the previous author
      let current = emptyReplica('A');
      const chain: Change[] = [];
      for (let i = 0; i < 8; i += 1) {
        const device = pick(rnd, DEVICES);
        const next = settle(emptyReplica(device), chain);
        const nextReplica = written({ ...next, device }, 'r1', { f1: `v${i}` });
        chain.push(...nextReplica.log.filter((c) => !chain.some((k) => keyOf(k) === keyOf(c))));
        current = nextReplica;
      }
      void current;
      const fresh = settle(emptyReplica('Z'), shuffle(rnd, chain), rnd);
      expect(fresh.notices).toEqual([]);
    }
  });
});

describe('redaction', () => {
  it('keeps the numbering gapless and the head check-valued', () => {
    let a = emptyReplica('A');
    a = written(a, 'r1', { f1: 'secret' }, { time: 5, by: 'u' });
    a = written(a, 'r2', { f1: 'keep' });
    a = written(a, 'r1', { f2: 'secret too' });
    const original = [...a.log];
    a = removed(a, COL, 'r1');
    expect(a.log.map((c) => c.seq).sort((x, y) => x - y)).toEqual([1, 2, 3, 4]);
    expect(a.vector).toEqual({ A: 4 });
    const red = a.log.filter((c) => c.kind === 'redacted');
    expect(red).toHaveLength(2);
    for (const c of red) {
      expect(c.fields).toBeUndefined();
      expect(c.knew).toBeUndefined();
      expect(c.by).toBeUndefined();
      const source = original.find((o) => o.seq === c.seq)!;
      expect(c.check).toBe(changeCheckValue(source));
    }
    expect(JSON.stringify(a.log)).not.toContain('secret');
    // a redacted head forwards, applies and numbers like any other
    const b = merge(emptyReplica('B'), missingFor(a, {})).replica;
    expect(b.vector).toEqual({ A: 4 });
    expect(findRecord(b, COL, 'r2')?.fields.f1?.value).toBe('keep');
  });

  it('keeps a signature field and an existing check value; takes the check value when none was set', () => {
    const signed: Change = {
      device: 'A',
      seq: 1,
      clock: 1,
      collection: COL,
      id: 'r1',
      kind: 'set',
      fields: { f1: 'x' },
      knew: {},
      sig: 'SIG',
    };
    const preset: Change = { ...signed, seq: 2, clock: 2, check: 'PRESET', sig: 'SIG2' };
    const del: Change = {
      device: 'A',
      seq: 3,
      clock: 3,
      collection: COL,
      id: 'r1',
      kind: 'delete',
      knew: {},
    };
    const r = merge(emptyReplica('B'), [signed, preset, del]).replica;
    const [first, second] = r.log;
    expect(first).toMatchObject({ kind: 'redacted', sig: 'SIG', check: changeCheckValue(signed) });
    expect(second).toMatchObject({ kind: 'redacted', sig: 'SIG2', check: 'PRESET' });
    expect(changeCheckValue(signed)).toHaveLength(43);
  });

  it('a write after the final delete is logged redacted from the start (random orders agree)', () => {
    for (let seed = 8000; seed < 8050; seed += 1) {
      const rnd = prng(seed);
      const a = removed(written(emptyReplica('A'), 'r1', { f1: 'x' }), COL, 'r1');
      const b = written(written(emptyReplica('B'), 'r1', { f1: 'late' }), 'r1', { f2: 'later' });
      const pool = [...a.log, ...b.log];
      const one = settle(emptyReplica('P'), shuffle(rnd, pool), rnd);
      const two = settle(emptyReplica('Q'), shuffle(rnd, pool), rnd);
      expect(state(one)).toEqual(state(two));
      expect(JSON.stringify(one)).not.toContain('late');
      expect(one.log.filter((c) => c.kind === 'redacted').length).toBe(3);
    }
  });
});

describe('vectors', () => {
  it('unionVector takes the higher number per device and never lowers one', () => {
    expect(unionVector({ A: 3, B: 1 }, { B: 4, C: 2 })).toEqual({ A: 3, B: 4, C: 2 });
    expect(unionVector({}, {})).toEqual({});
    expect(unionVector({ A: 5 }, { A: 2 })).toEqual({ A: 5 });
  });
});
