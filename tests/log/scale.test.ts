// Larger property tests: five devices, interleaved writes, soft deletes, undo, final deletes and
// partial exchanges, then a full exchange. Notices are checked against a ground truth derived
// independently from the logs; a growth test guards against merges that get quadratic.
import { describe, expect, it } from 'vitest';
import { canonical } from '../../src/core/index.ts';
import {
  emptyReplica,
  historyOf,
  merge,
  restore,
  softDelete,
  undo,
  write,
  type Change,
  type Notice,
  type Replica,
} from '../../src/log/index.ts';
import { int, pick, type Rng } from './fuzz.ts';
import { COL, prng, sync, written, removed } from './helpers.ts';

const DEVICES = ['d0', 'd1', 'd2', 'd3', 'd4'];
const RECORDS = ['r0', 'r1', 'r2', 'r3'];
const FIELDS = ['f0', 'f1', 'f2'];
// few distinct values, so equal values (no notice) happen as often as different ones
const VALUES: unknown[] = ['x', 'y', 'z', 1, ['a'], { k: 'v' }];
const SEEDS = 200;
const STEPS = 60;

interface Stats {
  writes: number;
  softDeletes: number;
  restores: number;
  undos: number;
  removes: number;
  exchanges: number;
  noticeRuns: number;
  maxNotices: number;
}

/**
 * A legal wire form: `knew` is shortened to the devices that wrote the fields, and another
 * implementation may leave the author's own device out (a later write of a device always counts as
 * knowing its earlier ones). Rewrites the newest change of the replica that way.
 */
function withoutOwnInKnew(replica: Replica): Replica {
  const last = replica.log[replica.log.length - 1] as Change;
  if (!last.knew || last.device !== replica.device) return replica;
  const { [last.device]: _own, ...rest } = last.knew;
  return { ...replica, log: [...replica.log.slice(0, -1), { ...last, knew: rest }] };
}

function step(rng: Rng, replicas: Replica[], stats: Stats, stripOwn: boolean): void {
  const i = int(rng, DEVICES.length);
  const me = replicas[i] as Replica;
  const id = pick(rng, RECORDS);
  const origin = { time: int(rng, 1_000_000), by: `u${i}` };
  const roll = rng();
  const apply = (result: ReturnType<typeof write>, counter: keyof Stats): void => {
    if (result.ok) {
      replicas[i] = stripOwn ? withoutOwnInKnew(result.replica) : result.replica;
      stats[counter] += 1;
    }
  };
  if (roll < 0.45) {
    const fields: Record<string, unknown> = {};
    for (let k = 1 + int(rng, 2); k > 0; k -= 1) fields[pick(rng, FIELDS)] = pick(rng, VALUES);
    apply(write(me, COL, id, fields, origin), 'writes');
  } else if (roll < 0.55) {
    apply(softDelete(me, COL, id, origin), 'softDeletes');
  } else if (roll < 0.63) {
    apply(restore(me, COL, id, origin), 'restores');
  } else if (roll < 0.73) {
    const history = historyOf(me, COL, id);
    if (history.length > 0) {
      const target = pick(rng, history);
      apply(undo(me, COL, id, { device: target.device, seq: target.seq }, origin), 'undos');
    }
  } else if (roll < 0.75) {
    const next = removed(me, COL, id, origin);
    if (next !== me) {
      replicas[i] = next;
      stats.removes += 1;
    }
  } else {
    // a partial exchange: this device takes from a random subset of the others
    for (let j = 0; j < DEVICES.length; j += 1) {
      if (j !== i && rng() < 0.5) {
        replicas[i] = sync(replicas[j] as Replica, replicas[i] as Replica);
        stats.exchanges += 1;
      }
    }
  }
}

const keyOf = (c: Change): string => `${c.device}#${c.seq}`;
const noticeKey = (n: { collection: string; id: string; field: string }): string =>
  JSON.stringify([n.collection, n.id, n.field]);
const byKey = (a: Notice, b: Notice): number => {
  const x = noticeKey(a);
  const y = noticeKey(b);
  return x < y ? -1 : x > y ? 1 : 0;
};

/**
 * The notices a replica must show, derived from its log alone. A write w is dominated by o when o
 * is a later write of the same device or o knew w; the heads are the undominated writes of a field.
 * A field has a notice iff there are two or more heads with different values.
 */
function expectedNotices(replica: Replica): Notice[] {
  const groups = new Map<string, Change[]>();
  for (const change of replica.log) {
    if (change.kind !== 'set') continue;
    for (const field of Object.keys(change.fields ?? {})) {
      const key = JSON.stringify([change.collection, change.id, field]);
      groups.set(key, [...(groups.get(key) ?? []), change]);
    }
  }
  const out: Notice[] = [];
  for (const [key, writes] of groups) {
    const [collection, id, field] = JSON.parse(key) as [string, string, string];
    const record = replica.collections[collection]?.[id];
    if (!record || record.deleted) continue;
    const dominated = (w: Change): boolean =>
      writes.some(
        (o) =>
          o !== w &&
          ((o.device === w.device && o.seq > w.seq) || (o.knew?.[w.device] ?? 0) >= w.seq),
      );
    const heads = writes.filter((w) => !dominated(w));
    const values = heads.map((w) => canonical(w.fields?.[field]));
    if (heads.length < 2 || values.every((v) => v === values[0])) continue;
    // the value that applies: the write with the highest clock, the higher device id on a tie
    const winner = writes.reduce((a, b) =>
      b.clock > a.clock || (b.clock === a.clock && b.device > a.device) ? b : a,
    );
    out.push({
      collection,
      id,
      field,
      values: heads
        .map((w) => ({ value: w.fields?.[field], device: w.device, seq: w.seq }))
        .sort((a, b) => (a.device < b.device ? -1 : a.device > b.device ? 1 : a.seq - b.seq)),
      applies: winner.fields?.[field],
    });
  }
  return out.sort(byKey);
}

/** What must be equal on every replica holding the same changes. */
const stateOf = (r: Replica) => ({
  clock: r.clock,
  vector: r.vector,
  collections: r.collections,
  log: [...r.log].sort((a, b) => (keyOf(a) < keyOf(b) ? -1 : 1)),
  notices: [...r.notices].sort(byKey),
});

function fullExchange(replicas: Replica[]): void {
  for (let pass = 0; pass < 3; pass += 1) {
    for (let i = 0; i < replicas.length; i += 1) {
      for (let j = 0; j < replicas.length; j += 1) {
        if (i !== j) replicas[j] = sync(replicas[i] as Replica, replicas[j] as Replica);
      }
    }
  }
}

describe('five devices, interleaved schedules (seeded)', () => {
  const stats: Stats = {
    writes: 0,
    softDeletes: 0,
    restores: 0,
    undos: 0,
    removes: 0,
    exchanges: 0,
    noticeRuns: 0,
    maxNotices: 0,
  };

  it(`${SEEDS} seeded schedules: notices match the ground truth, then all replicas converge`, () => {
    for (let seed = 1; seed <= SEEDS; seed += 1) {
      const rng = prng(seed * 7919);
      const replicas = DEVICES.map((d) => emptyReplica(d));
      for (let n = 0; n < STEPS; n += 1) step(rng, replicas, stats, seed % 2 === 0);

      // before the full exchange every replica already shows exactly the notices of its own log
      replicas.forEach((r, i) => {
        expect([...r.notices].sort(byKey), `seed ${seed}, device ${i}, partial`).toEqual(
          expectedNotices(r),
        );
      });

      fullExchange(replicas);
      const first = replicas[0] as Replica;
      for (const r of replicas) {
        expect(stateOf(r), `seed ${seed}, ${r.device}`).toEqual(stateOf(first));
      }
      const truth = expectedNotices(first);
      expect([...first.notices].sort(byKey), `seed ${seed}, final`).toEqual(truth);
      if (truth.length > 0) stats.noticeRuns += 1;
      stats.maxNotices = Math.max(stats.maxNotices, truth.length);

      // the vector counts every device's own changes without a gap; nothing was held back
      for (const d of DEVICES) {
        const own = first.log.filter((c) => c.device === d).map((c) => c.seq);
        expect(own, `seed ${seed}, ${d}`).toEqual(own.map((_, k) => k + 1));
        expect(first.vector[d] ?? 0, `seed ${seed}, ${d}`).toBe(own.length);
      }
      // the value that applies is the notice's `applies` and the record's field value
      for (const n of first.notices) {
        expect(first.collections[n.collection]?.[n.id]?.fields[n.field]?.value).toEqual(n.applies);
      }
    }
  });

  it('the schedules really exercise every kind of operation and produce notices', () => {
    // runs after the test above (same describe, same order); guards against a vacuous schedule
    expect(stats.writes).toBeGreaterThan(SEEDS * 5);
    expect(stats.softDeletes).toBeGreaterThan(SEEDS / 4);
    expect(stats.restores).toBeGreaterThan(SEEDS / 8);
    expect(stats.undos).toBeGreaterThan(SEEDS / 4);
    expect(stats.removes).toBeGreaterThan(SEEDS / 4);
    expect(stats.exchanges).toBeGreaterThan(SEEDS);
    expect(stats.noticeRuns).toBeGreaterThan(SEEDS / 5);
    expect(stats.maxNotices).toBeGreaterThanOrEqual(2);
  });
});

describe('growth', () => {
  /**
   * A replica holding `count` changes of one device, spread over 200 records. Built in one merge:
   * writing them one by one costs a scan of the log each, which is not what is measured here.
   */
  function big(count: number): Replica {
    const changes: Change[] = [];
    for (let i = 1; i <= count; i += 1) {
      changes.push({
        device: 'big',
        seq: i,
        clock: i,
        collection: COL,
        id: `r${i % 200}`,
        kind: 'set',
        fields: { [`f${i % 3}`]: i },
        knew: {},
      });
    }
    return merge(emptyReplica('base'), changes).replica;
  }

  /** Best of several rounds of merging single new changes of another device into `base`. */
  function timePerMerge(base: Replica, rounds: number, perRound: number): number {
    let other = emptyReplica('other');
    const incoming: Change[] = [];
    for (let i = 0; i < perRound; i += 1) {
      other = written(other, `r${i % 200}`, { f0: `o${i}` });
      incoming.push(other.log[other.log.length - 1] as Change);
    }
    let best = Infinity;
    for (let round = 0; round < rounds; round += 1) {
      const start = performance.now();
      for (const change of incoming) merge(base, [change]);
      best = Math.min(best, performance.now() - start);
    }
    return best / perRound;
  }

  // Measured on the development machine (ms per merged change, best of 5): about 0.05 for 1000
  // changes and about 0.13 for 3000, ratio about 2.5 = linear (a log copy and a scan per merge).
  // Quadratic growth would give 9.
  it('merging one more change into a log of 3000 is not quadratic in the log size', () => {
    const small = big(1000);
    const large = big(3000);
    timePerMerge(small, 1, 5); // warm up the JIT
    const t1000 = timePerMerge(small, 5, 20);
    const t3000 = timePerMerge(large, 5, 20);
    const ratio = t3000 / t1000;
    // linear is 3; a generous bound far below 9 keeps the test steady on a loaded machine
    expect(ratio, `1000: ${t1000.toFixed(3)} ms, 3000: ${t3000.toFixed(3)} ms`).toBeLessThan(6);
  });
});
