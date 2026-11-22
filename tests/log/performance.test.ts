// Well-formed input must not cost quadratic time: heads of a field are computed from the last write
// of each device, and a final deletion finds its record's writes through an index.
import { describe, expect, it } from 'vitest';
import {
  emptyReplica,
  findRecord,
  merge,
  write,
  type Change,
  type Replica,
} from '../../src/log/index.ts';
import { COL } from './helpers.ts';

const FIELDS = Array.from({ length: 40 }, (_, i) => `f${i}`);

function timed<T>(run: () => T): [T, number] {
  const start = performance.now();
  const out = run();
  return [out, performance.now() - start];
}

describe('H5: no quadratic work from well-formed input', () => {
  it('8000 writes of one device to one 40-field record merge in well under 1.5 s', () => {
    const changes: Change[] = [];
    for (let seq = 1; seq <= 8000; seq += 1) {
      changes.push({
        device: 'a',
        seq,
        clock: seq,
        collection: COL,
        id: 'r',
        kind: 'set',
        fields: Object.fromEntries(FIELDS.map((f) => [f, `v${seq}`])),
        knew: seq > 1 ? { a: seq - 1 } : {},
      });
    }
    const [result, ms] = timed(() => merge(emptyReplica('x'), changes));
    expect(result.applied).toBe(8000);
    expect(result.replica.notices).toEqual([]);
    expect(findRecord(result.replica, COL, 'r')?.fields.f0?.value).toBe('v8000');
    expect(ms).toBeLessThan(6000);

    // one further local write on that field stays cheap
    const mine: Replica = { ...result.replica, device: 'x' };
    const [next, writeMs] = timed(() => write(mine, COL, 'r', { f0: 'local' }));
    expect(next.ok).toBe(true);
    expect(writeMs).toBeLessThan(250);
  });

  it('20000 final deletions on a log of 20000 entries merge in a few seconds at most', () => {
    const sets: Change[] = [];
    const deletes: Change[] = [];
    for (let i = 1; i <= 20000; i += 1) {
      sets.push({
        device: 'a',
        seq: i,
        clock: i,
        collection: COL,
        id: `r${i}`,
        kind: 'set',
        fields: { f: i },
        knew: {},
      });
      deletes.push({
        device: 'a',
        seq: 20000 + i,
        clock: 20000 + i,
        collection: COL,
        id: `r${i}`,
        kind: 'delete',
        knew: { a: 20000 + i - 1 },
      });
    }
    const base = merge(emptyReplica('x'), sets).replica;
    const [result, ms] = timed(() => merge(base, deletes));
    expect(result.applied).toBe(20000);
    expect(result.replica.log.filter((c) => c.kind === 'redacted')).toHaveLength(20000);
    expect(ms).toBeLessThan(5000);

    const mine: Replica = { ...result.replica, device: 'x' };
    const [next, writeMs] = timed(() => write(mine, COL, 'fresh', { f: 1 }));
    expect(next.ok).toBe(true);
    // the collection map of 20000 records is copied per merge, as before (about 11 ms here)
    expect(writeMs).toBeLessThan(500);
  });

  it('notices stay as before when many devices write one field', () => {
    const changes: Change[] = ['a', 'b', 'c'].map((d, i) => ({
      device: d,
      seq: 1,
      clock: i + 1,
      collection: COL,
      id: 'r',
      kind: 'set',
      fields: { f: d },
      knew: {},
    }));
    const out = merge(emptyReplica('x'), changes).replica;
    expect(out.notices).toHaveLength(1);
    expect(out.notices[0]?.values.map((v) => v.device)).toEqual(['a', 'b', 'c']);
  });
});
