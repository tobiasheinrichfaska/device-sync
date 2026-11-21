// A device that takes a large log in one go (a new device, a long-away device) must not pay a
// price that grows with the square of the size. Regression: `apply` copied the whole collection for
// every change, so 6000 changes to 6000 different records took about 12 seconds.
import { describe, expect, it } from 'vitest';
import { emptyReplica, findRecord, merge, type Change } from '../../src/log/index.ts';

function changes(count: number, records: number): Change[] {
  return Array.from({ length: count }, (_, i) => ({
    device: 'a',
    seq: i + 1,
    clock: i + 1,
    collection: 'items',
    id: `r${i % records}`,
    kind: 'set' as const,
    fields: { title: `t${i}` },
    knew: {},
  }));
}

describe('a large batch merges in linear time', () => {
  it('6000 changes to 6000 different records are taken in well under two seconds', () => {
    const batch = changes(6000, 6000);
    const started = performance.now();
    const result = merge(emptyReplica('b'), batch);
    const took = performance.now() - started;
    expect(result.applied).toBe(6000);
    expect(result.held).toEqual([]);
    // measured: ~15 ms after the fix, ~12 s before it; the bound leaves room for slow machines
    expect(took).toBeLessThan(2000);
    expect(findRecord(result.replica, 'items', 'r5999')?.fields.title?.value).toBe('t5999');
  });

  it('the result of a batch equals the result of the same changes taken one at a time', () => {
    const batch = changes(300, 40);
    const all = merge(emptyReplica('b'), batch).replica;
    let one = emptyReplica('b');
    for (const change of batch) one = merge(one, [change]).replica;
    expect(all.collections).toEqual(one.collections);
    expect(all.vector).toEqual(one.vector);
    expect(all.notices).toEqual(one.notices);
  });

  it('a merge does not touch the replica it started from (collections are shared, never changed)', () => {
    const start = merge(emptyReplica('b'), changes(50, 10)).replica;
    const frozen = structuredClone(start.collections);
    const more: Change[] = Array.from({ length: 20 }, (_, i) => ({
      device: 'c',
      seq: i + 1,
      clock: 100 + i,
      collection: 'items',
      id: `r${i % 10}`,
      kind: 'set' as const,
      fields: { title: `c${i}` },
      knew: {},
    }));
    const next = merge(start, more).replica;
    expect(start.collections).toEqual(frozen);
    expect(next.collections).not.toEqual(frozen);
  });
});
