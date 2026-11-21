// Cases of the typed earlier implementation that the other one does not cover, generic data.
import { describe, expect, it } from 'vitest';
import {
  DELETED_FIELD,
  emptyReplica,
  fieldHistory,
  findRecord,
  historyOf,
  isHidden,
  liveRecords,
  merge,
  missingFor,
  remove,
  restore,
  softDelete,
  undo,
  visibleRecords,
  write,
  type Replica,
} from '../../src/log/index.ts';
import { COL, ok, permutations, sync, values, written } from './helpers.ts';

const U1 = { time: 1_762_600_000_000, by: 'u1' };
const U2 = { time: 1_762_600_060_000, by: 'u2' };

describe('who and when', () => {
  it('a field tells since when and by whom it holds its value; older changes show no author', () => {
    const a = written(
      written(emptyReplica('A'), 'r1', { name: 'n', level: 'a' }, U1),
      'r1',
      { level: 'b' },
      U2,
    );
    expect(a.log.map((c) => [c.time, c.by])).toEqual([
      [U1.time, U1.by],
      [U2.time, U2.by],
    ]);
    const record = findRecord(sync(a, emptyReplica('B')), COL, 'r1');
    expect(record?.fields.level).toMatchObject({ value: 'b', time: U2.time, by: U2.by });
    expect(record?.fields.name).toMatchObject({ value: 'n', time: U1.time, by: U1.by });
    const plain = ok(write(emptyReplica('A'), COL, 'r1', { name: 'n' }));
    expect(plain.log[0]).not.toHaveProperty('time');
    expect(plain.log[0]).not.toHaveProperty('by');
    expect(historyOf(plain, COL, 'r1')[0]).not.toHaveProperty('by');
  });
});

describe('soft delete and final delete', () => {
  it('soft delete keeps content and history; a change made meanwhile on another device is kept', () => {
    const a0 = written(emptyReplica('A'), 'r1', { name: 'n', level: 'a' });
    const b0 = sync(a0, emptyReplica('B'));
    const a = ok(softDelete(a0, COL, 'r1'));
    expect(liveRecords(a, COL)).toHaveLength(1);
    expect(historyOf(a, COL, 'r1')).toHaveLength(2);
    const b = written(b0, 'r1', { level: 'b' }, U2);
    for (const r of [sync(b, a), sync(a, b)]) {
      expect(values(r, 'r1')).toEqual({ name: 'n', level: 'b', [DELETED_FIELD]: true });
    }
  });

  it('restore of a visible record and soft delete twice change nothing', () => {
    const a = written(emptyReplica('A'), 'r1', { name: 'n' });
    expect(restore(a, COL, 'r1')).toEqual({ ok: false, reason: 'unchanged' });
    const hidden = ok(softDelete(a, COL, 'r1'));
    expect(softDelete(hidden, COL, 'r1')).toEqual({ ok: false, reason: 'unchanged' });
    expect(visibleRecords(ok(restore(hidden, COL, 'r1')), COL).map((r) => r.id)).toEqual(['r1']);
  });

  it('final delete erases content, history and authors; only the delete keeps its author', () => {
    const a = remove(written(emptyReplica('A'), 'r1', { name: 'n' }), COL, 'r1', U2);
    expect(historyOf(a, COL, 'r1')).toEqual([]);
    expect(a.log.map((c) => [c.kind, c.by])).toEqual([
      ['redacted', undefined],
      ['delete', U2.by],
    ]);
    expect(JSON.stringify(a.log)).not.toContain('"n"');
  });

  it('final delete reaches other devices and erases their copy; a never-seeing device gets only redacted entries', () => {
    const a = written(emptyReplica('A'), 'r1', { name: 'visible-text' });
    const b = sync(a, emptyReplica('B'));
    const bAfter = sync(remove(a, COL, 'r1'), b);
    expect(findRecord(bAfter, COL, 'r1')?.deleted).toBe(true);
    expect(JSON.stringify(bAfter)).not.toContain('visible-text');
    const c = sync(remove(a, COL, 'r1'), emptyReplica('C'));
    expect(c.vector).toEqual({ A: 2 });
    expect(JSON.stringify(c)).not.toContain('visible-text');
  });

  it('a deleted record refuses soft delete and restore', () => {
    const gone = remove(written(emptyReplica('A'), 'r1', { name: 'n' }), COL, 'r1');
    expect(softDelete(gone, COL, 'r1')).toEqual({ ok: false, reason: 'record-deleted' });
    expect(restore(gone, COL, 'r1')).toEqual({ ok: false, reason: 'record-deleted' });
    expect(softDelete(emptyReplica('A'), COL, 'r1')).toEqual({ ok: false, reason: 'no-record' });
  });
});

describe('history', () => {
  it('orders writes of several devices the way values are decided, on every device alike', () => {
    const a0 = written(emptyReplica('A'), 'r1', { level: 'a' });
    const b = written(sync(a0, emptyReplica('B')), 'r1', { level: 'b' }, U2);
    const a = written(a0, 'r1', { level: 'c' });
    const onA = historyOf(sync(b, a), COL, 'r1');
    const onB = historyOf(sync(a, b), COL, 'r1');
    expect(onA).toEqual(onB);
    expect(onA[0]?.applies).toEqual(['level']);
    expect(onA[0]?.fields.level).toBe(values(sync(b, a), 'r1')?.level);
  });

  it('of one field: its values newest first, the current one marked, with author', () => {
    let a = written(emptyReplica('A'), 'r1', { name: 'n', level: 'a' }, U1);
    a = written(a, 'r1', { level: 'b' }, U2);
    a = written(a, 'r1', { name: 'm' }, U1);
    expect(fieldHistory(a, COL, 'r1', 'level').map((e) => [e.value, e.by, e.applies])).toEqual([
      ['b', U2.by, true],
      ['a', U1.by, false],
    ]);
  });
});

describe('undo', () => {
  const two = () =>
    written(
      written(emptyReplica('A'), 'r1', { name: 'n', level: 'a' }, U1),
      'r1',
      { level: 'b' },
      U2,
    );
  const entry = (r: Replica, seq: number) => {
    const found = historyOf(r, COL, 'r1').find((e) => e.seq === seq);
    if (!found) throw new Error(`no write ${seq}`);
    return found;
  };

  it('restores the earlier value as a new write, with its own author', () => {
    const a = two();
    const undone = ok(undo(a, COL, 'r1', entry(a, 2), U1));
    expect(values(undone, 'r1')).toEqual({ name: 'n', level: 'a' });
    expect(undone.log).toHaveLength(3);
    expect(historyOf(undone, COL, 'r1')[0]).toMatchObject({ by: U1.by, fields: { level: 'a' } });
  });

  it('leaves fields alone that were written again since; nothing left = unchanged', () => {
    let a = written(emptyReplica('A'), 'r1', { name: 'n', level: 'a' });
    a = written(a, 'r1', { name: 'm', level: 'b' });
    a = written(a, 'r1', { level: 'c' });
    const undone = ok(undo(a, COL, 'r1', entry(a, 2)));
    expect(values(undone, 'r1')).toEqual({ name: 'n', level: 'c' });
    const b = written(undone, 'r1', { name: 'o' });
    expect(undo(b, COL, 'r1', entry(b, 2))).toEqual({ ok: false, reason: 'unchanged' });
  });

  it('of the write that created the record hides it; undoing that again is unchanged', () => {
    const a = two();
    const undone = ok(undo(a, COL, 'r1', entry(a, 1)));
    expect(values(undone, 'r1')).toEqual({ name: 'n', level: 'b', [DELETED_FIELD]: true });
    expect(undo(undone, COL, 'r1', entry(undone, 1))).toEqual({ ok: false, reason: 'unchanged' });
  });

  it('of a soft delete shows the record again', () => {
    const a = ok(softDelete(two(), COL, 'r1'));
    const undone = ok(undo(a, COL, 'r1', entry(a, 3)));
    expect(visibleRecords(undone, COL).map((r) => r.id)).toEqual(['r1']);
    expect(isHidden(findRecord(undone, COL, 'r1')!)).toBe(false);
  });

  it('travels: the other device shows the earlier value again', () => {
    const a = two();
    const b = sync(a, emptyReplica('B'));
    const undoneOnB = ok(undo(b, COL, 'r1', entry(b, 2), U2));
    expect(values(sync(undoneOnB, a), 'r1')).toEqual({ name: 'n', level: 'a' });
  });

  it('refuses unknown writes, unknown records and finally deleted records', () => {
    const a = two();
    expect(undo(a, COL, 'r1', { device: 'A', seq: 9 })).toEqual({
      ok: false,
      reason: 'unknown-change',
    });
    expect(undo(a, COL, 'r2', { device: 'A', seq: 1 })).toEqual({ ok: false, reason: 'no-record' });
    expect(undo(remove(a, COL, 'r1'), COL, 'r1', { device: 'A', seq: 1 })).toEqual({
      ok: false,
      reason: 'record-deleted',
    });
  });
});

describe('merge order', () => {
  it('a mix of writes and a delete gives the same result in every order of single changes', () => {
    const a = written(emptyReplica('A'), 'r1', { name: 'n' });
    const b = remove(written(emptyReplica('B'), 'r1', { level: 'x' }), COL, 'r1');
    const all = [...a.log, ...b.log];
    const results = permutations(all).map((order) => {
      let d = emptyReplica('D');
      for (const c of order) d = merge(d, [c]).replica;
      return merge(d, all).replica;
    });
    for (const r of results) expect(r.collections).toEqual(results[0]!.collections);
    expect(missingFor(results[0]!, {}).length).toBe(all.length);
  });
});
