// Cases of the more advanced earlier implementation (shortened `knew`, equal values are no notice,
// lists and objects are values), with generic data.
import { describe, expect, it } from 'vitest';
import {
  DELETED_FIELD,
  MAX_CLOCK_JUMP,
  emptyReplica,
  fieldHistory,
  findRecord,
  historyOf,
  isHidden,
  knownFor,
  liveRecords,
  merge,
  missingFor,
  restore,
  softDelete,
  undo,
  visibleRecords,
  write,
  type Replica,
} from '../../src/log/index.ts';
import { COL, ok, permutations, prng, sync, values, written, removed } from './helpers.ts';

const AUTHOR1 = { time: 1_762_600_000_000, by: 'u1' };
const AUTHOR2 = { time: 1_762_600_060_000, by: 'u2' };

describe('write', () => {
  it('numbers own changes without gaps and advances the clock', () => {
    const a = written(written(emptyReplica('A'), 'r1', { label: 'x' }), 'r1', { note: 'n' });
    expect(a.log.map((c) => [c.device, c.seq, c.clock])).toEqual([
      ['A', 1, 1],
      ['A', 2, 2],
    ]);
    expect(a.vector).toEqual({ A: 2 });
    expect(values(a, 'r1')).toEqual({ label: 'x', note: 'n' });
  });

  it('keeps fields a later write does not name; refuses an empty write and a deleted record', () => {
    const a = written(written(emptyReplica('A'), 'r1', { label: 'x', note: 'x' }), 'r1', {
      note: 'y',
    });
    expect(values(a, 'r1')).toEqual({ label: 'x', note: 'y' });
    expect(write(emptyReplica('A'), COL, 'r1', {})).toEqual({ ok: false, reason: 'no-fields' });
    expect(write(removed(a, COL, 'r1'), COL, 'r1', { label: 'x' })).toEqual({
      ok: false,
      reason: 'record-deleted',
    });
  });

  it('lists and objects are values like any other', () => {
    const fields = { list: ['1-3', '4-6'], obj: { k: 'f1', n: 'one' } };
    const a = written(emptyReplica('A'), 'r1', fields);
    expect(values(sync(a, emptyReplica('B')), 'r1')).toEqual(fields);
  });
});

describe('missingFor and merge', () => {
  const three = () =>
    written(written(written(emptyReplica('A'), 'r1', { label: 'x' }), 'r2', { label: 'x' }), 'r1', {
      note: 'x',
    });

  it('missingFor returns everything, the rest beyond a stand, nothing when up to date', () => {
    const a = three();
    expect(missingFor(a, {}).map((c) => c.seq)).toEqual([1, 2, 3]);
    expect(missingFor(a, { A: 2 }).map((c) => c.seq)).toEqual([3]);
    expect(missingFor(a, a.vector)).toEqual([]);
  });

  it('takes over the changes of another device; idempotent; a doubled change in a batch counts once', () => {
    const a = three();
    const once = merge(emptyReplica('B'), a.log);
    expect(values(once.replica, 'r1')).toEqual({ label: 'x', note: 'x' });
    expect(once.replica.vector).toEqual({ A: 3 });
    const twice = merge(once.replica, a.log);
    expect(twice.applied).toBe(0);
    expect(twice.replica).toEqual(once.replica);
    const doubled = merge(emptyReplica('B'), [a.log[0]!, a.log[0]!]);
    expect([doubled.applied, doubled.replica.log.length]).toEqual([1, 1]);
  });

  it('holds back a change after a gap until the gap is filled', () => {
    const a = written(written(emptyReplica('A'), 'r1', { label: 'x' }), 'r1', { note: 'x' });
    const [first, second] = a.log as [(typeof a.log)[0], (typeof a.log)[0]];
    const waiting = merge(emptyReplica('B'), [second]);
    expect([waiting.applied, waiting.held]).toEqual([0, [second]]);
    expect(findRecord(waiting.replica, COL, 'r1')).toBeUndefined();
    expect(merge(waiting.replica, [second, first]).applied).toBe(2);
  });

  it('passes changes on through a third device (A to B to C)', () => {
    const c = sync(
      sync(written(emptyReplica('A'), 'r1', { label: 'x' }), emptyReplica('B')),
      emptyReplica('C'),
    );
    expect(values(c, 'r1')).toEqual({ label: 'x' });
    expect(c.vector).toEqual({ A: 1 });
  });

  it('advances the Lamport clock so a later local write wins', () => {
    let a = emptyReplica('A');
    for (let i = 0; i < 5; i += 1) a = written(a, 'r1', { note: `v${i}` });
    const b = written(sync(a, emptyReplica('B')), 'r1', { note: 'last' });
    expect(b.clock).toBe(6);
    expect(values(sync(b, a), 'r1')).toEqual({ note: 'last' });
  });

  it('does not let one change push the clock beyond any real history', () => {
    const real = written(emptyReplica('A'), 'r1', { label: 'x' }).log[0]!;
    const far = merge(emptyReplica('B'), [{ ...real, clock: MAX_CLOCK_JUMP + 1 }]);
    expect([far.applied, far.held.length, far.replica.clock]).toEqual([0, 1, 0]);
    expect(merge(emptyReplica('B'), [{ ...real, clock: MAX_CLOCK_JUMP }]).applied).toBe(1);
  });
});

describe('concurrent edits', () => {
  it('converge on the same value, the higher device id breaking a tie; different fields both stay', () => {
    const base = written(emptyReplica('A'), 'r1', { label: 'x' });
    const a = written(base, 'r1', { note: 'A' });
    const b = written(sync(base, emptyReplica('B')), 'r1', { note: 'B' });
    expect(values(sync(b, a), 'r1')).toEqual({ label: 'x', note: 'B' });
    expect(sync(b, a).collections).toEqual(sync(a, b).collections);
    const a2 = written(base, 'r1', { note: 'A' });
    const b2 = written(sync(base, emptyReplica('B')), 'r1', { list: ['1-3'] });
    expect(values(sync(b2, a2), 'r1')).toEqual({ label: 'x', note: 'A', list: ['1-3'] });
  });

  it('give the same result in every order of arrival', () => {
    const a = written(written(emptyReplica('A'), 'r1', { label: 'x' }), 'r1', { note: 'A' });
    const b = written(written(emptyReplica('B'), 'r1', { note: 'B' }), 'r2', { label: 'x' });
    const c = removed(written(emptyReplica('C'), 'r3', { label: 'x' }), COL, 'r3');
    const all = [...a.log, ...b.log, ...c.log];
    const outcomes = permutations(all).map((order) => {
      let d = emptyReplica('D');
      for (const change of order) d = merge(d, [change]).replica;
      return merge(d, all).replica.collections;
    });
    for (const outcome of outcomes) expect(outcome).toEqual(outcomes[0]);
  });
});

describe('final delete', () => {
  it('erases the content everywhere, forwards only redacted entries, wins over a concurrent write', () => {
    const a = written(written(emptyReplica('A'), 'r1', { note: 'secret' }), 'r1', { label: 'x' });
    const deleted = removed(a, COL, 'r1');
    expect(findRecord(deleted, COL, 'r1')).toEqual({ id: 'r1', fields: {}, deleted: true });
    expect(liveRecords(deleted, COL)).toEqual([]);
    expect(deleted.log.map((c) => c.kind)).toEqual(['redacted', 'redacted', 'delete']);
    expect(JSON.stringify(deleted.log)).not.toContain('secret');
    expect(JSON.stringify(sync(deleted, emptyReplica('C')))).not.toContain('secret');
    let b = sync(a, emptyReplica('B'));
    for (let i = 0; i < 3; i += 1) b = written(b, 'r1', { note: `later ${i}` });
    for (const r of [sync(b, deleted), sync(deleted, b)]) {
      expect(findRecord(r, COL, 'r1')?.deleted).toBe(true);
      expect(JSON.stringify(r)).not.toContain('later');
    }
    expect(removed(deleted, COL, 'r1')).toBe(deleted);
  });
});

describe('conflict notice', () => {
  const start = () => {
    const a = written(emptyReplica('A'), 'r1', { label: 'x', note: 'x' });
    return { a, b: sync(a, emptyReplica('B')) };
  };

  it('notes two writes to one field that knew nothing of each other, on both devices', () => {
    const { a, b } = start();
    const a2 = written(a, 'r1', { note: 'A' });
    const b2 = written(b, 'r1', { note: 'B' });
    for (const r of [sync(b2, a2), sync(a2, b2)]) {
      expect(r.notices).toEqual([
        {
          collection: COL,
          id: 'r1',
          field: 'note',
          values: [
            { value: 'A', device: 'A', seq: 2 },
            { value: 'B', device: 'B', seq: 1 },
          ],
          applies: 'B',
        },
      ]);
    }
  });

  it('notes nothing for writes in sequence, to different fields, or in a chain arriving late', () => {
    const { a, b } = start();
    const a2 = written(a, 'r1', { note: 'A' });
    const b2 = written(sync(a2, b), 'r1', { note: 'B' });
    expect(sync(b2, a2).notices).toEqual([]);
    expect(sync(written(b, 'r1', { list: ['7-8'] }), a2).notices).toEqual([]);
    // A writes, B writes knowing it, C gets B's write first and A's afterwards
    const c = sync(a, emptyReplica('C'));
    const onlyB = merge(
      c,
      missingFor(b2, c.vector).filter((x) => x.device === 'B'),
    ).replica;
    // B's write says it knew A's second write: it waits (causal hold) until A's write is here
    expect(onlyB.vector).toEqual(c.vector);
    const late = merge(onlyB, [
      ...missingFor(a2, onlyB.vector),
      ...missingFor(b2, onlyB.vector),
    ]).replica;
    expect(late.notices).toEqual([]);
    expect(values(late, 'r1')?.note).toBe('B');
  });

  it('shows on a third device, is settled by a write that knew all values, goes with the final delete', () => {
    const { a, b } = start();
    const a2 = written(a, 'r1', { note: 'first' });
    const b2 = written(b, 'r1', { note: 'second' });
    expect(sync(b2, sync(a2, sync(a, emptyReplica('C')))).notices).toHaveLength(1);
    const both = sync(b2, a2);
    const settled = written(both, 'r1', { note: 'first' });
    expect(settled.notices).toEqual([]);
    expect(sync(settled, b2).notices).toEqual([]);
    const gone = removed(both, COL, 'r1');
    expect(gone.notices).toEqual([]);
    expect(JSON.stringify(gone)).not.toMatch(/first|second/);
  });

  it('two writes of the same value are no notice; different values are', () => {
    const a = written(emptyReplica('A'), 'r1', { list: ['1-3', '4-6'] });
    const b = written(emptyReplica('B'), 'r1', { list: ['1-3', '4-6'] });
    expect(sync(b, a).notices).toEqual([]);
    expect(sync(a, b).notices).toEqual([]);
    const b2 = written(emptyReplica('B'), 'r1', { list: ['7-8'] });
    expect(sync(b2, a).notices).toHaveLength(1);
  });

  it('a third concurrent writer joins an open notice, even with a value equal to one already in it', () => {
    const a = written(emptyReplica('A'), 'r1', { note: 'x' });
    const b = written(emptyReplica('B'), 'r1', { note: 'y' });
    const c = written(emptyReplica('C'), 'r1', { note: 'x' });
    const ab = sync(b, a);
    expect(ab.notices).toHaveLength(1);
    const withC = sync(c, ab);
    expect(withC.notices[0]?.values.map((v) => v.device)).toEqual(['A', 'B', 'C']);
  });
});

describe('who and when, soft delete, history, undo', () => {
  const two = () =>
    written(
      written(emptyReplica('A'), 'r1', { label: 'x', note: 'x' }, AUTHOR1),
      'r1',
      { note: 'y' },
      AUTHOR2,
    );
  const entry = (r: Replica, seq: number) => {
    const found = historyOf(r, COL, 'r1').find((e) => e.seq === seq);
    if (!found) throw new Error(`no write ${seq}`);
    return found;
  };

  it('who and when travel with every write and never decide which value wins', () => {
    const b = sync(two(), emptyReplica('B'));
    expect(findRecord(b, COL, 'r1')?.fields.note).toMatchObject({
      value: 'y',
      time: AUTHOR2.time,
      by: AUTHOR2.by,
    });
    expect(written(emptyReplica('A'), 'r1', { label: 'x' }).log[0]).not.toHaveProperty('by');
    const a = written(emptyReplica('A'), 'r1', { note: 'old' });
    const next = written(sync(a, emptyReplica('B')), 'r1', { note: 'new' }, { time: 0, by: 'x' });
    expect(values(sync(next, a), 'r1')).toEqual({ note: 'new' });
  });

  it('soft delete hides and keeps, restore shows again; both need a live record', () => {
    const hidden = ok(softDelete(two(), COL, 'r1', AUTHOR2));
    expect(isHidden(findRecord(hidden, COL, 'r1')!)).toBe(true);
    expect(visibleRecords(hidden, COL)).toEqual([]);
    expect(values(hidden, 'r1')).toEqual({ label: 'x', note: 'y', [DELETED_FIELD]: true });
    expect(softDelete(hidden, COL, 'r1')).toEqual({ ok: false, reason: 'unchanged' });
    expect(visibleRecords(ok(restore(hidden, COL, 'r1')), COL).map((r) => r.id)).toEqual(['r1']);
    expect(softDelete(emptyReplica('A'), COL, 'r1')).toEqual({ ok: false, reason: 'no-record' });
    expect(restore(removed(two(), COL, 'r1'), COL, 'r1')).toEqual({
      ok: false,
      reason: 'record-deleted',
    });
  });

  it('history lists the writes newest first with what each still decides; per field too', () => {
    const a = two();
    expect(historyOf(a, COL, 'r1').map((e) => [e.seq, e.by, e.fields, e.applies])).toEqual([
      [2, AUTHOR2.by, { note: 'y' }, ['note']],
      [1, AUTHOR1.by, { label: 'x', note: 'x' }, ['label']],
    ]);
    expect(fieldHistory(a, COL, 'r1', 'note').map((e) => [e.value, e.applies])).toEqual([
      ['y', true],
      ['x', false],
    ]);
    expect(historyOf(emptyReplica('A'), COL, 'r1')).toEqual([]);
  });

  it('undo is a new write that travels; of the first write it hides; refuses the unknown', () => {
    const a = two();
    const undone = ok(undo(a, COL, 'r1', entry(a, 2), AUTHOR1));
    expect(values(undone, 'r1')).toEqual({ label: 'x', note: 'x' });
    expect(values(sync(undone, sync(a, emptyReplica('B'))), 'r1')).toEqual({
      label: 'x',
      note: 'x',
    });
    expect(values(ok(undo(undone, COL, 'r1', entry(undone, 3))), 'r1')).toEqual({
      label: 'x',
      note: 'y',
    });
    expect(values(ok(undo(a, COL, 'r1', entry(a, 1))), 'r1')).toEqual({
      label: 'x',
      note: 'y',
      [DELETED_FIELD]: true,
    });
    expect(undo(a, COL, 'r1', { device: 'A', seq: 9 })).toEqual({
      ok: false,
      reason: 'unknown-change',
    });
    const b = written(emptyReplica('A'), 'r1', { label: 'x' });
    expect(
      values(ok(undo(written(b, 'r1', { note: 'new' }), COL, 'r1', { device: 'A', seq: 2 })), 'r1'),
    ).toEqual({ label: 'x', note: null });
  });
});

describe('shortened `knew`', () => {
  it('a change names only the devices that wrote its fields; a first write knows nothing', () => {
    let a = written(emptyReplica('A'), 'r1', { label: 'x' });
    expect(a.log[0]!.knew).toEqual({});
    // 24 other devices write records of their own; A holds all of them
    for (let i = 0; i < 24; i += 1) {
      a = sync(
        written(emptyReplica(`G${String(i).padStart(2, '0')}`), `r${i + 10}`, { label: 'x' }),
        a,
      );
    }
    const b = written(sync(a, emptyReplica('B')), 'r1', { label: 'none' });
    a = written(sync(b, a), 'r1', { note: 'x' });
    expect(a.log[a.log.length - 1]!.knew).toEqual({}); // nobody wrote "note" before
    const again = written(a, 'r1', { label: 'x' });
    const last = again.log[again.log.length - 1]!;
    expect(last.knew).toEqual({ A: 2, B: 1 });
    expect(JSON.stringify(last).length).toBeLessThan(250);
    expect(Object.keys(a.vector)).toHaveLength(26);
    // a final delete names everyone who wrote the record
    expect(knownFor(again, COL, 'r1', null)).toEqual({ A: 3, B: 1 });
  });

  // The case a `knew` of only the current values would get wrong: A knew Y's write although X's,
  // made knowing it, holds the field on A, so no notice there names Y.
  it('a write that knew an older value of the field is no notice with it on a device that lacks the newer', () => {
    const y = written(emptyReplica('Y'), 'r1', { note: 'from Y' });
    const x = written(sync(y, emptyReplica('X')), 'r1', { note: 'from X' });
    const beforeA = sync(x, sync(y, emptyReplica('A')));
    expect(beforeA.notices).toEqual([]);
    const a = written(beforeA, 'r1', { note: 'from A' });
    expect(a.log[a.log.length - 1]!.knew).toEqual({ X: 1, Y: 1 });
    // R holds Y's write and gets A's before X's: A's write says it knew X's, so it waits
    const aChanges = a.log.filter((c) => c.device === 'A');
    const r = merge(sync(y, emptyReplica('R')), aChanges);
    expect(r.held).toHaveLength(1);
    expect(r.replica.notices).toEqual([]);
    expect(values(r.replica, 'r1')?.note).toBe('from Y');
    // once X's write is here, A's is taken (in one call, whatever the order)
    const done = merge(r.replica, [...aChanges, ...x.log.filter((c) => c.device === 'X')]);
    expect(done.held).toEqual([]);
    expect(done.replica.notices).toEqual([]);
    expect(values(done.replica, 'r1')?.note).toBe('from A');
  });

  // Every check of the model asks `knew` only about devices that wrote the same fields: random runs
  // give the very same data and notices with the shortened `knew` as with the whole stand.
  it('decides exactly as with the whole stand (400 random runs)', () => {
    const full = (r: Replica, id: string, fields: Record<string, unknown>): Replica => {
      const next = written(r, id, fields);
      const c = next.log[next.log.length - 1]!;
      return merge(r, [{ ...c, knew: r.vector }]).replica;
    };
    for (let run = 0; run < 400; run += 1) {
      const rnd = prng(run + 1);
      const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)]!;
      const devices = ['A', 'B', 'C'];
      const short: Record<string, Replica> = Object.fromEntries(
        devices.map((d) => [d, emptyReplica(d)]),
      );
      const long: Record<string, Replica> = Object.fromEntries(
        devices.map((d) => [d, emptyReplica(d)]),
      );
      for (let step = 0; step < 24; step += 1) {
        const d = pick(devices);
        if (rnd() < 0.5) {
          const fields = { [pick(['label', 'note'])]: pick(['x', 'none', 'y']) };
          short[d] = written(short[d]!, 'r1', fields);
          long[d] = full(long[d]!, 'r1', fields);
        } else {
          // a sync, now and then only of one device's changes (a forwarder that lacks the rest)
          const e = pick(devices);
          // A forwarder that lacks the rest would make the two runs differ by design: a whole-stand
          // `knew` makes a change wait for more (causal hold) than the shortened one. Partial
          // deliveries are covered by the property tests.
          const only: string | null = null;
          const part = (from: Replica, to: Replica) =>
            merge(
              to,
              missingFor(from, to.vector).filter((c) => !only || c.device === only),
            ).replica;
          short[e] = part(short[d]!, short[e]!);
          long[e] = part(long[d]!, long[e]!);
        }
        for (const g of devices) {
          expect(short[g]!.collections).toEqual(long[g]!.collections);
          expect(short[g]!.notices).toEqual(long[g]!.notices);
        }
      }
    }
  });
});
