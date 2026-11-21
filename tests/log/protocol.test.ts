import { describe, expect, it } from 'vitest';
import {
  LIMITS,
  PIECE_BYTES,
  emptyReplica,
  findRecord,
  fingerprint,
  historyOf,
  isHidden,
  merge,
  onSyncMessage,
  outcome,
  parseSyncMessage,
  pieces,
  receive,
  softDelete,
  startSession,
  undo,
  valuesOf,
  write,
  type Replica,
  type Session,
  type SyncMessage,
} from '../../src/log/index.ts';
import { COL, ok, written, removed } from './helpers.ts';

const must = <T>(v: T | undefined): T => {
  if (v === undefined) throw new Error('expected a value');
  return v;
};
const json = (m: SyncMessage): unknown => JSON.parse(JSON.stringify(m));
/** These replicas are not signed: plain sessions send everything. */
const PLAIN = { signedOnly: false };

interface Side {
  session: Session;
  replica: Replica;
  out: SyncMessage[];
}

/** Two devices run the protocol over a channel that delivers every message (as JSON). */
function exchange(x: Replica, y: Replica) {
  const side = (replica: Replica): Side => {
    const step = startSession(replica);
    return { session: step.session, replica: step.replica, out: [...step.send] };
  };
  const a = side(x);
  const b = side(y);
  for (let round = 0; round < 50 && (a.out.length > 0 || b.out.length > 0); round += 1) {
    for (const [from, to] of [
      [a, b],
      [b, a],
    ] as const) {
      for (const message of from.out.splice(0)) {
        const step = receive(to.session, to.replica, json(message), PLAIN);
        to.session = step.session;
        to.replica = step.replica;
        to.out.push(...step.send);
      }
    }
  }
  return {
    x: a.replica,
    y: b.replica,
    ox: must(outcome(a.session, a.replica)),
    oy: must(outcome(b.session, b.replica)),
  };
}

const many = (device: string, n: number, fields: Record<string, unknown> = { title: 't' }) => {
  let r = emptyReplica(device);
  for (let i = 0; i < n; i += 1) r = written(r, `r${i}`, fields);
  return r;
};

describe('exchange protocol', () => {
  it('brings two devices to the same data and says so on both', () => {
    let a = emptyReplica('a');
    let b = emptyReplica('b');
    for (let i = 0; i < 3; i += 1) {
      a = written(a, `a${i}`, { title: 'one', n: i });
      b = written(b, `b${i}`, { title: 'two', pos: { x: i, y: [1, 2] } });
    }
    const { x, y, ox, oy } = exchange(a, b);
    expect(x.collections).toEqual(y.collections);
    expect(Object.keys(x.collections[COL] ?? {})).toHaveLength(6);
    expect(ox).toMatchObject({ equal: true, sent: 3, taken: 3 });
    expect(oy).toMatchObject({ equal: true, sent: 3, taken: 3 });
  });

  it('carries soft delete, undo, who/when, yes/no, null and what the author knew', () => {
    const origin = { time: 1_762_600_000_000, by: 'user-1' };
    let a = ok(write(emptyReplica('a'), COL, 'r1', { title: 'x' }, origin));
    a = ok(write(a, COL, 'r1', { flag: true }, origin));
    const flagWrite = must(historyOf(a, COL, 'r1').find((e) => 'flag' in e.fields));
    // undoing the first write of a field: the field had no value before, so null has to travel
    a = ok(undo(a, COL, 'r1', flagWrite, origin));
    a = ok(softDelete(a, COL, 'r1', origin));
    const { y, oy } = exchange(a, emptyReplica('b'));
    expect(oy.equal).toBe(true);
    const record = must(findRecord(y, COL, 'r1'));
    expect(isHidden(record)).toBe(true);
    expect(record.fields.flag?.value).toBeNull();
    const history = historyOf(y, COL, 'r1');
    expect(history).toHaveLength(4);
    expect(history.every((e) => e.time === origin.time && e.by === origin.by)).toBe(true);
    expect(y.log.map((c) => c.knew)).toEqual(a.log.map((c) => c.knew));
  });

  it('carries what the author knew through the wire (else no conflict could be seen)', () => {
    const a = written(emptyReplica('a'), 'r1', { title: 'x' });
    const raw = json(must(pieces(a.log)[0]));
    const parsed = parseSyncMessage(raw);
    expect(parsed?.t === 'changes' && parsed.changes[0]?.knew).toEqual({});
  });

  it('sends nothing when both are already equal, and still closes', () => {
    expect(exchange(emptyReplica('a'), emptyReplica('b')).ox).toMatchObject({
      equal: true,
      sent: 0,
      taken: 0,
    });
  });

  it('a stand is answered with exactly what the sender lacks', () => {
    const a = many('a', 4);
    const b = merge(emptyReplica('b'), a.log.slice(0, 2)).replica;
    const step = onSyncMessage(startSession(a).session, a, { t: 'stand', vector: b.vector }, PLAIN);
    expect(step.session.sent).toBe(2);
    const sent = step.send.flatMap((m) => (m.t === 'changes' ? m.changes : []));
    expect(sent.map((c) => c.seq)).toEqual([3, 4]);
  });

  it('a done message is remembered; the session closes only after both sides did', () => {
    const a = many('a', 1);
    let session = startSession(a).session;
    expect(outcome(session, a)).toBeUndefined();
    session = onSyncMessage(session, a, {
      t: 'done',
      vector: a.vector,
      fingerprint: fingerprint(a),
    }).session;
    expect(outcome(session, a)).toBeUndefined(); // own side has not closed yet
    session = onSyncMessage(session, a, { t: 'changes', changes: [], last: true }).session;
    expect(outcome(session, a)).toMatchObject({ equal: true });
  });

  it('the fingerprint comparison decides: a different peer fingerprint is reported', () => {
    const a = many('a', 1);
    let session = startSession(a).session;
    session = onSyncMessage(session, a, { t: 'changes', changes: [], last: true }).session;
    session = onSyncMessage(session, a, {
      t: 'done',
      vector: a.vector,
      fingerprint: '0'.repeat(32),
    }).session;
    expect(outcome(session, a)).toMatchObject({ equal: false, peerFingerprint: '0'.repeat(32) });
  });

  it('a duplicated piece changes nothing and does not close twice', () => {
    const a = many('a', 5);
    const [piece] = pieces(a.log);
    let step = onSyncMessage(
      startSession(emptyReplica('b')).session,
      emptyReplica('b'),
      must(piece),
    );
    expect(step.send.map((m) => m.t)).toEqual(['done']);
    expect(step.session.taken).toBe(5);
    const again = onSyncMessage(step.session, step.replica, must(piece));
    expect(again.send).toEqual([]);
    expect(again.session.taken).toBe(5);
    expect(again.replica.log).toHaveLength(5);
    step = again;
  });

  it('pieces out of order: nothing is corrupted, the fingerprints say "not equal", a second exchange fixes it', () => {
    const a = many('a', 30, { title: 'x'.repeat(200) });
    const parts = pieces(a.log, { limits: { pieceBytes: 2000 } });
    expect(parts.length).toBeGreaterThan(2);
    const b0 = emptyReplica('b');
    let session = startSession(b0).session;
    let replica = b0;
    for (const part of [...parts].reverse()) {
      const step = onSyncMessage(session, replica, part);
      session = step.session;
      replica = step.replica;
    }
    // the last piece came first: its changes sat behind a gap and were not stored
    expect(replica.log.length).toBeLessThan(30);
    for (const c of replica.log) expect(a.log).toContainEqual(c);
    expect(replica.vector.a ?? 0).toBeLessThan(30);
    const second = exchange(a, replica);
    expect(second.oy.equal).toBe(true);
    expect(second.y.log).toHaveLength(30);
  });

  it('cuts many changes into pieces a data channel carries', () => {
    const a = many('a', 300, { title: 'one', tags: ['x', 'y'] });
    const out = pieces(a.log);
    expect(out.length).toBeGreaterThan(1);
    for (const message of out) {
      expect(new TextEncoder().encode(JSON.stringify(message)).length).toBeLessThan(
        PIECE_BYTES + 500,
      );
    }
    expect(out.at(-1)).toMatchObject({ last: true });
    expect(out.slice(0, -1).every((m) => m.last === false)).toBe(true);
    expect(out.flatMap((m) => m.changes)).toEqual(a.log);
    expect(exchange(a, emptyReplica('b')).oy).toMatchObject({ equal: true, taken: 300 });
  });

  it('always sends at least one piece, the last marked', () => {
    expect(pieces([])).toEqual([{ t: 'changes', changes: [], last: true }]);
  });

  it('a single change over the piece size travels alone', () => {
    const a = many('a', 3, { title: 'x'.repeat(500) });
    const out = pieces(a.log, { limits: { pieceBytes: 100 } });
    expect(out.map((m) => m.changes.length)).toEqual([1, 1, 1]);
  });

  it('pieces respect maxChanges, and measure UTF-8 bytes not characters', () => {
    const tiny = many('a', 7);
    expect(pieces(tiny.log, { limits: { maxChanges: 3 } }).map((m) => m.changes.length)).toEqual([
      3, 3, 1,
    ]);
    // 100 emoji = 100 UTF-16 pairs (200 units) but 400 bytes
    const wide = many('a', 3, { title: '😀'.repeat(100) });
    const bytes = new TextEncoder().encode(JSON.stringify(wide.log[0])).length;
    const chars = JSON.stringify(wide.log[0]).length;
    expect(bytes).toBeGreaterThan(chars + 100);
    const limit = Math.floor((chars + 1) * 2 + 1); // two changes fit by characters, not by bytes
    expect(
      pieces(wide.log, { limits: { pieceBytes: limit } }).map((m) => m.changes.length),
    ).toEqual([1, 1, 1]);
  });

  it('a limits override reaches the session', () => {
    const a = many('a', 6);
    const step = onSyncMessage(
      startSession(a).session,
      a,
      { t: 'stand', vector: {} },
      { limits: { maxChanges: 2 }, ...PLAIN },
    );
    expect(step.send.map((m) => (m.t === 'changes' ? m.changes.length : -1))).toEqual([2, 2, 2]);
    expect(LIMITS.maxChanges).toBe(500);
  });

  it('a whole record entry travels and arrives the same', () => {
    const entry = { label: '2 of 4', dims: { grade: '7-8' }, note: 'Ä ö ü ß – „quote“' };
    const a = written(emptyReplica('a'), 'combo|a|grade=7-8', entry);
    const { y } = exchange(a, emptyReplica('b'));
    expect(valuesOf(must(findRecord(y, COL, 'combo|a|grade=7-8')))).toEqual(entry);
  });

  it('a final deletion travels and the content is gone on both', () => {
    let a = written(emptyReplica('a'), 'r1', { title: 'secret' });
    const { x: b0 } = exchange(a, emptyReplica('b'));
    a = removed(a, COL, 'r1');
    const { y, oy } = exchange(a, b0);
    expect(oy.equal).toBe(true);
    expect(findRecord(y, COL, 'r1')?.deleted).toBe(true);
    expect(JSON.stringify(y.log)).not.toContain('secret');
  });
});

describe('fingerprint', () => {
  it('is the same for the same data, another after any change, a hidden or a deleted record', () => {
    const a = written(emptyReplica('a'), 'r1', { title: 'x' });
    const { x, y } = exchange(a, emptyReplica('b'));
    expect(fingerprint(x)).toBe(fingerprint(y));
    expect(fingerprint(x)).toMatch(/^[0-9a-f]{32}$/);
    expect(fingerprint(written(x, 'r1', { title: 'y' }))).not.toBe(fingerprint(x));
    expect(fingerprint(ok(softDelete(x, COL, 'r1')))).not.toBe(fingerprint(x));
    expect(fingerprint(removed(x, COL, 'r1'))).not.toBe(fingerprint(x));
    expect(fingerprint(removed(x, COL, 'r1'))).not.toBe(fingerprint(ok(softDelete(x, COL, 'r1'))));
  });

  it('covers every collection, not only the first', () => {
    const a = emptyReplica('a');
    const b = ok(write(a, 'other', 'r1', { title: 'x' }));
    expect(fingerprint(b)).not.toBe(fingerprint(a));
    expect(fingerprint(ok(write(b, COL, 'r1', { title: 'x' })))).not.toBe(fingerprint(b));
  });

  it('does not depend on the order of keys inside a value or on who wrote what first', () => {
    const x = written(emptyReplica('a'), 'r1', { v: { a: 1, b: 2 } });
    const y = written(emptyReplica('b'), 'r1', { v: { b: 2, a: 1 } });
    // different writers, same visible value
    expect(fingerprint(x)).toBe(fingerprint(y));
    const p = written(written(emptyReplica('a'), 'r1', { a: 1 }), 'r2', { b: 2 });
    const q = written(written(emptyReplica('b'), 'r2', { b: 2 }), 'r1', { a: 1 });
    expect(fingerprint(p)).toBe(fingerprint(q));
  });

  it('an empty replica has a fingerprint, and a record id cannot fake a deleted record', () => {
    expect(fingerprint(emptyReplica('a'))).toMatch(/^[0-9a-f]{32}$/);
    const del = removed(written(emptyReplica('a'), 'r1', { x: 1 }), COL, 'r1');
    const fake = written(emptyReplica('a'), 'r1', { deleted: 'deleted' });
    expect(fingerprint(del)).not.toBe(fingerprint(fake));
  });
});

describe('a refused message ends the session and takes nothing', () => {
  const valid = (n = 2) => must(pieces(many('a', n).log)[0]);

  it('an unreadable message: refusal, the replica is the very same object', () => {
    const b = emptyReplica('b');
    const start = startSession(b);
    const step = receive(start.session, b, {
      t: 'changes',
      changes: [{ device: 'a' }],
      last: true,
    });
    expect(step.session.refusal).toBe('unreadable');
    expect(step.replica).toBe(b);
    expect(step.send).toEqual([]);
    expect(outcome(step.session, b)).toBeUndefined();
  });

  it('one bad change among valid ones: NOTHING of the piece is taken', () => {
    const good = json(valid(3)) as { changes: unknown[] };
    const poisoned = { ...good, changes: [...good.changes, { device: 'a', seq: 4, clock: 4 }] };
    const b = emptyReplica('b');
    const step = receive(startSession(b).session, b, poisoned);
    expect(step.session.refusal).toBe('unreadable');
    expect(step.replica.log).toHaveLength(0);
    expect(step.session.taken).toBe(0);
  });

  it('a refused session ignores every later message, valid or not', () => {
    const b = emptyReplica('b');
    let step = receive(startSession(b).session, b, 'junk');
    expect(step.session.refusal).toBe('unreadable');
    step = receive(step.session, step.replica, json(valid()));
    expect(step.replica.log).toHaveLength(0);
    expect(step.send).toEqual([]);
    step = receive(step.session, step.replica, json({ t: 'stand', vector: {} }));
    expect(step.send).toEqual([]);
    const direct = onSyncMessage(step.session, step.replica, valid());
    expect(direct.replica.log).toHaveLength(0);
  });

  it('an unknown member refuses the message as a whole', () => {
    const b = emptyReplica('b');
    const step = receive(startSession(b).session, b, { ...(json(valid()) as object), extra: 1 });
    expect(step.session.refusal).toBe('unreadable');
    expect(step.replica.log).toHaveLength(0);
  });

  it('limits and the device id pattern reach receive', () => {
    const b = emptyReplica('b');
    const raw = json(valid(3));
    expect(
      receive(startSession(b).session, b, raw, { limits: { maxChanges: 2 } }).session.refusal,
    ).toBe('unreadable');
    expect(
      receive(startSession(b).session, b, raw, { deviceId: (s) => s.length === 5 }).session.refusal,
    ).toBe('unreadable');
    expect(receive(startSession(b).session, b, raw).session.refusal).toBeUndefined();
  });
});
