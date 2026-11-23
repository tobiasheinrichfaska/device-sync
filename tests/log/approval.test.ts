import { describe, expect, it } from 'vitest';
import {
  APPROVAL_LIMITS,
  approve,
  decidedWaiting,
  emptyReplica,
  findRecord,
  fingerprint,
  merge,
  mergeApproved,
  onSyncMessage,
  outcome,
  pendingApproval,
  readApprovalState,
  reject,
  startSession,
  write,
  type ApprovalDecision,
  type Change,
  type Replica,
} from '../../src/log/index.ts';
import { COL, ok, removed, values, written } from './helpers.ts';

const holdAll = (): ApprovalDecision => 'hold';
const holdFrom =
  (device: string) =>
  (c: Change): ApprovalDecision =>
    c.device === device ? 'hold' : 'apply';
const ref = (c: Change): { device: string; seq: number } => ({ device: c.device, seq: c.seq });

const json = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** A runs a few writes; returns the replica of A. */
function authored(n: number, device = 'a'): Replica {
  let r = emptyReplica(device);
  for (let i = 1; i <= n; i += 1) r = written(r, `r${i}`, { v: i });
  return r;
}

describe('without a hook nothing changes', () => {
  it('mergeApproved with no hook equals merge, plus an empty state', () => {
    const a = authored(5);
    const plain = merge(emptyReplica('b'), a.log);
    const approved = mergeApproved(emptyReplica('b'), a.log);
    const { approval, ...rest } = approved.replica;
    expect(approval).toEqual({ entries: [] });
    expect(rest).toEqual(plain.replica);
    expect(approved.applied).toBe(plain.applied);
    expect(approved.approval).toEqual({ held: 0, rejected: 0, dropped: 0 });
  });

  it('merge and write keep (never read) a state a replica carries', () => {
    const a = authored(2);
    const b = mergeApproved(emptyReplica('b'), a.log, { hook: holdAll }).replica;
    expect(b.approval?.entries).toHaveLength(2);
    const after = merge(b, [a.log[0] as Change]).replica;
    expect(after.approval?.entries).toHaveLength(2);
    // plain merge applies a1 and never reads the state; the next approval-aware call tidies it
    expect(after.vector).toEqual({ a: 1 });
    const w = written(b, 'mine', { x: 1 });
    expect(w.approval?.entries).toHaveLength(2);
  });

  it('a session without the option does not mention approvals', () => {
    const a = authored(2);
    const step = onSyncMessage(startSession(emptyReplica('b')).session, emptyReplica('b'), {
      t: 'changes',
      changes: [...a.log],
      last: true,
    });
    expect(step.session.approvals).toBeUndefined();
    expect(step.replica.approval).toBeUndefined();
  });
});

describe('hold', () => {
  it('a held change is outside log, vector and data; the stand does not claim it', () => {
    const a = authored(3);
    const r = mergeApproved(emptyReplica('b'), a.log, { hook: holdAll });
    expect(r.replica.log).toHaveLength(0);
    expect(r.replica.vector).toEqual({});
    expect(r.replica.collections).toEqual({});
    expect(r.applied).toBe(0);
    // the later numbers of the author are held behind the first (the hook holds them all here)
    expect(pendingApproval(r.replica).map((c) => c.seq)).toEqual([1, 2, 3]);
    expect(r.approval.held).toBe(3);
    expect(startSession(r.replica).send[0]).toMatchObject({ t: 'stand', vector: {} });
  });

  it('is asked once; a repeat of a held change does not ask again', () => {
    const a = authored(2);
    let asked = 0;
    const hook = (): ApprovalDecision => {
      asked += 1;
      return 'hold';
    };
    let r = mergeApproved(emptyReplica('b'), a.log, { hook }).replica;
    expect(asked).toBe(2);
    r = mergeApproved(r, a.log, { hook }).replica;
    expect(asked).toBe(2);
    expect(pendingApproval(r)).toHaveLength(2);
  });

  it('later changes of the author that the hook lets through wait behind the held one', () => {
    const a = authored(3);
    const hook = (c: Change): ApprovalDecision => (c.seq === 1 ? 'hold' : 'apply');
    const r = mergeApproved(emptyReplica('b'), a.log, { hook });
    expect(r.replica.vector).toEqual({});
    expect(r.held.map((c) => c.seq)).toEqual([2, 3]);
    expect(pendingApproval(r.replica).map((c) => c.seq)).toEqual([1]);
    const approved = approve(r.replica, [{ device: 'a', seq: 1 }]);
    expect(approved.replica.vector).toEqual({ a: 1 });
    // the others are not stored: they come again
    const again = mergeApproved(approved.replica, a.log, { hook });
    expect(again.replica.vector).toEqual({ a: 3 });
    expect(pendingApproval(again.replica)).toEqual([]);
  });

  it('a change that names a held one in knew waits as for any causal hold', () => {
    const a = authored(1);
    const b = merge(emptyReplica('b'), a.log).replica;
    const bw = written(b, 'r1', { v: 'b edits' });
    const bChange = bw.log[1] as Change;
    expect(bChange.knew).toMatchObject({ a: 1 });
    const c = mergeApproved(emptyReplica('c'), [...a.log, bChange], { hook: holdFrom('a') });
    expect(c.replica.vector).toEqual({});
    expect(c.held.map(ref)).toEqual([{ device: 'b', seq: 1 }]);
    const done = approve(c.replica, [{ device: 'a', seq: 1 }]);
    expect(done.replica.vector).toEqual({ a: 1 });
    const final = mergeApproved(done.replica, [bChange]);
    expect(final.replica.vector).toEqual({ a: 1, b: 1 });
    expect(values(final.replica, 'r1')).toEqual({ v: 'b edits' });
  });

  it('a hook that throws, or answers nonsense, holds; booleans mean apply or hold', () => {
    const a = authored(3);
    const odd = (c: Change): ApprovalDecision => {
      if (c.seq === 1) throw new Error('boom');
      return 'maybe' as unknown as ApprovalDecision;
    };
    const r = mergeApproved(emptyReplica('b'), a.log, { hook: odd });
    expect(pendingApproval(r.replica).map((c) => c.seq)).toEqual([1, 2, 3]);
    const yes = mergeApproved(emptyReplica('b'), a.log, { hook: () => true });
    expect(yes.replica.vector).toEqual({ a: 3 });
    const no = mergeApproved(emptyReplica('b'), a.log, { hook: () => false });
    expect(no.replica.vector).toEqual({});
  });

  it('the hook gets the replica as the call began, whatever the order in the batch', () => {
    const a = authored(3);
    const seenVectors: unknown[] = [];
    const hook = (_c: Change, replica: Replica): ApprovalDecision => {
      seenVectors.push(replica.vector);
      return 'apply';
    };
    mergeApproved(emptyReplica('b'), [...a.log].reverse(), { hook });
    expect(seenVectors).toEqual([{}, {}, {}]);
  });

  it('approving a number nothing holds is ignored; decisions are final', () => {
    const a = authored(2);
    const r = mergeApproved(emptyReplica('b'), a.log, { hook: holdAll }).replica;
    const none = approve(r, [{ device: 'zzz', seq: 9 }]);
    expect(pendingApproval(none.replica)).toHaveLength(2);
    const one = approve(r, [{ device: 'a', seq: 1 }]);
    expect(one.replica.vector).toEqual({ a: 1 });
    // a2 is still held
    expect(pendingApproval(one.replica).map((c) => c.seq)).toEqual([2]);
    const rej = reject(one.replica, [{ device: 'a', seq: 2 }]);
    expect(rej.replica.vector).toEqual({ a: 2 });
    // approving what is applied already does nothing
    expect(approve(rej.replica, [{ device: 'a', seq: 2 }]).applied).toBe(0);
  });
});

describe('approve', () => {
  it('applies held changes in a correct order (gap, knew) however they are named', () => {
    const a = authored(2);
    let b = merge(emptyReplica('b'), a.log).replica;
    b = written(b, 'r1', { v: 'b' });
    let c = emptyReplica('c');
    c = mergeApproved(c, [...b.log].reverse(), { hook: holdAll }).replica;
    expect(pendingApproval(c)).toHaveLength(3);
    const all = approve(c, [...pendingApproval(c)].reverse().map(ref));
    expect(all.replica.vector).toEqual({ a: 2, b: 1 });
    expect(all.applied).toBe(3);
    expect(all.replica.approval?.entries).toEqual([]);
    expect(fingerprint(all.replica)).toBe(fingerprint(b));
  });

  it('approving a change that cannot be applied yet keeps it decided until it can', () => {
    const a = authored(3);
    const r = mergeApproved(emptyReplica('b'), a.log, { hook: holdAll }).replica;
    // approve only number 3: gap, so it waits, decided
    const step = approve(r, [{ device: 'a', seq: 3 }]);
    expect(step.replica.vector).toEqual({});
    expect(decidedWaiting(step.replica).map((c) => c.seq)).toEqual([3]);
    expect(pendingApproval(step.replica).map((c) => c.seq)).toEqual([1, 2]);
    expect(step.held).toEqual([]);
    const rest = approve(step.replica, [
      { device: 'a', seq: 1 },
      { device: 'a', seq: 2 },
    ]);
    expect(rest.replica.vector).toEqual({ a: 3 });
    expect(decidedWaiting(rest.replica)).toEqual([]);
  });
});

describe('reject', () => {
  it('drops the content for good and does not block the later changes of the author', () => {
    const a = authored(3);
    let r = mergeApproved(emptyReplica('b'), a.log, {
      hook: (c) => (c.seq === 2 ? 'hold' : 'apply'),
    }).replica;
    expect(r.vector).toEqual({ a: 1 });
    r = reject(r, [{ device: 'a', seq: 2 }]).replica;
    expect(r.vector).toEqual({ a: 2 });
    expect(pendingApproval(r)).toEqual([]);
    const entry = r.log[1] as Change;
    expect(entry.kind).toBe('redacted');
    expect(entry.fields).toBeUndefined();
    expect(entry.sig ?? 'unsigned').toBeDefined();
    expect(values(r, 'r2')).toBeUndefined();
    // number 3 comes again and applies
    r = mergeApproved(r, a.log, { hook: (c) => (c.seq === 2 ? 'hold' : 'apply') }).replica;
    expect(r.vector).toEqual({ a: 3 });
    expect(values(r, 'r3')).toEqual({ v: 3 });
    // the rejected change is not asked again and never held again
    expect(pendingApproval(r)).toEqual([]);
  });

  it('a rejected change also counts for what names it in knew', () => {
    const a = authored(1);
    const b = written(merge(emptyReplica('b'), a.log).replica, 'r1', { v: 'b' });
    const bChange = b.log[1] as Change;
    let c = mergeApproved(emptyReplica('c'), [...a.log, bChange], { hook: holdFrom('a') }).replica;
    c = reject(c, [{ device: 'a', seq: 1 }]).replica;
    c = mergeApproved(c, [bChange]).replica;
    expect(c.vector).toEqual({ a: 1, b: 1 });
    // a's content never arrived, b's write did
    expect(values(c, 'r1')).toEqual({ v: 'b' });
  });

  it('the hook can reject at once: erased, counted, nothing held', () => {
    const a = authored(2);
    const r = mergeApproved(emptyReplica('b'), a.log, {
      hook: (c) => (c.seq === 1 ? 'reject' : 'apply'),
    });
    expect(r.replica.vector).toEqual({ a: 2 });
    expect(r.approval).toEqual({ held: 0, rejected: 1, dropped: 0 });
    expect(r.replica.log.map((c) => c.kind)).toEqual(['redacted', 'set']);
    expect(pendingApproval(r.replica)).toEqual([]);
  });

  it('a rejected change is not forwarded, nor what follows it from its author; others are', () => {
    const a = authored(3);
    const hook = (c: Change): ApprovalDecision => (c.seq === 2 ? 'reject' : 'apply');
    const b = mergeApproved(emptyReplica('b'), a.log, { hook }).replica;
    expect(b.vector).toEqual({ a: 3 });
    // a third device with a:1 asks b
    const c = merge(emptyReplica('c'), [a.log[0] as Change]).replica;
    const opened = startSession(c);
    const answer = onSyncMessage(startSession(b).session, b, opened.send[0] as never, {
      signedOnly: false,
    });
    const sent = answer.send.flatMap((m) => (m.t === 'changes' ? m.changes : []));
    expect(sent).toEqual([]);
    expect(answer.session.withheld).toBe(2);
    // a device that has nothing of a gets number 1 only
    const none = onSyncMessage(
      startSession(b).session,
      b,
      startSession(emptyReplica('d')).send[0] as never,
      { signedOnly: false },
    );
    expect(
      none.send.flatMap((m) => (m.t === 'changes' ? m.changes : [])).map((x) => x.seq),
    ).toEqual([1]);
    // a writer's own other devices are not cut off
    const e = written(b, 'mine', { q: 1 });
    const out = onSyncMessage(
      startSession(e).session,
      e,
      startSession(emptyReplica('d')).send[0] as never,
      { signedOnly: false },
    );
    const ids = out.send
      .flatMap((m) => (m.t === 'changes' ? m.changes : []))
      .map((x) => `${x.device}${x.seq}`);
    expect(ids).toEqual(['a1', 'b1']);
  });
});

describe('final deletions and their erased changes', () => {
  /** a writes r1 twice and deletes it; returns the log (two erased changes and the deletion). */
  function deletedLog(): { source: Replica; log: Change[] } {
    let a = emptyReplica('a');
    a = written(a, 'r1', { v: 1 });
    a = written(a, 'r1', { v: 2 });
    a = removed(a, COL, 'r1');
    return { source: a, log: [...a.log] };
  }

  it('a held deletion holds its erased changes; approving it applies them together', () => {
    const { source, log } = deletedLog();
    expect(log.map((c) => c.kind)).toEqual(['redacted', 'redacted', 'delete']);
    const hook = (c: Change): ApprovalDecision => (c.kind === 'delete' ? 'hold' : 'apply');
    const r = mergeApproved(emptyReplica('b'), log, { hook });
    expect(r.replica.vector).toEqual({});
    expect(pendingApproval(r.replica).map((c) => c.kind)).toEqual([
      'redacted',
      'redacted',
      'delete',
    ]);
    // later arrivals of the erased changes while the deletion is held do not get through either
    const r2 = mergeApproved(r.replica, [log[0] as Change], { hook });
    expect(r2.replica.vector).toEqual({});
    const done = approve(r2.replica, [{ device: 'a', seq: 3 }]);
    expect(done.replica.vector).toEqual({ a: 3 });
    expect(findRecord(done.replica, COL, 'r1')?.deleted).toBe(true);
    expect(fingerprint(done.replica)).toBe(fingerprint(source));
    expect(done.replica.approval?.entries).toEqual([]);
  });

  it('the companions cannot be decided alone: they follow the deletion', () => {
    const { log } = deletedLog();
    const hook = (c: Change): ApprovalDecision => (c.kind === 'delete' ? 'hold' : 'apply');
    const r = mergeApproved(emptyReplica('b'), log, { hook }).replica;
    const alone = approve(r, [
      { device: 'a', seq: 1 },
      { device: 'a', seq: 2 },
    ]);
    expect(alone.replica.vector).toEqual({});
    expect(pendingApproval(alone.replica)).toHaveLength(3);
  });

  it('a final deletion cannot be rejected: the hook and reject() leave it held', () => {
    const { log } = deletedLog();
    const rejectsDeletes = (c: Change): ApprovalDecision =>
      c.kind === 'delete' ? 'reject' : 'apply';
    let r = mergeApproved(emptyReplica('b'), log, { hook: rejectsDeletes }).replica;
    expect(pendingApproval(r).map((c) => c.kind)).toEqual(['redacted', 'redacted', 'delete']);
    r = reject(r, [{ device: 'a', seq: 3 }]).replica;
    expect(r.vector).toEqual({});
    expect(pendingApproval(r)).toHaveLength(3);
    expect(approve(r, [{ device: 'a', seq: 3 }]).replica.vector).toEqual({ a: 3 });
  });

  it('an erased change waits when its deletion waits behind a held change of its author', () => {
    let a = emptyReplica('a');
    a = written(a, 'r2', { v: 'first' });
    a = written(a, 'r1', { v: 'a' });
    let b = merge(emptyReplica('b'), a.log).replica;
    b = written(b, 'r1', { v: 'b' });
    a = merge(a, b.log.slice(2)).replica;
    a = removed(a, COL, 'r1');
    const log = [...a.log];
    expect(log.map((c) => `${c.device}${c.seq}${c.kind[0]}`)).toEqual(['a1s', 'a2r', 'b1r', 'a3d']);
    const hook = (c: Change): ApprovalDecision =>
      c.device === 'a' && c.seq === 1 ? 'hold' : 'apply';
    const c = mergeApproved(emptyReplica('c'), log, { hook });
    // b1 is an erased change that needs no number before it, but its deletion (a3) cannot be applied
    expect(c.replica.vector).toEqual({});
    expect(c.replica.log).toEqual([]);
    expect(c.held.map((x) => `${x.device}${x.seq}`).sort()).toEqual(['a2', 'a3', 'b1']);
    const approved = approve(c.replica, [{ device: 'a', seq: 1 }]);
    const done = mergeApproved(approved.replica, log, { hook });
    expect(done.replica.vector).toEqual({ a: 3, b: 1 });
    expect(findRecord(done.replica, COL, 'r1')?.deleted).toBe(true);
    expect(fingerprint(done.replica)).toBe(fingerprint(a));
  });

  it('a held write is erased when the record is deleted meanwhile, and goes through as an erased change', () => {
    let a = emptyReplica('a');
    a = written(a, 'r1', { v: 'secret' });
    const mine = a.log[0] as Change;
    let c = emptyReplica('c');
    c = ok(write(c, COL, 'r1', { v: 'other' }));
    const dels = removed(c, COL, 'r1');
    const deletion = dels.log[1] as Change;
    let b = mergeApproved(emptyReplica('b'), [mine], { hook: holdAll }).replica;
    expect(JSON.stringify(b.approval)).toContain('secret');
    b = mergeApproved(
      b,
      [...c.log.slice(0, 1), deletion].map((x, i) => (i === 0 ? { ...x } : x)),
      {
        hook: (ch) => (ch.device === 'a' ? 'hold' : 'apply'),
      },
    ).replica;
    expect(findRecord(b, COL, 'r1')?.deleted).toBe(true);
    expect(JSON.stringify(b)).not.toContain('secret');
    expect(b.vector.a).toBe(1);
    expect(pendingApproval(b)).toEqual([]);
  });

  it('a write to a record that is already deleted is not asked and never kept', () => {
    const { log } = deletedLog();
    let b = merge(emptyReplica('b'), log).replica;
    let c = emptyReplica('c');
    c = written(c, 'r1', { v: 'late secret' });
    let asked = 0;
    b = mergeApproved(b, c.log, {
      hook: () => {
        asked += 1;
        return 'hold';
      },
    }).replica;
    expect(asked).toBe(0);
    expect(b.vector.c).toBe(1);
    expect(JSON.stringify(b)).not.toContain('late secret');
  });
});

describe('the stored state', () => {
  function sample(): Replica {
    const a = authored(3);
    return mergeApproved(emptyReplica('b'), a.log, { hook: holdAll }).replica;
  }

  it('is plain JSON and reads back the same; the replica keeps working', () => {
    const r = sample();
    const read = readApprovalState(json(r.approval));
    expect(read).toEqual({ ok: true, state: r.approval });
    if (!read.ok) return;
    const restored: Replica = { ...r, approval: read.state };
    const done = approve(restored, pendingApproval(restored).map(ref));
    expect(done.replica.vector).toEqual({ a: 3 });
  });

  it('is sorted when read, whatever the stored order', () => {
    const r = sample();
    const shuffled = { entries: [...(r.approval?.entries ?? [])].reverse() };
    const read = readApprovalState(json(shuffled));
    expect(read).toEqual({ ok: true, state: r.approval });
  });

  it('refuses everything that is not exactly a state', () => {
    const r = sample();
    const entry = json((r.approval?.entries ?? [])[0]) as unknown as {
      change: Record<string, unknown>;
      decision: string;
    };
    const cases: [unknown, string][] = [
      [null, 'not-object'],
      [[], 'not-object'],
      ['x', 'not-object'],
      [{}, 'bad-entries'],
      [{ entries: {} }, 'bad-entries'],
      [{ entries: [], extra: 1 }, 'unknown-member'],
      [{ entries: [1] }, 'bad-entry'],
      [{ entries: [{ change: entry.change }] }, 'bad-entry'],
      [{ entries: [{ ...entry, extra: 1 }] }, 'bad-entry'],
      [{ entries: [{ ...entry, decision: 'maybe' }] }, 'bad-decision'],
      [{ entries: [{ ...entry, decision: undefined }] }, 'bad-decision'],
      [
        {
          entries: [
            {
              change: { ...entry.change, kind: 'delete', fields: undefined },
              decision: 'rejected',
            },
          ],
        },
        'bad-decision',
      ],
      [{ entries: [{ change: { ...entry.change, seq: 0 }, decision: 'hold' }] }, 'bad-change'],
      [{ entries: [{ change: { ...entry.change, extra: 1 }, decision: 'hold' }] }, 'bad-change'],
      [{ entries: [entry, entry] }, 'duplicate'],
    ];
    for (const [raw, reason] of cases) {
      expect(readApprovalState(raw), JSON.stringify(raw).slice(0, 60)).toEqual({
        ok: false,
        reason,
      });
    }
    expect(readApprovalState(json(r.approval), { maxPending: 2 })).toEqual({
      ok: false,
      reason: 'too-many',
    });
    expect(readApprovalState(json(r.approval), { maxChars: 100 })).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect(readApprovalState(json(r.approval), { maxPending: 3 }).ok).toBe(true);
  });

  it('a hostile object never throws the reader (getters, proxies, __proto__)', () => {
    const evil = JSON.parse('{"entries":[],"__proto__":{"x":1}}') as unknown;
    expect(readApprovalState(evil)).toEqual({ ok: false, reason: 'unknown-member' });
    const getter = {
      get entries(): unknown {
        throw new Error('no');
      },
    };
    expect(readApprovalState(getter).ok).toBe(false);
    expect(readApprovalState(new Map()).ok).toBe(false);
  });
});

describe('bounds', () => {
  it('maxPending keeps the first by device and number, drops the rest, and they come again', () => {
    const a = authored(6);
    const r = mergeApproved(emptyReplica('b'), a.log, { hook: holdAll, maxPending: 4 });
    expect(r.replica.approval?.entries).toHaveLength(4);
    expect(r.approval).toEqual({ held: 4, rejected: 0, dropped: 2 });
    const room = approve(r.replica, pendingApproval(r.replica).map(ref), { maxPending: 4 });
    expect(room.replica.vector).toEqual({ a: 4 });
    const more = mergeApproved(room.replica, a.log, { hook: holdAll, maxPending: 4 });
    expect(pendingApproval(more.replica).map((c) => c.seq)).toEqual([5, 6]);
    expect(more.approval.dropped).toBe(0);
  });

  it('maxChars bounds the size of what is kept', () => {
    const a = authored(5);
    const one = JSON.stringify(a.log[0]).length;
    const r = mergeApproved(emptyReplica('b'), a.log, { hook: holdAll, maxChars: one * 2 + 5 });
    expect(r.replica.approval?.entries.length).toBeLessThanOrEqual(2);
    expect(r.approval.dropped).toBeGreaterThanOrEqual(3);
  });

  it('a deletion that does not fit takes its erased changes with it: they never pass without it', () => {
    let a = emptyReplica('a');
    a = written(a, 'r1', { v: 1 });
    a = removed(a, COL, 'r1');
    const hook = (c: Change): ApprovalDecision => (c.kind === 'delete' ? 'hold' : 'apply');
    const r = mergeApproved(emptyReplica('b'), [...a.log], { hook, maxPending: 1 });
    // the deletion is held first, its erased change does not fit: it comes again, never alone
    expect(r.replica.vector).toEqual({});
    expect(pendingApproval(r.replica).map((c) => c.kind)).toEqual(['delete']);
    expect(r.approval.dropped).toBe(1);
    expect(findRecord(r.replica, COL, 'r1')).toBeUndefined();
    const again = mergeApproved(r.replica, [...a.log], { hook, maxPending: 2 });
    expect(pendingApproval(again.replica).map((c) => c.kind)).toEqual(['redacted', 'delete']);
    expect(approve(again.replica, [{ device: 'a', seq: 2 }]).replica.vector).toEqual({ a: 2 });
  });

  it('the defaults are the documented ones', () => {
    expect(APPROVAL_LIMITS).toEqual({ maxPending: 2000, maxChars: 8_000_000 });
  });
});

describe('sessions', () => {
  it('counts what the hook did and the fingerprints differ until the held change is decided', () => {
    const a = authored(2);
    const b0 = emptyReplica('b');
    let sa = startSession(a);
    let sb = startSession(b0);
    let b = b0;
    const options = { approval: { hook: holdAll }, signedOnly: false };
    const toB = onSyncMessage(sb.session, b, sa.send[0] as never, options);
    // b answers a's stand with nothing; a answers b's stand with its changes
    const answer = onSyncMessage(sa.session, a, sb.send[0] as never, { signedOnly: false });
    sa = { ...sa, session: answer.session };
    for (const m of answer.send) {
      const step = onSyncMessage(toB.session, b, m, options);
      b = step.replica;
      sb = { ...sb, session: step.session };
    }
    expect(sb.session.approvals).toEqual({ held: 2, rejected: 0, dropped: 0 });
    expect(b.vector).toEqual({});
    expect(outcome(sb.session, b)?.equal ?? false).toBe(false);
  });
});
