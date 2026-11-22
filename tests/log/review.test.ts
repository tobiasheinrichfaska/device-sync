// Office review as a derived view of the log: the cases of the earlier implementation, re-expressed for the
// package, and what the derived model adds (shortened `knew`, removal of an approver, both models side by
// side, seeded schedules whose views converge, cost).
import { describe, expect, it } from 'vitest';
import {
  approveAll,
  approveChange,
  correctValue,
  emptyReplica,
  findRecord,
  isHidden,
  keepValue,
  mergeApproved,
  merge,
  missingFor,
  pendingApproval,
  recordsWithRequests,
  review,
  remove,
  requestCount,
  reviewConflicts,
  reviewRequests,
  reviewSettlements,
  reviewView,
  takeApproverValue,
  visibleRecords,
  write,
  type Change,
  type Replica,
  type ReviewConfig,
  type ReviewRequest,
  type ReviewWriteResult,
} from '../../src/log/index.ts';
import { canonical } from '../../src/core/index.ts';
import { prng } from './helpers.ts';

const APPROVERS = new Set(['b1', 'b2']);
const config: ReviewConfig = {
  isApprover: (d) => APPROVERS.has(d),
  reviewed: (c) => c !== 'times',
};
const PLAN = 'plan';

const put = (
  r: Replica,
  collection: string,
  id: string,
  fields: Record<string, unknown>,
): Replica => {
  const x = write(r, collection, id, fields, { time: 1000, by: r.device });
  expect(x.ok).toBe(true);
  return (x as { replica: Replica }).replica;
};
const plan = (r: Replica, id: string, fields: Record<string, unknown>): Replica =>
  put(r, PLAN, id, fields);
const sync = (to: Replica, from: Replica): Replica =>
  merge(to, missingFor(from, to.vector)).replica;
const value = (r: Replica, id: string, f: string): unknown =>
  findRecord(r, PLAN, id)?.fields[f]?.value;
const taken = (r: ReviewWriteResult): Replica => {
  expect(r.ok).toBe(true);
  return (r as { replica: Replica }).replica;
};
const requests = (r: Replica): ReviewRequest[] => reviewRequests(r, config);
const approvedValue = (r: Replica, id: string, f: string): unknown =>
  findRecord(reviewView(r, config), PLAN, id)?.fields[f]?.value;

function start(): { b: Replica; l: Replica } {
  const b = plan(emptyReplica('b1'), 'mon', { day: 'mon', slot: 'am', rooms: ['1-3'] });
  return { b, l: sync(emptyReplica('l1'), b) };
}

describe('office review, the cases of the earlier implementation', () => {
  it('a new entry of another device waits; taken over field by field it is approved and nothing comes back', () => {
    let { b, l } = start();
    l = plan(l, 'tue', { day: 'tue', slot: 'am', rooms: ['4-6'] });
    b = sync(b, l);
    const open = requests(b);
    expect(open.map((a) => a.field).sort()).toEqual(['day', 'rooms', 'slot']);
    expect(open.every((a) => a.device === 'l1' && !a.conflict && a.approved === undefined)).toBe(
      true,
    );
    expect(requestCount(open)).toBe(3);
    expect(recordsWithRequests(open)).toEqual(new Set([JSON.stringify([PLAN, 'tue'])]));
    expect(findRecord(reviewView(b, config), PLAN, 'tue')).toBeUndefined();
    expect(approvedValue(b, 'mon', 'rooms')).toEqual(['1-3']);
    for (const a of open) b = taken(approveChange(b, a, config));
    expect(requests(b)).toEqual([]);
    expect(approvedValue(b, 'tue', 'rooms')).toEqual(['4-6']);
    l = sync(l, b);
    expect(requests(l)).toEqual([]);
  });

  it('"take all" writes one change per entry, the newest request of a sequence', () => {
    let { b, l } = start();
    l = plan(l, 'mon', { rooms: ['4-6'] });
    let l2 = sync(emptyReplica('l2'), l);
    l2 = plan(l2, 'mon', { rooms: ['7-8'] });
    b = sync(sync(b, l), l2);
    const open = requests(b);
    expect(open.map((a) => [a.device, a.conflict])).toEqual([
      ['l2', undefined],
      ['l1', undefined],
    ]);
    const before = b.log.length;
    const r = approveAll(b, open, config);
    expect(r).toMatchObject({ approved: 1, skipped: 0, failed: 0 });
    expect(r.replica.log.length).toBe(before + 1);
    expect(value(r.replica, 'mon', 'rooms')).toEqual(['7-8']);
    expect(requests(r.replica)).toEqual([]);
  });

  it('two requests that did not know each other are a conflict; "take all" leaves the field', () => {
    let { b, l } = start();
    let l2 = sync(emptyReplica('l2'), b);
    l = plan(l, 'mon', { rooms: ['4-6'] });
    l2 = plan(l2, 'mon', { rooms: ['7-8'] });
    l = plan(l, 'fri', { day: 'fri', slot: 'pm', rooms: ['1-3'] });
    b = sync(sync(b, l), l2);
    const open = requests(b);
    expect(open.slice(0, 2).map((a) => a.conflict)).toEqual([
      'concurrent-requests',
      'concurrent-requests',
    ]);
    expect(open.slice(2).every((a) => a.conflict === undefined)).toBe(true);
    expect(reviewConflicts(b, config)).toMatchObject([
      {
        kind: 'concurrent-requests',
        field: 'rooms',
        values: [
          { device: 'l1', value: ['4-6'] },
          { device: 'l2', value: ['7-8'] },
        ],
      },
    ]);
    const r = approveAll(b, open, config);
    expect(r).toMatchObject({ approved: 3, skipped: 2 });
    expect(requests(r.replica).map((a) => a.field)).toEqual(['rooms', 'rooms']);
    // decided one by one, both go
    const c = taken(correctValue(r.replica, open[0] as ReviewRequest, ['9-10'], config));
    expect(requests(c)).toEqual([]);
    expect(value(c, 'mon', 'rooms')).toEqual(['9-10']);
  });

  it('a request that did not know the last approval is a conflict, on the approver and on the requester', () => {
    let { b, l } = start();
    b = plan(b, 'mon', { rooms: ['7-8'] });
    l = plan(l, 'mon', { rooms: ['4-6'] });
    b = sync(b, l);
    const [a] = requests(b);
    expect(a).toMatchObject({
      conflict: 'approval-not-known',
      value: ['4-6'],
      approved: { value: ['7-8'], device: 'b1' },
    });
    expect(approvedValue(b, 'mon', 'rooms')).toEqual(['7-8']);
    // the requesting device sees its own request against the approved view too
    l = sync(l, b);
    expect(requests(l).map((x) => x.device)).toEqual(['l1']);
    expect(approvedValue(l, 'mon', 'rooms')).toEqual(['7-8']);
  });

  it('"keep" rejects; a request that knew the approval is no conflict', () => {
    let { b, l } = start();
    l = plan(l, 'mon', { rooms: ['4-6'] });
    b = sync(b, l);
    const [a] = requests(b);
    expect((a as ReviewRequest).conflict).toBeUndefined();
    b = taken(keepValue(b, a as ReviewRequest, config));
    expect(requests(b)).toEqual([]);
    expect(value(b, 'mon', 'rooms')).toEqual(['1-3']);
  });

  it('rejecting a new entry hides it; only bringing it back is a request again', () => {
    let { b, l } = start();
    l = plan(l, 'tue', { day: 'tue', slot: 'am', rooms: ['4-6'] });
    b = sync(b, l);
    for (const a of requests(b)) b = taken(keepValue(b, a, config));
    expect(requests(b)).toEqual([]);
    expect(approvedValue(b, 'tue', 'deleted')).toBe(true);
    l = plan(sync(l, b), 'tue', { deleted: false });
    b = sync(b, l);
    expect(requests(b).map((x) => [x.field, x.value])).toEqual([['deleted', false]]);
  });

  it('the same value as approved asks for nothing; an earlier write of a device counts no more', () => {
    let { b, l } = start();
    l = plan(l, 'mon', { rooms: ['4-6'] });
    l = plan(l, 'mon', { rooms: ['1-3'] });
    b = sync(b, l);
    expect(requests(b)).toEqual([]);
  });

  it('two approved values that did not know each other are a conflict; times are not reviewed', () => {
    let { b } = start();
    let b2 = sync(emptyReplica('b2'), b);
    b = plan(b, 'mon', { rooms: ['4-6'] });
    b2 = plan(b2, 'mon', { rooms: ['7-8'] });
    b = sync(b, b2);
    expect(requests(b)).toEqual([]);
    expect(reviewConflicts(b, config)).toMatchObject([{ kind: 'approver-clash', field: 'rooms' }]);
    // a final deletion stays one in the approved view
    const gone = taken(remove(b, PLAN, 'mon'));
    expect(findRecord(reviewView(gone, config), PLAN, 'mon')?.deleted).toBe(true);
    const l = put(emptyReplica('l1'), 'times', 't1', { person: 'ann', date: '2026-01-01' });
    expect(reviewRequests(l, config)).toEqual([]);
    expect(findRecord(reviewView(l, config), 'times', 't1')?.fields.person?.value).toBe('ann');
  });

  describe('a conflict of two approvers is decided with one write; the other approver is told', () => {
    const clash = (): { b: Replica; b2: Replica } => {
      let { b } = start();
      let b2 = sync(emptyReplica('b2'), b);
      b = plan(b, 'mon', { rooms: ['4-6'] });
      b2 = plan(b2, 'mon', { rooms: ['7-8'] });
      return { b: sync(b, b2), b2: sync(b2, b) };
    };
    const first = (r: Replica) =>
      reviewConflicts(r, config)[0] as ReturnType<typeof reviewConflicts>[number];

    it('either approver picks one of the values; settled there and, after the exchange, on the other', () => {
      let { b, b2 } = clash();
      const c = first(b);
      expect(c).toMatchObject({
        kind: 'approver-clash',
        values: [
          { value: ['4-6'], device: 'b1' },
          { value: ['7-8'], device: 'b2' },
        ],
      });
      b = taken(takeApproverValue(b, c, ['7-8'], config));
      expect(value(b, 'mon', 'rooms')).toEqual(['7-8']);
      expect(b.notices).toEqual([]);
      expect(reviewConflicts(b, config)).toEqual([]);
      // the clash is still there on the other device until the decision arrives
      expect(reviewConflicts(b2, config)).toHaveLength(1);
      b2 = sync(b2, b);
      expect(reviewConflicts(b2, config)).toEqual([]);
      expect(value(b2, 'mon', 'rooms')).toEqual(['7-8']);
      // both see who decided; it is a hint, never a request
      for (const r of [b, b2]) {
        expect(reviewSettlements(r, config)).toMatchObject([
          { field: 'rooms', value: ['7-8'], device: 'b1' },
        ]);
        expect(requests(r)).toEqual([]);
      }
    });

    it('only a value of the clash, only for such a clash, only on an approver device', () => {
      const { b } = clash();
      const c = first(b);
      expect(takeApproverValue(b, c, ['9-10'], config)).toEqual({
        ok: false,
        reason: 'unknown-value',
      });
      const s = start();
      const l = plan(s.l, 'mon', { rooms: ['4-6'] });
      expect(takeApproverValue(b, { ...c, kind: 'concurrent-requests' }, ['4-6'], config)).toEqual({
        ok: false,
        reason: 'not-an-approver-clash',
      });
      expect(requests(sync(s.b, l))).toHaveLength(1);
      expect(takeApproverValue(sync(emptyReplica('l9'), b), c, ['4-6'], config)).toEqual({
        ok: false,
        reason: 'not-approver',
      });
      expect(approveAll(b, requests(b), config)).toMatchObject({ replica: b, approved: 0 });
    });

    it('both decide the same value at once: nothing is left on either device', () => {
      let { b, b2 } = clash();
      b = taken(takeApproverValue(b, first(b), ['7-8'], config));
      b2 = taken(takeApproverValue(b2, first(b2), ['7-8'], config));
      for (const r of [sync(b, b2), sync(b2, b)]) {
        expect(reviewConflicts(r, config)).toEqual([]);
        expect(requests(r)).toEqual([]);
        expect(r.notices).toEqual([]);
      }
    });

    it('both decide different values at once: a new clash of the two decisions, ended by one more decision', () => {
      let { b, b2 } = clash();
      b = taken(takeApproverValue(b, first(b), ['4-6'], config));
      b2 = taken(takeApproverValue(b2, first(b2), ['7-8'], config));
      b = sync(b, b2);
      b2 = sync(b2, b);
      for (const r of [b, b2]) {
        expect(reviewConflicts(r, config)).toMatchObject([
          {
            kind: 'approver-clash',
            values: [
              { value: ['4-6'], device: 'b1' },
              { value: ['7-8'], device: 'b2' },
            ],
          },
        ]);
      }
      // the later decision wins by the log's own rules; the other device just takes note
      b = taken(takeApproverValue(b, first(b), ['7-8'], config));
      expect(reviewConflicts(b, config)).toEqual([]);
      b2 = sync(b2, b);
      expect(reviewConflicts(b2, config)).toEqual([]);
      expect(requests(b2)).toEqual([]);
      expect(requests(sync(b, b2))).toEqual([]);
      expect(value(b2, 'mon', 'rooms')).toEqual(['7-8']);
      expect(JSON.stringify(reviewSettlements(b, config))).toBe(
        JSON.stringify(reviewSettlements(b2, config)),
      );
    });

    it('a final deletion takes the clash and its hint with it', () => {
      let { b, b2 } = clash();
      b = taken(takeApproverValue(b, first(b), ['4-6'], config));
      b2 = sync(b2, b);
      expect(reviewSettlements(b2, config)).toHaveLength(1);
      b = taken(remove(b, PLAN, 'mon'));
      b2 = sync(b2, b);
      expect(reviewSettlements(b2, config)).toEqual([]);
      expect(reviewConflicts(b2, config)).toEqual([]);
      expect(requests(b2)).toEqual([]);
    });
  });

  it('only an approver decides; "take all" per person', () => {
    let { b, l } = start();
    let l2 = sync(emptyReplica('l2'), b);
    l = plan(l, 'mon', { rooms: ['4-6'] });
    l2 = plan(l2, 'wed', { day: 'wed', slot: 'pm' });
    b = sync(sync(b, l), l2);
    const open = requests(b);
    expect(approveChange(sync(l, b), open[0] as ReviewRequest, config)).toEqual({
      ok: false,
      reason: 'not-approver',
    });
    expect(approveAll(l, open, config)).toMatchObject({ replica: l, approved: 0 });
    const r = approveAll(b, open, config, { select: (a) => a.device === 'l2' });
    expect(r.approved).toBe(2);
    expect(requests(r.replica).map((a) => a.device)).toEqual(['l1']);
  });
});

describe('what the derived model adds', () => {
  it('a decision that settled a request by a shortened `knew` (a head that knew it) still settles it', () => {
    // l2 saw l1's request and wrote after it: only l2 is a head, so the approver's `knew` names l2 alone
    let { b, l } = start();
    l = plan(l, 'mon', { rooms: ['4-6'] });
    let l2 = plan(sync(emptyReplica('l2'), l), 'mon', { rooms: ['7-8'] });
    b = sync(sync(b, l), l2);
    const open = requests(b);
    const top = open.find((a) => a.device === 'l2') as ReviewRequest;
    b = taken(approveChange(b, top, config));
    const decided = b.log[b.log.length - 1] as Change;
    expect(Object.keys(decided.knew ?? {})).not.toContain('l1');
    expect(requests(b)).toEqual([]);
    l2 = sync(l2, b);
    expect(requests(l2)).toEqual([]);
  });

  it('a request answered by a newer write that asks for the approved value is not taken over later', () => {
    let { b, l } = start();
    l = plan(l, 'mon', { rooms: ['4-6'] });
    let l2 = plan(sync(emptyReplica('l2'), l), 'mon', { rooms: ['1-3'] });
    b = sync(sync(b, l), l2);
    l2 = sync(l2, b);
    expect(requests(b)).toEqual([]);
    expect(approveAll(b, requests(b), config).approved).toBe(0);
  });

  it('a removed approver: its writes are requests again, its decisions do not hold, the other approver decides', () => {
    let { b, l } = start();
    let b2 = sync(emptyReplica('b2'), b);
    l = plan(l, 'mon', { rooms: ['4-6'] });
    b2 = plan(sync(b2, l), 'mon', { rooms: ['4-6'], slot: 'pm' });
    b = sync(sync(b, l), b2);
    expect(requests(b)).toEqual([]);
    expect(approvedValue(b, 'mon', 'slot')).toBe('pm');
    // the app stops trusting b2: the predicate answers from state the app derives from the log
    const removed: ReviewConfig = { ...config, isApprover: (d) => d === 'b1' };
    expect(reviewView(b, removed).collections[PLAN]?.mon?.fields.slot?.value).toBe('am');
    const open = reviewRequests(b, removed);
    expect(open.map((a) => [a.field, a.device, a.value]).sort()).toEqual([
      ['rooms', 'b2', ['4-6']],
      ['rooms', 'l1', ['4-6']],
      ['slot', 'b2', 'pm'],
    ]);
    const slot = open.find((a) => a.field === 'slot') as ReviewRequest;
    expect(slot.approved).toMatchObject({ device: 'b1', value: 'am' });
    // b1 keeps its own value: the compromised write is settled
    b = taken(keepValue(b, slot, removed));
    expect(reviewRequests(b, removed).map((a) => a.field)).toEqual(['rooms', 'rooms']);
    // and the removed device can no longer decide
    expect(approveChange(b2, slot, removed)).toEqual({ ok: false, reason: 'not-approver' });
    // two approvers that disagree about the removal derive different views, which is the app's to avoid
    expect(JSON.stringify(reviewView(b, config))).not.toBe(JSON.stringify(reviewView(b, removed)));
  });

  it('a throwing predicate or collection filter counts as "no"', () => {
    const { b, l } = start();
    const bad: ReviewConfig = {
      isApprover: () => {
        throw new Error('x');
      },
      reviewed: () => {
        throw new Error('y');
      },
    };
    expect(reviewRequests(sync(b, plan(l, 'mon', { rooms: ['4-6'] })), bad)).toEqual([]);
    expect(
      approveChange(
        b,
        { collection: PLAN, id: 'mon', field: 'rooms', value: 1, device: 'x', seq: 1 },
        bad,
      ),
    ).toEqual({
      ok: false,
      reason: 'not-reviewed',
    });
  });

  it("the decision refuses a record that does not exist and reports the write's own codes", () => {
    const { b } = start();
    const ghost = { collection: PLAN, id: 'nope', field: 'rooms', value: 1, device: 'l1', seq: 1 };
    expect(approveChange(b, ghost, config)).toEqual({ ok: false, reason: 'no-record' });
    expect(correctValue(b, { ...ghost, id: 'mon' }, { bad: () => 1 }, config)).toMatchObject({
      ok: false,
    });
    expect(
      correctValue(b, { collection: PLAN, id: 'x'.repeat(5000), field: 'f' }, 1, config),
    ).toMatchObject({
      ok: false,
    });
  });
});

describe('the two models side by side', () => {
  const HELD = 'secret';
  const hook = (c: Change): 'apply' | 'hold' => (c.collection === HELD ? 'hold' : 'apply');
  const mixed: ReviewConfig = { ...config, reviewed: (c) => c === PLAN };

  it('the review ignores changes held back for approval and leaves the held state alone', () => {
    const { b, l } = start();
    let l2 = plan(l, 'mon', { rooms: ['4-6'] });
    l2 = put(l2, HELD, 's1', { text: 'x' });
    const received = mergeApproved(b, missingFor(l2, b.vector), { hook });
    let r = received.replica;
    expect(pendingApproval(r).length).toBeGreaterThan(0);
    expect(reviewRequests(r, mixed).map((a) => a.collection)).toEqual([PLAN]);
    const held = r.approval;
    const [req] = reviewRequests(r, mixed);
    r = taken(approveChange(r, req as ReviewRequest, mixed));
    expect(r.approval).toBe(held);
    expect(pendingApproval(r)).toEqual(pendingApproval(received.replica));
    expect(reviewRequests(r, mixed)).toEqual([]);
    // a collection that is not reviewed is not decided here
    expect(correctValue(r, { collection: HELD, id: 's1', field: 'text' }, 1, mixed)).toEqual({
      ok: false,
      reason: 'not-reviewed',
    });
  });

  it('review decisions and derived notices agree: a decision settles the notice', () => {
    let { b, l } = start();
    const l2 = plan(sync(emptyReplica('l2'), b), 'mon', { rooms: ['7-8'] });
    l = plan(l, 'mon', { rooms: ['4-6'] });
    b = sync(sync(b, l), l2);
    expect(b.notices).toHaveLength(1);
    const [req] = requests(b);
    b = taken(approveChange(b, req as ReviewRequest, config));
    expect(b.notices).toEqual([]);
  });
});

// ---- seeded schedules ----

const DEVICES = ['b1', 'b2', 'l1', 'l2', 'l3'];
const IDS = ['r1', 'r2', 'r3'];
const FIELDS = ['a', 'b', 'c'];

function schedule(seed: number): Replica[] {
  const rnd = prng(seed);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
  let replicas = DEVICES.map((d) => emptyReplica(d));
  for (let step = 0; step < 70; step += 1) {
    const i = Math.floor(rnd() * DEVICES.length);
    const r = replicas[i] as Replica;
    const roll = rnd();
    if (roll < 0.4) {
      const id = pick(IDS);
      const fields = Object.fromEntries(
        FIELDS.filter(() => rnd() < 0.5).map((f) => [f, pick(['x', 'y', 'z'])]),
      );
      if (Object.keys(fields).length > 0) replicas[i] = put(r, 'plan', id, fields);
    } else if (roll < 0.65) {
      const j = Math.floor(rnd() * DEVICES.length);
      if (j !== i) replicas[i] = sync(r, replicas[j] as Replica);
    } else if (APPROVERS.has(r.device)) {
      const open = reviewRequests(r, config);
      const clashes = reviewConflicts(r, config).filter((c) => c.kind === 'approver-clash');
      const kind = pick(['take', 'keep', 'correct', 'all', 'clash']);
      let result: ReviewWriteResult | undefined;
      if (kind === 'all') {
        replicas[i] = approveAll(r, open, config, { select: () => rnd() < 0.8 }).replica;
      } else if (kind === 'clash' && clashes.length > 0) {
        const c = pick(clashes);
        result = takeApproverValue(r, c, pick(c.values).value, config);
      } else if (open.length > 0) {
        const q = pick(open);
        result =
          kind === 'take'
            ? approveChange(r, q, config)
            : kind === 'keep'
              ? keepValue(r, q, config)
              : correctValue(r, q, pick(['x', 'y', 'q']), config);
      }
      // a record may have been created by nobody yet; every refusal here is a code, never a throw
      if (result?.ok) replicas[i] = result.replica;
    }
  }
  // everybody ends up with everything
  for (let round = 0; round < 2; round += 1) {
    replicas = replicas.map((r) =>
      replicas.reduce((acc, other) => (other === r ? acc : sync(acc, other)), r),
    );
  }
  return replicas;
}

const digest = (r: Replica): string =>
  canonical([
    reviewRequests(r, config),
    reviewConflicts(r, config),
    reviewSettlements(r, config),
    reviewView(r, config).collections,
  ]);

describe('seeded multi-device schedules', () => {
  it('120 schedules: every device derives the same review, in any order of delivery', () => {
    for (let seed = 1; seed <= 120; seed += 1) {
      const replicas = schedule(seed);
      const reference = digest(replicas[0] as Replica);
      for (const r of replicas) expect(digest(r), `seed ${seed}`).toBe(reference);
      // a replica that received every change in one shuffled batch derives the same
      const rnd = prng(seed + 7);
      const all = [...(replicas[0] as Replica).log].sort(() => rnd() - 0.5);
      const batch = merge(emptyReplica('l3'), all).replica;
      expect(digest(batch), `seed ${seed} shuffled`).toBe(reference);
    }
  });

  it('60 schedules: one approver deciding everything one by one empties requests and conflicts, and it stays empty', () => {
    for (let seed = 1; seed <= 60; seed += 1) {
      const replicas = schedule(seed + 1000);
      let b = replicas[0] as Replica;
      for (let guard = 0; guard < 200; guard += 1) {
        const q = reviewRequests(b, config)[0];
        const c = reviewConflicts(b, config).find((x) => x.kind === 'approver-clash');
        if (q) b = taken(correctValue(b, q, 'fin', config));
        else if (c)
          b = taken(takeApproverValue(b, c, (c.values[0] as { value: unknown }).value, config));
        else break;
      }
      expect(reviewRequests(b, config), `seed ${seed}`).toEqual([]);
      expect(reviewConflicts(b, config), `seed ${seed}`).toEqual([]);
      // a record an approver hid keeps its notices: only a request to bring it back is open (docs/review.md)
      const live = b.notices.filter((n) => {
        const record = findRecord(b, n.collection, n.id);
        return record !== undefined && !isHidden(record);
      });
      expect(live, `seed ${seed}`).toEqual([]);
      // the others take it and agree
      const other = sync(replicas[3] as Replica, b);
      expect(digest(other), `seed ${seed}`).toBe(digest(sync(b, other)));
      expect(reviewRequests(other, config), `seed ${seed}`).toEqual([]);
      expect(visibleRecords(reviewView(other, config), PLAN).length).toBeGreaterThanOrEqual(0);
    }
  });
});

// ---- cost ----

function many(writes: number, fieldsPerRecord: number): Replica {
  const changes: Change[] = [];
  const records = Math.max(1, Math.floor(writes / 8));
  const seqs: Record<string, number> = { b1: 0, l1: 0, l2: 0 };
  let clock = 0;
  for (let i = 0; i < writes; i += 1) {
    const device = ['b1', 'l1', 'l2'][i % 3] as string;
    seqs[device] = (seqs[device] ?? 0) + 1;
    clock += 1;
    const f = i % fieldsPerRecord;
    changes.push({
      device,
      seq: seqs[device] as number,
      clock,
      collection: PLAN,
      id: `r${i % records}`,
      kind: 'set',
      fields: { [`f${f}`]: `v${i}` },
      knew: seqs[device] === 1 ? {} : { [device]: (seqs[device] as number) - 1 },
    });
  }
  return merge(emptyReplica('x'), changes).replica;
}

const reviewAll = (r: Replica) => review(r, config);
const time = <T>(run: () => T): [T, number] => {
  const start = performance.now();
  const out = run();
  return [out, performance.now() - start];
};

describe('cost', () => {
  it('the review of 6000 and of 24000 writes costs about four times as much, not sixteen', () => {
    const small = many(6000, 5);
    const large = many(24000, 5);
    reviewAll(small); // warm up the index
    reviewAll(large);
    // The best of three runs each: one slow run is garbage collection or a loaded machine, a
    // quadratic review is slow in every run.
    let a = reviewAll(small);
    let b = reviewAll(large);
    let fast = Infinity;
    let slow = Infinity;
    for (let run = 0; run < 3; run += 1) {
      const [ra, ta] = time(() => reviewAll(small));
      const [rb, tb] = time(() => reviewAll(large));
      a = ra;
      b = rb;
      fast = Math.min(fast, ta);
      slow = Math.min(slow, tb);
    }
    expect(a.requests.length).toBeGreaterThan(0);
    expect(b.requests.length).toBeGreaterThan(a.requests.length);
    expect(fast).toBeLessThan(2500);
    expect(slow).toBeLessThan(5000);
    // four times the writes: about 4 times the time when linear, about 16 when quadratic
    expect(slow / Math.max(fast, 1)).toBeLessThan(8);
  });

  it('thousands of writes of two devices to one field stay linear', () => {
    const one = (n: number): Replica => {
      const changes: Change[] = [];
      for (let i = 1; i <= n; i += 1) {
        for (const d of ['b1', 'l1']) {
          changes.push({
            device: d,
            seq: i,
            clock: 2 * i + (d === 'l1' ? 1 : 0),
            collection: PLAN,
            id: 'r',
            kind: 'set',
            fields: { f: `${d}${i}` },
            knew: i === 1 ? {} : { [d]: i - 1 },
          });
        }
      }
      return merge(emptyReplica('x'), changes).replica;
    };
    const [r1, t1] = time(() => reviewAll(one(3000)));
    const [r2, t2] = time(() => reviewAll(one(6000)));
    expect(r1.requests).toHaveLength(1);
    expect(r2.requests).toHaveLength(1);
    expect(t2).toBeLessThan(5000);
    expect(t2 / Math.max(t1, 1)).toBeLessThan(3.4);
  });
});
