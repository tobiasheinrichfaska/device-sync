// Full stack with real signatures: signed, cut into pieces, JSON, strictly read, judged, then through the
// approval hook. A held change is not claimed by any stand, a rejected one never makes a peer refuse
// the session, and after the decisions the devices converge as far as the decisions allow.
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  approve,
  emptyReplica,
  findRecord,
  fingerprint,
  insertSignatures,
  merge,
  outcome,
  pendingApproval,
  readApprovalState,
  receiveJudged,
  reject,
  signOwnChanges,
  startSession,
  type ApprovalDecision,
  type Change,
  type JudgeOptions,
  type KeySource,
  type Replica,
  type Session,
  type SessionOptions,
} from '../../src/log/index.ts';
import { COL, removed, written } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
const IDS = ['a', 'b', 'c'] as const;
const pairs: Record<string, CryptoKeyPair> = {};
const keySource: KeySource = { keyFor: (device) => pairs[device]?.publicKey };

beforeAll(async () => {
  for (const id of IDS) pairs[id] = (await generateDeviceKeys()).signing;
});

const judgeFor = (me: string): JudgeOptions => ({
  appId: APP,
  dataSet: SET,
  keys: keySource,
  ownDevice: me,
  allowFinalDelete: () => true,
});

async function signed(replica: Replica): Promise<Replica> {
  const key = (pairs[replica.device] as CryptoKeyPair).privateKey;
  return insertSignatures(replica, await signOwnChanges(APP, key, replica, SET));
}

const json = (m: unknown): unknown => JSON.parse(JSON.stringify(m));

interface Side {
  session: Session;
  replica: Replica;
  out: unknown[];
}

/** One whole exchange; `options` says, per device, what its sessions pass (the approval hook). */
async function exchange(
  x: Replica,
  y: Replica,
  options: Partial<Record<string, SessionOptions>> = {},
) {
  const open = async (replica: Replica): Promise<Side> => {
    const own = await signed(replica);
    const step = startSession(own);
    return { session: step.session, replica: step.replica, out: step.send.map(json) };
  };
  const a = await open(x);
  const b = await open(y);
  for (let round = 0; round < 50 && (a.out.length > 0 || b.out.length > 0); round += 1) {
    for (const [from, to] of [
      [a, b],
      [b, a],
    ] as const) {
      for (const message of from.out.splice(0)) {
        const step = await receiveJudged(
          to.session,
          to.replica,
          message,
          judgeFor(to.replica.device),
          options[to.replica.device] ?? {},
        );
        to.session = step.session;
        to.replica = step.replica;
        to.out.push(...step.send.map(json));
      }
    }
  }
  return { x: a.replica, y: b.replica, sx: a.session, sy: b.session };
}

const holdFrom =
  (device: string) =>
  (c: Change): ApprovalDecision =>
    c.device === device ? 'hold' : 'apply';

describe('full stack with approval', () => {
  it('holds what a device sends, claims nothing of it, and takes it after the approval', async () => {
    let a = emptyReplica('a');
    for (let i = 0; i < 6; i += 1) a = written(a, `a${i}`, { title: `from a ${i}` });
    let b = emptyReplica('b');
    b = written(b, 'b0', { title: 'from b' });
    const options = { b: { approval: { hook: holdFrom('a') } } };
    const first = await exchange(a, b, options);
    // b holds a's six changes; its own went through to a
    expect(first.sx.refusal).toBeUndefined();
    expect(first.sy.refusal).toBeUndefined();
    expect(first.y.vector).toEqual({ b: 1 });
    expect(pendingApproval(first.y)).toHaveLength(6);
    expect(first.sy.approvals).toEqual({ held: 6, rejected: 0, dropped: 0 });
    expect(first.x.vector).toEqual({ a: 6, b: 1 });
    expect(fingerprint(first.x)).not.toBe(fingerprint(first.y));
    // the outcome says why: nothing was cut (complete), the fingerprints differ, b holds six changes.
    // A device that sees `held > 0` decides and compares again instead of repeating the session.
    expect(outcome(first.sy, first.y)).toMatchObject({ complete: true, equal: false, held: 6 });
    expect(outcome(first.sx, first.x)).toMatchObject({ complete: true, equal: false, held: 0 });
    // the stand b sends next time still says a: nothing
    expect(startSession(first.y).send[0]).toMatchObject({ t: 'stand', vector: { b: 1 } });

    // a second meeting does not ask again and does not duplicate
    const again = await exchange(first.x, first.y, options);
    expect(pendingApproval(again.y)).toHaveLength(6);
    expect(again.sy.approvals?.held).toBe(0);
    // still held, still unequal, still complete: a second session did not change that
    expect(outcome(again.sy, again.y)).toMatchObject({ complete: true, equal: false, held: 6 });

    // the state survives storage, and approving needs nothing from a
    const stored = readApprovalState(json(again.y.approval));
    expect(stored.ok).toBe(true);
    if (!stored.ok) return;
    const restored: Replica = { ...again.y, approval: stored.state };
    const approved = approve(restored, pendingApproval(restored));
    expect(approved.replica.vector).toEqual({ a: 6, b: 1 });
    const final = await exchange(first.x, approved.replica, options);
    expect(final.sy.refusal).toBeUndefined();
    expect(fingerprint(final.x)).toBe(fingerprint(final.y));
    expect(pendingApproval(final.y)).toEqual([]);
    expect(outcome(final.sy, final.y)).toMatchObject({ complete: true, equal: true, held: 0 });
  });

  it('a rejected change blocks nobody: later numbers apply, no peer refuses, the rejecter does not forward it', async () => {
    let a = emptyReplica('a');
    for (let i = 0; i < 3; i += 1) a = written(a, `a${i}`, { title: `from a ${i}` });
    const options = { b: { approval: { hook: holdFrom('a') } } };
    let b = (await exchange(a, emptyReplica('b'), options)).y;
    expect(pendingApproval(b)).toHaveLength(3);
    b = approve(b, [{ device: 'a', seq: 1 }]).replica;
    b = reject(b, [{ device: 'a', seq: 2 }]).replica;
    b = approve(b, [{ device: 'a', seq: 3 }]).replica;
    expect(b.vector).toEqual({ a: 3 });
    expect(findRecord(b, COL, 'a1')).toBeUndefined();
    expect(findRecord(b, COL, 'a2')).toBeDefined();
    expect(b.log[1]?.kind).toBe('redacted');

    // a third device meets b: it gets number 1, is not refused, and is told nothing was left out wrongly
    const viaB = await exchange(b, emptyReplica('c'));
    expect(viaB.sx.refusal).toBeUndefined();
    expect(viaB.sy.refusal).toBeUndefined();
    expect(viaB.y.vector).toEqual({ a: 1 });
    expect(viaB.sx.withheld).toBe(2);
    expect(findRecord(viaB.y, COL, 'a0')).toBeDefined();

    // c then meets a and gets everything there is, including what b rejected
    const direct = await exchange(a, viaB.y);
    expect(direct.sy.refusal).toBeUndefined();
    expect(fingerprint(direct.x)).toBe(fingerprint(direct.y));
    expect(findRecord(direct.y, COL, 'a1')).toBeDefined();
    // b decided differently from c; they are not forced to agree, and the exchange says so, no refusal
    const bc = await exchange(b, direct.y);
    expect(bc.sx.refusal).toBeUndefined();
    expect(bc.sy.refusal).toBeUndefined();
    expect(fingerprint(bc.x)).not.toBe(fingerprint(bc.y));
  });

  it('a final deletion with its erased changes is held as a group and applied together', async () => {
    let a = emptyReplica('a');
    a = written(a, 'r1', { v: 1 });
    a = written(a, 'r1', { v: 2 });
    a = removed(a, COL, 'r1');
    a = written(a, 'r2', { v: 'keep' });
    const hook = (c: Change): ApprovalDecision => (c.kind === 'delete' ? 'hold' : 'apply');
    const options = { b: { approval: { hook } } };
    const first = await exchange(a, emptyReplica('b'), options);
    expect(first.sy.refusal).toBeUndefined();
    // the two erased changes and the deletion wait together; the later write waits behind them
    expect(pendingApproval(first.y).map((c) => c.kind)).toEqual(['redacted', 'redacted', 'delete']);
    expect(first.y.vector).toEqual({});
    const deletion = pendingApproval(first.y).find((c) => c.kind === 'delete') as Change;
    const approved = approve(first.y, [{ device: deletion.device, seq: deletion.seq }]).replica;
    expect(approved.vector).toEqual({ a: 3 });
    expect(findRecord(approved, COL, 'r1')?.deleted).toBe(true);
    const final = await exchange(a, approved, options);
    expect(final.sy.refusal).toBeUndefined();
    expect(fingerprint(final.x)).toBe(fingerprint(final.y));
    // the deletion cannot be rejected: it stays held until it is approved
    const kept = reject(first.y, [{ device: deletion.device, seq: deletion.seq }]).replica;
    expect(pendingApproval(kept)).toHaveLength(3);
  });

  it('without the option a session is what it was: nothing held, no state', async () => {
    let a = emptyReplica('a');
    a = written(a, 'a0', { title: 'x' });
    const run = await exchange(a, emptyReplica('b'));
    expect(run.y.approval).toBeUndefined();
    expect(run.sy.approvals).toBeUndefined();
    expect(fingerprint(run.x)).toBe(fingerprint(run.y));
    expect(merge(run.y, []).replica.approval).toBeUndefined();
  });
});
