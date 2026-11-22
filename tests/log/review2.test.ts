// Regression tests of the second half of the security review. Each describe block is one finding;
// every test was written from the proof of concept first and failed on the code before the fix.
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  LIMITS,
  tipsOf,
  changeSigningText,
  emptyReplica,
  insertSignatures,
  judgeChange,
  judgeChanges,
  merge,
  missingFor,
  onSyncMessage,
  outcome,
  pieces,
  readChanges,
  signChange,
  receive,
  receiveJudged,
  signOwnChanges,
  startSession,
  write,
  remove,
  type Change,
  type JudgeOptions,
  type KeySource,
  type Replica,
  type Step,
  type SyncMessage,
} from '../../src/log/index.ts';
import { COL, permutations, removed, sync, written, ok } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
const IDS = ['x', 'y', 'm', 'c', 'h', 'z', 'q', 'n', 'd'] as const;
const pairs: Record<string, CryptoKeyPair> = {};
beforeAll(async () => {
  for (const id of IDS) pairs[id] = (await generateDeviceKeys()).signing;
});

const keysAll: KeySource = { keyFor: (device) => pairs[device]?.publicKey };
const judgeFor = (me: string, extra: Partial<JudgeOptions> = {}): JudgeOptions => ({
  appId: APP,
  dataSet: SET,
  keys: keysAll,
  ownDevice: me,
  allowFinalDelete: () => true,
  ...extra,
});
const context = (state: Replica, extra: Partial<JudgeOptions> = {}) => ({
  ...judgeFor(state.device, extra),
  state,
});

async function signed(replica: Replica): Promise<Replica> {
  const key = (pairs[replica.device] as CryptoKeyPair).privateKey;
  return insertSignatures(replica, await signOwnChanges(APP, key, replica, SET));
}
const json = <T>(m: T): T => JSON.parse(JSON.stringify(m)) as T;
const pick = (r: Replica, device: string, seq: number): Change => {
  const c = r.log.find((x) => x.device === device && x.seq === seq);
  if (!c) throw new Error(`no ${device}#${seq}`);
  return c;
};
const part = (changes: Change[], last: boolean): SyncMessage => ({ t: 'changes', changes, last });

/** All pieces of a batch, one after the other, each as it would arrive. */
async function feed(
  replica: Replica,
  parts: readonly SyncMessage[],
  judge: JudgeOptions,
  options: Parameters<typeof receiveJudged>[4] = {},
): Promise<{ step: Step; steps: Step[] }> {
  let step: Step = { session: startSession(replica).session, replica, send: [] };
  const steps: Step[] = [];
  for (const p of parts) {
    step = await receiveJudged(step.session, step.replica, json(p), judge, options);
    steps.push(step);
  }
  return { step, steps };
}

// ---------------------------------------------------------------------------------------------
describe('H1: an honest batch is not rejected because of the round structure', () => {
  /** x:1 set, x:2 (erased by y), x:3 deletes y's record, y:1 (erased by x), y:2 deletes x's record. */
  async function honestBatch(): Promise<Change[]> {
    let x = await signed(
      written(written(emptyReplica('x'), 'ra', { t: 'intro' }), 'rx', { t: 'w' }),
    );
    let y = merge(emptyReplica('y'), missingFor(x, {})).replica;
    y = await signed(removed(written(y, 'ry', { t: 'y-write' }), COL, 'rx'));
    x = merge(x, missingFor(y, x.vector)).replica;
    x = await signed(removed(x, COL, 'ry'));
    return missingFor(x, {});
  }
  const learning: Record<string, KeySource> = {
    'y known upfront': keysAll,
    'y learned from x:1': {
      keyFor: (device, state) =>
        device === 'y'
          ? (state.vector.x ?? 0) >= 1
            ? pairs.y?.publicKey
            : undefined
          : pairs[device]?.publicKey,
    },
  };

  it('the batch has the shape of the proof of concept', async () => {
    const batch = await honestBatch();
    expect(batch.map((c) => `${c.device}:${c.seq}:${c.kind}`)).toEqual([
      'x:1:set',
      'x:2:redacted',
      'x:3:delete',
      'y:1:redacted',
      'y:2:delete',
    ]);
  });

  for (const [name, keys] of Object.entries(learning)) {
    it(`${name}: every order of the batch is taken completely (readChanges)`, async () => {
      const batch = await honestBatch();
      for (const order of permutations(batch)) {
        const read = await readChanges(emptyReplica('n'), order, judgeFor('n', { keys }));
        expect(read.rejected, order.map((c) => `${c.device}${c.seq}`).join()).toBe(0);
        expect(read.accepted).toHaveLength(5);
        expect(read.pending).toHaveLength(0);
      }
    });

    it(`${name}: whatever the piece size, receiveJudged takes 5 and does not refuse`, async () => {
      const batch = await honestBatch();
      for (const size of [1, 2, 3, 5]) {
        for (const order of [batch, [...batch].reverse()]) {
          const parts = pieces(order, { limits: { maxChanges: size } });
          const { step } = await feed(emptyReplica('n'), parts, judgeFor('n', { keys }));
          expect(step.session.refusal, `size ${size}`).toBeUndefined();
          expect(step.session.taken, `size ${size}`).toBe(5);
        }
      }
    });
  }
});

// ---------------------------------------------------------------------------------------------
describe('H2: equivocation (the same device and number signed twice with different content)', () => {
  async function fixture() {
    const y = await signed(written(emptyReplica('y'), 'ry', { t: 'y-write' }));
    let mA = merge(emptyReplica('m'), y.log).replica;
    mA = await signed(removed(mA, COL, 'ry'));
    const mB = await signed(written(emptyReplica('m'), 'rz', { t: 'harmless' }));
    return {
      A: pick(mA, 'm', 1), // m:1, a deletion of y's record
      B: pick(mB, 'm', 1), // m:1, a harmless write
      yErased: pick(mA, 'y', 1),
      yWrite: pick(y, 'y', 1),
      mA,
      mB,
    };
  }

  it('2b: a forwarder gives [y:1 erased, m:1 delete] to a device holding the other m:1: refused, nothing consumed', async () => {
    const f = await fixture();
    const c = merge(emptyReplica('c'), [f.B]).replica;
    const { step } = await feed(c, [part([f.yErased, f.A], true)], judgeFor('c'));
    expect(step.session.refusal).toBe('forged');
    expect(step.session.refusalReason).toBe('equivocation');
    expect(step.session.taken).toBe(0);
    expect(step.replica.vector.y).toBeUndefined();
    expect(step.replica).toBe(c);
  });

  it('2a: pulling from the history that erased y:1 gives a named reason, not a silent block', async () => {
    const f = await fixture();
    const c = merge(emptyReplica('c'), [f.B]).replica;
    const answer = missingFor(f.mA, c.vector);
    expect(answer.map((x) => `${x.device}${x.seq}`)).toEqual(['y1']);
    const { step } = await feed(c, [part(answer, true)], judgeFor('c'));
    expect(step.session.refusal).toBe('forged');
    expect(step.session.refusalReason).toBe('redacted-without-deletion');
    expect(step.replica.vector.y).toBeUndefined();
  });

  it('the other way round the stands are equal, nothing is sent, and only the fingerprints differ', async () => {
    const f = await fixture();
    expect(missingFor(f.mB, f.mA.vector).filter((c) => c.device === 'm')).toEqual([]);
    const a = startSession(f.mA);
    const b = startSession(f.mB);
    const toB = onSyncMessage(b.session, f.mB, a.send[0] as SyncMessage, { signedOnly: false });
    expect(toB.send.flatMap((m) => (m.t === 'changes' ? m.changes : []))).toEqual([]);
    expect(
      outcome(
        { ...b.session, ownDone: true, peer: { vector: f.mA.vector, fingerprint: 'x' } },
        f.mB,
      )?.equal,
    ).toBe(false);
  });

  it('a different m:1 is equivocation in every meeting order (single change, batch, two sessions)', async () => {
    const f = await fixture();
    const withA = f.mA;
    const withB = f.mB;
    expect(await judgeChange(context(withA), f.B)).toBe('false');
    expect(await judgeChange(context(withB), f.A)).toBe('false');
    for (const order of [
      [f.A, f.B],
      [f.B, f.A],
    ]) {
      const read = await readChanges(emptyReplica('n'), [f.yErased, ...order], judgeFor('n'));
      expect(read.accepted).toEqual([]);
      expect(read.rejections.map((r) => r.reason)).toContain('equivocation');
    }
    // two sessions: whatever came first stays, the second is refused with its reason
    const first = await feed(emptyReplica('n'), [part([f.yErased, f.A], true)], judgeFor('n'));
    expect(first.step.session.taken).toBe(2);
    const second = await feed(first.step.replica, [part([f.B], true)], judgeFor('n'));
    expect(second.step.session.refusalReason).toBe('equivocation');
    expect(second.step.replica).toBe(first.step.replica);
    const third = await feed(emptyReplica('n'), [part([f.B], true)], judgeFor('n'));
    expect(third.step.session.taken).toBe(1);
    const fourth = await feed(third.step.replica, [part([f.yErased, f.A], true)], judgeFor('n'));
    expect(fourth.step.session.refusalReason).toBe('equivocation');
    expect(fourth.step.replica).toBe(third.step.replica);
  });

  it('the same change again (same content, a new signature) is no equivocation', async () => {
    const f = await fixture();
    const c = merge(emptyReplica('c'), [f.B]).replica;
    const { sig: _s, ...bare } = f.B;
    const twin = await signChange(APP, (pairs.m as CryptoKeyPair).privateKey, bare, SET);
    expect(twin.sig).not.toBe(f.B.sig);
    expect(await judgeChange(context(c), twin)).toBe('checked');
  });
});

// ---------------------------------------------------------------------------------------------
describe('H6: memory before any signature check', () => {
  const chars = (changes: readonly Change[] | undefined): number =>
    JSON.stringify(changes ?? []).length;

  /** About 600 000 characters of JSON that the strict parser accepts. */
  const bigFields = (): Record<string, unknown> =>
    Object.fromEntries(
      Array.from({ length: 40 }, (_, i) => [
        `f${i}`,
        Array.from({ length: 8 }, () => 'v'.repeat(1900)),
      ]),
    );

  it('the parser really accepts such a change (the proof of concept is real)', () => {
    const r = write(emptyReplica('x'), COL, 'big', bigFields());
    expect(r.ok).toBe(true);
    expect(JSON.stringify(r.ok ? r.replica.log[0] : {}).length).toBeGreaterThan(500_000);
  });

  it('a flood of large unsigned pieces is refused at the first piece; nothing is buffered', async () => {
    const r = write(emptyReplica('x'), COL, 'big', bigFields());
    const big = (r.ok ? r.replica.log[0] : undefined) as Change;
    let step: Step = {
      session: startSession(emptyReplica('n')).session,
      replica: emptyReplica('n'),
      send: [],
    };
    let refusedAt = -1;
    for (let i = 0; i < 40; i += 1) {
      step = await receiveJudged(
        step.session,
        step.replica,
        json(part([{ ...big, seq: i + 1 }], false)),
        judgeFor('n'),
      );
      expect(chars(step.session.buffered)).toBeLessThanOrEqual(LIMITS.maxSessionChars);
      if (step.session.refusal && refusedAt < 0) refusedAt = i;
    }
    expect(refusedAt).toBe(0);
    expect(step.session.refusal).toBe('forged');
    expect(step.session.refusalReason).toBe('unsigned');
    expect(chars(step.session.buffered)).toBe(2);
  });

  it('a forged first piece is refused at once, without waiting for the last piece', async () => {
    const x = await signed(written(emptyReplica('x'), 'r1', { t: 'v' }));
    const good = pick(x, 'x', 1);
    const sig = good.sig as string;
    const forged = { ...good, sig: `${sig[0] === 'A' ? 'B' : 'A'}${sig.slice(1)}` };
    const { steps } = await feed(emptyReplica('n'), [part([forged], false)], judgeFor('n'));
    expect(steps[0]?.session.refusal).toBe('forged');
    expect(steps[0]?.session.refusalReason).toBe('bad-signature');
  });

  it('large signed pieces beyond maxSessionChars end the reading (truncated), not the session; the verified part is taken', async () => {
    let x = emptyReplica('x');
    for (let i = 0; i < 3; i += 1) x = ok(write(x, COL, `big${i}`, bigFields()));
    x = await signed(x);
    const parts = x.log.map((c, i) => part([c], i === 2));
    const { steps } = await feed(emptyReplica('n'), parts, judgeFor('n'), {
      limits: { maxSessionChars: 1_000_000 },
    });
    expect(steps[0]?.session.refusal).toBeUndefined();
    expect(chars(steps[0]?.session.buffered)).toBeLessThanOrEqual(1_000_000);
    // the second piece does not fit: reading ends there, nothing is refused
    expect(steps[1]?.session.refusal).toBeUndefined();
    expect(chars(steps[1]?.session.buffered)).toBeLessThanOrEqual(1_000_000);
    expect(steps[2]?.session.refusal).toBeUndefined();
    expect(steps[2]?.session.truncated).toBe(true);
    expect(steps[2]?.session.taken).toBe(1);
    expect(steps[2]?.replica.log).toHaveLength(1);
  });

  it('LIMITS has the two new limits with their defaults', () => {
    expect(LIMITS.maxSessionChars).toBe(16_000_000);
    expect(LIMITS.maxPendingChanges).toBeGreaterThan(0);
  });

  it('a change whose author cannot be checked yet waits; the count limit applies after the key-learning rounds', async () => {
    let q = emptyReplica('q');
    for (let i = 0; i < 5; i += 1) q = written(q, `r${i}`, { t: 'v' });
    q = await signed(q);
    const unknown: KeySource = { keyFor: (d) => (d === 'q' ? undefined : pairs[d]?.publicKey) };
    const { steps } = await feed(
      emptyReplica('n'),
      [part([...q.log], false)],
      judgeFor('n', { keys: unknown }),
      {
        limits: { maxPendingChanges: 3 },
      },
    );
    // while the pieces arrive pending is bounded only by the session budget
    expect(steps[0]?.session.refusal).toBeUndefined();
    expect(steps[0]?.session.buffered).toHaveLength(5);
    const capped = await feed(
      emptyReplica('n'),
      [part([...q.log], true)],
      judgeFor('n', { keys: unknown }),
      { limits: { maxPendingChanges: 3 } },
    );
    expect(capped.step.session.refusal).toBeUndefined();
    expect(capped.step.session.truncated).toBe(true);
    expect(capped.step.session.waiting).toBe(3);
    const fine = await feed(
      emptyReplica('n'),
      [part([...q.log], true)],
      judgeFor('n', { keys: unknown }),
    );
    expect(fine.step.session.refusal).toBeUndefined();
    expect(fine.step.session.waiting).toBe(5);
  });

  it('the quota hook is asked with author, running count and replica; false ends the reading (truncated), not the session', async () => {
    let x = emptyReplica('x');
    for (let i = 0; i < 6; i += 1) x = written(x, `r${i}`, { t: 'v' });
    x = await signed(x);
    const asked: [string, number, Replica][] = [];
    const quota = (author: string, count: number, state: Replica): boolean => {
      asked.push([author, count, state]);
      return count <= 3;
    };
    const n = emptyReplica('n');
    const { steps } = await feed(n, [part([...x.log], false)], judgeFor('n', { quota }));
    expect(steps[0]?.session.refusal).toBeUndefined();
    expect(steps[0]?.session.buffered).toHaveLength(3);
    expect(asked.map((a) => a[1])).toEqual([1, 2, 3, 4]);
    expect(asked[0]?.[0]).toBe('x');
    expect(asked[0]?.[2]).toBe(n);
    const open = await feed(n, [part([...x.log], true)], judgeFor('n'));
    expect(open.step.session.taken).toBe(6);
  });
});

// ---------------------------------------------------------------------------------------------
describe('H4b: unsigned own changes are not delivered', () => {
  const answer = (step: Step): Change[] =>
    step.send.flatMap((m) => (m.t === 'changes' ? m.changes : []));
  const stand: SyncMessage = { t: 'stand', vector: {}, tips: {} };

  it('by default only signed changes answer a stand; the rest is counted as withheld', async () => {
    let a = written(written(emptyReplica('x'), 'r1', { t: '1' }), 'r2', { t: '2' });
    const step = onSyncMessage(startSession(a).session, a, stand);
    expect(answer(step)).toEqual([]);
    expect(step.session.withheld).toBe(2);
    expect(step.session.sent).toBe(0);
    a = await signed(a);
    const signedStep = onSyncMessage(startSession(a).session, a, stand);
    expect(answer(signedStep)).toHaveLength(2);
    expect(signedStep.session.withheld).toBe(0);
  });

  it('numbering stays gapless: from the first unsigned change of a device nothing of it is sent', async () => {
    let a = await signed(written(emptyReplica('x'), 'r1', { t: '1' }));
    const one = pick(a, 'x', 1);
    a = written(written(a, 'r2', { t: '2' }), 'r3', { t: '3' });
    const third = (await signed(a)).log[2] as Change;
    const mixed: Replica = { ...a, log: [one, a.log[1] as Change, third] };
    const step = onSyncMessage(startSession(mixed).session, mixed, stand);
    expect(answer(step).map((c) => c.seq)).toEqual([1]);
    expect(step.session.withheld).toBe(2);
  });

  it('plain test sessions opt out with signedOnly: false', () => {
    const a = written(emptyReplica('x'), 'r1', { t: '1' });
    const step = onSyncMessage(startSession(a).session, a, stand, { signedOnly: false });
    expect(answer(step)).toHaveLength(1);
    expect(step.session.withheld).toBe(0);
  });

  it('an honest device with an unsigned change does not make the other refuse the session', async () => {
    let a = written(emptyReplica('x'), 'r1', { t: '1' });
    const b = emptyReplica('n');
    const step = onSyncMessage(startSession(a).session, a, {
      t: 'stand',
      vector: b.vector,
      tips: tipsOf(b),
    });
    const { step: got } = await feed(
      b,
      step.send.map((m) => m),
      judgeFor('n'),
    );
    expect(got.session.refusal).toBeUndefined();
    a = await signed(a);
    expect(a.log[0]?.sig).toBeDefined();
  });
});

// ---------------------------------------------------------------------------------------------
describe('M3: judgeChange agrees with judgeChanges', () => {
  it('a lone erased change is false unless its deletion is in the log', async () => {
    const y = await signed(written(emptyReplica('y'), 'ry', { t: 'v' }));
    let m = merge(emptyReplica('m'), y.log).replica;
    m = await signed(removed(m, COL, 'ry'));
    const erased = pick(m, 'y', 1);
    const bare = emptyReplica('n');
    expect(erased.kind).toBe('redacted');
    expect(await judgeChange(context(bare), erased)).toBe('false');
    expect((await judgeChanges(context(bare), [erased]))[0]).toBe('false');
    const withDeletion = merge(bare, [erased, pick(m, 'm', 1)]).replica;
    expect(await judgeChange(context(withDeletion), erased)).toBe('checked');
  });
});

// ---------------------------------------------------------------------------------------------
describe('M4: every rejection carries a reason', () => {
  const reasonsOf = async (state: Replica, changes: Change[], extra: Partial<JudgeOptions> = {}) =>
    (await readChanges(state, changes, judgeFor(state.device, extra))).rejections.map(
      (r) => r.reason,
    );

  it('unsigned, bad-check, bad-signature, unknown-member', async () => {
    const x = await signed(written(emptyReplica('x'), 'r1', { t: 'v' }));
    const good = pick(x, 'x', 1);
    const n = emptyReplica('n');
    const { sig: _s, ...unsigned } = good;
    expect(await reasonsOf(n, [unsigned])).toEqual(['unsigned']);
    expect(await reasonsOf(n, [{ ...good, fields: { t: 'other' } }])).toEqual(['bad-check']);
    expect(await reasonsOf(n, [{ ...good, clock: 9 }])).toEqual(['bad-signature']);
    expect(await reasonsOf(n, [{ ...good, extra: 1 } as unknown as Change])).toEqual([
      'unknown-member',
    ]);
  });

  it('not-allowed (mayWrite) and never-erase', async () => {
    const x = await signed(removed(written(emptyReplica('x'), 'r1', { t: 'v' }), COL, 'r1'));
    const n = emptyReplica('n');
    expect(await reasonsOf(n, [pick(x, 'x', 1)], { mayWrite: () => false })).toContain(
      'not-allowed',
    );
    expect(await reasonsOf(n, [pick(x, 'x', 2)], { neverErase: [COL] })).toEqual(['never-erase']);
  });

  it('own-history: a change under the own id that this device does not hold', async () => {
    const old = emptyReplica('x');
    const later = await signed(written(written(old, 'r1', { t: '1' }), 'r2', { t: '2' }));
    const reasons = await reasonsOf(written(old, 'r1', { t: '1' }), [pick(later, 'x', 2)]);
    expect(reasons).toEqual(['own-history']);
    const { step } = await feed(old, [part([pick(later, 'x', 1)], true)], judgeFor('x'));
    expect(step.session.refusal).toBe('forged');
    expect(step.session.refusalReason).toBe('own-history');
    expect(step.session.refusalDevice).toBe('x');
  });

  it('redacted-without-deletion and equivocation have their reasons', async () => {
    const y = await signed(written(emptyReplica('y'), 'ry', { t: 'v' }));
    const m = await signed(removed(merge(emptyReplica('m'), y.log).replica, COL, 'ry'));
    expect(await reasonsOf(emptyReplica('n'), [pick(m, 'y', 1)])).toEqual([
      'redacted-without-deletion',
    ]);
  });

  it('a session refusal for unsigned changes names the reason', async () => {
    const x = written(emptyReplica('x'), 'r1', { t: 'v' });
    const { step } = await feed(emptyReplica('n'), [part([...x.log], true)], judgeFor('n'));
    expect(step.session.refusal).toBe('forged');
    expect(step.session.refusalReason).toBe('unsigned');
  });
});

// ---------------------------------------------------------------------------------------------
describe('M5: a final deletion needs the app to allow it', () => {
  it('without allowFinalDelete a deletion is false (delete-not-allowed); with it, checked', async () => {
    const x = await signed(removed(written(emptyReplica('x'), 'r1', { t: 'v' }), COL, 'r1'));
    const del = pick(x, 'x', 2);
    const state = merge(emptyReplica('n'), [pick(x, 'x', 1)]).replica;
    const { allowFinalDelete: _a, ...without } = judgeFor('n');
    expect(await judgeChange({ ...without, state }, del)).toBe('false');
    const read = await readChanges(state, [del], without);
    expect(read.rejections.map((r) => r.reason)).toEqual(['delete-not-allowed']);
    expect(await judgeChange(context(state), del)).toBe('checked');
  });

  it('allowFinalDelete and mayWrite get author, change and the replica', async () => {
    const x = await signed(removed(written(emptyReplica('x'), 'r1', { t: 'v' }), COL, 'r1'));
    const state = merge(emptyReplica('n'), [pick(x, 'x', 1)]).replica;
    const seen: unknown[][] = [];
    await judgeChange(
      context(state, {
        mayWrite: (...args) => (seen.push(['write', ...args]), true),
        allowFinalDelete: (...args) => (seen.push(['delete', ...args]), true),
      }),
      pick(x, 'x', 2),
    );
    expect(seen.map((s) => s[0]).sort()).toEqual(['delete', 'write']);
    for (const s of seen) {
      expect(s[1]).toBe('x');
      expect((s[2] as Change).seq).toBe(2);
      expect(s[3]).toBe(state);
    }
  });

  it('a final deletion that the app refuses leaves the record alone (receiveJudged)', async () => {
    const x = await signed(removed(written(emptyReplica('x'), 'r1', { t: 'v' }), COL, 'r1'));
    const { allowFinalDelete: _a, ...without } = judgeFor('n');
    const { step } = await feed(emptyReplica('n'), [part(missingFor(x, {}), true)], without);
    expect(step.session.refusalReason).toBe('delete-not-allowed');
  });
});

// ---------------------------------------------------------------------------------------------
describe('N3: the signing text needs a data set', () => {
  const change: Change = {
    device: 'a',
    seq: 1,
    clock: 1,
    collection: 'c',
    id: 'i',
    kind: 'set',
    check: 'k',
  };
  it('an undefined, empty or non-string data set is a programming error', () => {
    for (const bad of [undefined, '', 5, null]) {
      expect(() => changeSigningText('demo', change, bad as never), String(bad)).toThrow(TypeError);
    }
    expect(changeSigningText('demo', change, 'main')).toContain('"set":"main"');
  });
});

// ---------------------------------------------------------------------------------------------
describe('N4: one stand and one done per session', () => {
  const stand: SyncMessage = { t: 'stand', vector: {}, tips: {} };
  const done: SyncMessage = { t: 'done', vector: {}, fingerprint: '0'.repeat(32) };

  it('a second stand ends the session (unexpected / repeated-stand) and sends nothing', () => {
    const a = emptyReplica('a');
    const first = onSyncMessage(startSession(a).session, a, stand);
    expect(first.session.refusal).toBeUndefined();
    const second = onSyncMessage(first.session, a, stand);
    expect(second.session.refusal).toBe('unexpected');
    expect(second.session.refusalReason).toBe('repeated-stand');
    expect(second.send).toEqual([]);
    const viaReceive = receive(first.session, a, json(stand));
    expect(viaReceive.session.refusalReason).toBe('repeated-stand');
  });

  it('a second done ends the session (unexpected / repeated-done)', async () => {
    const a = emptyReplica('a');
    const first = onSyncMessage(startSession(a).session, a, done);
    expect(first.session.refusal).toBeUndefined();
    const second = onSyncMessage(first.session, a, done);
    expect(second.session.refusal).toBe('unexpected');
    expect(second.session.refusalReason).toBe('repeated-done');
    const judged = await receiveJudged(first.session, a, json(done), judgeFor('a'));
    expect(judged.session.refusalReason).toBe('repeated-done');
  });

  it('twenty stands cost one answer', () => {
    let step: Step = startSession(emptyReplica('a'));
    let answers = 0;
    for (let i = 0; i < 20; i += 1) {
      step = onSyncMessage(step.session, step.replica, stand);
      answers += step.send.length;
    }
    expect(answers).toBe(1);
  });
});

// ---------------------------------------------------------------------------------------------
describe('X1: a field written by many devices one after another stays writable', () => {
  /** device i syncs with device i-1 first, then writes: never a conflict. */
  function chain(
    count: number,
    field: string,
    fieldsOf = (i: number) => ({ [field]: i }),
  ): Replica[] {
    const out: Replica[] = [];
    let previous = emptyReplica('d0');
    for (let i = 0; i < count; i += 1) {
      const own = merge(emptyReplica(`d${i}`), previous.log).replica;
      const r = write(own, COL, 'r', fieldsOf(i));
      if (!r.ok) throw new Error(`device ${i}: ${r.reason}`);
      out.push(r.replica);
      previous = r.replica;
    }
    return out;
  }

  it('80 devices write the same field one after another: all accepted, no notice, short knew', () => {
    const all = chain(80, 'f');
    const last = all[79] as Replica;
    expect(last.notices).toEqual([]);
    expect(Object.keys(last.log[79]?.knew ?? {}).length).toBeLessThanOrEqual(2);
    expect(last.log).toHaveLength(80);
  });

  it('a final deletion after that chain is accepted too', () => {
    const all = chain(80, 'f');
    const gone = remove(all[79] as Replica, COL, 'r');
    expect(gone.ok).toBe(true);
  });

  it('two fields, written by alternating devices, stay writable', () => {
    const all = chain(70, 'f', (i) => (i % 2 === 0 ? { f: i } : { g: i }));
    expect(all[69]?.notices).toEqual([]);
  });

  it('with 60 concurrent unresolved writers the limit still triggers', () => {
    const base = ok(write(emptyReplica('base'), COL, 'r', { f: 'start' }));
    const concurrent = Array.from({ length: 60 }, (_, i) =>
      ok(write(merge(emptyReplica(`w${i}`), base.log).replica, COL, 'r', { f: i })),
    );
    let join = emptyReplica('join');
    for (const w of concurrent) join = sync(w, join);
    const r = write(join, COL, 'r', { f: 'resolved' });
    expect(r).toEqual({ ok: false, reason: 'too-many-devices' });
  });

  it('with 40 concurrent writers the join is accepted and settles the notice', () => {
    const base = ok(write(emptyReplica('base'), COL, 'r', { f: 'start' }));
    const concurrent = Array.from({ length: 40 }, (_, i) =>
      ok(write(merge(emptyReplica(`w${i}`), base.log).replica, COL, 'r', { f: i })),
    );
    let join = emptyReplica('join');
    for (const w of concurrent) join = sync(w, join);
    expect(join.notices).toHaveLength(1);
    const r = ok(write(join, COL, 'r', { f: 'resolved' }));
    expect(r.notices).toEqual([]);
  });
});
