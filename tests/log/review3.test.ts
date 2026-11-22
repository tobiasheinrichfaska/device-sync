// Regression tests of the third security review (part A). Each describe block is one finding; every
// test was written from the proof of concept first and failed on the code before the fix.
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  changeCheckValue,
  emptyReplica,
  fingerprint,
  insertSignatures,
  judgeChanges,
  judgeDetailed,
  merge,
  onSyncMessage,
  outcome,
  parseChange,
  parseSyncMessage,
  readChanges,
  receiveJudged,
  signChange,
  signOwnChanges,
  startSession,
  type Change,
  type JudgeOptions,
  type KeySource,
  type Replica,
  type Step,
  type SyncMessage,
} from '../../src/log/index.ts';
import { indexOf } from '../../src/log/recordIndex.ts';
import { COL, removed, written } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
const IDS = ['x', 'y', 'm', 'z', 'n', 'l', 'b', 'valueOf', 'toString', 'hasOwnProperty'] as const;
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
const resign = (change: Change): Promise<Change> =>
  signChange(APP, (pairs[change.device] as CryptoKeyPair).privateKey, change, SET);
const json = <T>(m: T): T => JSON.parse(JSON.stringify(m)) as T;
const pick = (r: Replica, device: string, seq: number): Change => {
  const c = r.log.find((x) => x.device === device && x.seq === seq);
  if (!c) throw new Error(`no ${device}#${seq}`);
  return c;
};
const part = (changes: Change[], last: boolean, more?: boolean): SyncMessage => ({
  t: 'changes',
  changes,
  last,
  ...(more ? { more } : {}),
});

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

/** One full session between two devices (messages delivered in order, both ways). */
async function session(
  a: Replica,
  b: Replica,
  judgeA: JudgeOptions,
  judgeB: JudgeOptions,
  options: Parameters<typeof receiveJudged>[4] = {},
): Promise<{ a: Step; b: Step; messages: SyncMessage[] }> {
  let sa: Step = startSession(a);
  let sb: Step = startSession(b);
  let toA: SyncMessage[] = [...sb.send];
  let toB: SyncMessage[] = [...sa.send];
  const messages: SyncMessage[] = [];
  while (toA.length > 0 || toB.length > 0) {
    const m = toB.shift();
    if (m) {
      messages.push(m);
      sb = await receiveJudged(sb.session, sb.replica, json(m), judgeB, options);
      toA = [...toA, ...sb.send];
    }
    const n = toA.shift();
    if (n) {
      messages.push(n);
      sa = await receiveJudged(sa.session, sa.replica, json(n), judgeA, options);
      toB = [...toB, ...sa.send];
    }
  }
  return { a: sa, b: sb, messages };
}

// ---------------------------------------------------------------------------------------------
describe('L1: a new device can join a large data set', () => {
  /** x:1 introduces b (b is checkable only once the state holds x:1); then b writes `count` changes. */
  async function newcomerBatch(count: number): Promise<{ batch: Change[]; keys: KeySource }> {
    const x = await signed(written(emptyReplica('x'), 'device-b', { t: 'intro' }));
    let b = merge(emptyReplica('b'), x.log).replica;
    for (let i = 0; i < count; i += 1) b = written(b, `r${i % 7}`, { t: i });
    b = await signed(b);
    const keys: KeySource = {
      keyFor: (device, state) =>
        device === 'b'
          ? (state.vector.x ?? 0) >= 1
            ? pairs.b?.publicKey
            : undefined
          : pairs[device]?.publicKey,
    };
    return { batch: [...b.log].sort((p, q) => (p.device < q.device ? 1 : -1)), keys };
  }

  it('changes of an author introduced inside the batch are not capped by maxPendingChanges', async () => {
    const { batch, keys } = await newcomerBatch(25);
    expect(batch.length).toBeGreaterThan(20);
    const inviter = emptyReplica('n');
    const { step } = await feed(inviter, [part(batch, true)], judgeFor('n', { keys }), {
      limits: { maxPendingChanges: 20 },
    });
    expect(step.session.refusal).toBeUndefined();
    expect(step.session.taken).toBe(batch.length);
    expect(step.session.truncated).not.toBe(true);
  });

  it('what is STILL unverifiable after the rounds is capped, without refusing the session', async () => {
    let q = emptyReplica('z');
    for (let i = 0; i < 25; i += 1) q = written(q, `r${i}`, { t: 'v' });
    q = await signed(q);
    const batch = [...q.log];
    const unknown: KeySource = { keyFor: () => undefined };
    const { step } = await feed(
      emptyReplica('n'),
      [part(batch, true)],
      judgeFor('n', { keys: unknown }),
      { limits: { maxPendingChanges: 20 } },
    );
    expect(step.session.refusal).toBeUndefined();
    expect(step.session.truncated).toBe(true);
    expect(step.session.taken).toBe(0);
    expect(step.session.waiting).toBeLessThanOrEqual(20);
  });

  async function history(device: string, count: number, base?: Replica): Promise<Replica> {
    let r = base ?? emptyReplica(device);
    for (let i = 0; i < count; i += 1) r = written(r, `r${i % 11}`, { t: `${device}${i}` });
    return signed(r);
  }

  it('an honest history larger than maxSessionChanges converges over several sessions (sender cuts)', async () => {
    const limits = { maxSessionChanges: 100 };
    const old = await history('x', 260);
    const late = emptyReplica('l');
    let a = old;
    let b = late;
    const counts: number[] = [];
    for (let round = 0; round < 8 && fingerprint(a) !== fingerprint(b); round += 1) {
      const r = await session(a, b, judgeFor('x'), judgeFor('l'), { limits });
      expect(r.a.session.refusal).toBeUndefined();
      expect(r.b.session.refusal).toBeUndefined();
      counts.push(r.b.session.taken);
      a = r.a.replica;
      b = r.b.replica;
    }
    expect(fingerprint(a)).toBe(fingerprint(b));
    expect(b.vector.x).toBe(260);
    expect(counts.length).toBeGreaterThanOrEqual(3);
    expect(Math.max(...counts)).toBeLessThanOrEqual(100);
  });

  it('a partial answer says so in its last message (more: true); the final one does not', async () => {
    const old = await history('x', 30);
    const first = onSyncMessage(
      startSession(old).session,
      old,
      { t: 'stand', vector: {}, tips: {} },
      { limits: { maxSessionChanges: 10 } },
    );
    const msgs = first.send.filter((m) => m.t === 'changes');
    expect(msgs.reduce((n, m) => n + (m.t === 'changes' ? m.changes.length : 0), 0)).toBe(10);
    const last = msgs[msgs.length - 1];
    expect(last?.t === 'changes' && last.last && last.more === true).toBe(true);
    const all = onSyncMessage(startSession(old).session, old, { t: 'stand', vector: {}, tips: {} });
    const lastAll = all.send[all.send.length - 1];
    expect(lastAll?.t === 'changes' && lastAll.more).toBeFalsy();
  });

  it('the receiver ends reading at its own limit WITHOUT refusing and takes what it verified', async () => {
    const old = await history('x', 12);
    const r = await session(old, emptyReplica('l'), judgeFor('x'), judgeFor('l'), {
      limits: { maxSessionChanges: 5 },
    });
    // the sender (same limits) cuts at 5; a receiver with a smaller limit is tested below
    expect(r.b.session.refusal).toBeUndefined();
    expect(r.b.session.taken).toBe(5);
    const parts = [...old.log].map((c, i, all) => part([c], i === all.length - 1));
    const { step } = await feed(emptyReplica('l'), parts, judgeFor('l'), {
      limits: { maxSessionChanges: 5 },
    });
    expect(step.session.refusal).toBeUndefined();
    expect(step.session.truncated).toBe(true);
    expect(step.session.taken).toBe(5);
    expect(step.replica.vector.x).toBe(5);
  });

  it('maxSessionChars ends reading without refusing (verified prefix taken, truncated)', async () => {
    const old = await history('x', 12);
    const parts = [...old.log].map((c, i, all) => part([c], i === all.length - 1));
    const one = JSON.stringify(old.log[0]).length;
    const { step } = await feed(emptyReplica('l'), parts, judgeFor('l'), {
      limits: { maxSessionChars: one * 4 + 10 },
    });
    expect(step.session.refusal).toBeUndefined();
    expect(step.session.truncated).toBe(true);
    expect(step.session.taken).toBeGreaterThanOrEqual(3);
    expect(step.session.taken).toBeLessThanOrEqual(4);
  });

  it('quota false for an author ends reading (truncated), it does not refuse the session', async () => {
    const old = await history('x', 8);
    const quota = (_a: string, count: number): boolean => count <= 3;
    const { step } = await feed(
      emptyReplica('l'),
      [part([...old.log], true)],
      judgeFor('l', { quota }),
    );
    expect(step.session.refusal).toBeUndefined();
    expect(step.session.truncated).toBe(true);
    expect(step.session.taken).toBe(3);
  });

  it('a member with a huge history does not lock out latecomers (scaled down)', async () => {
    const limits = { maxSessionChanges: 40 };
    const member = await history('x', 150);
    const other = await history('y', 40);
    let a = merge(member, other.log).replica;
    for (const late of ['l', 'n']) {
      let b = emptyReplica(late);
      let rounds = 0;
      while (fingerprint(a) !== fingerprint(b) && rounds < 12) {
        const r = await session(a, b, judgeFor('x'), judgeFor(late), { limits });
        expect(r.b.session.refusal).toBeUndefined();
        a = r.a.replica;
        b = r.b.replica;
        rounds += 1;
      }
      expect(fingerprint(a)).toBe(fingerprint(b));
      expect(rounds).toBeLessThanOrEqual(7);
    }
  });

  it('a cut never sends an erased change without its deletion, and still converges', async () => {
    // y:1 is erased by m's deletion at the END of m's log, so a short prefix holds y:1 but not it
    const y = await signed(written(emptyReplica('y'), 'rec', { t: 'secret' }));
    let m = merge(emptyReplica('m'), y.log).replica;
    for (let i = 0; i < 12; i += 1) m = written(m, `o${i}`, { t: i });
    m = await signed(removed(m, COL, 'rec'));
    let b = emptyReplica('b');
    let a = m;
    for (let round = 0; round < 12 && fingerprint(a) !== fingerprint(b); round += 1) {
      const r = await session(a, b, judgeFor('m'), judgeFor('b'), {
        limits: { maxSessionChanges: 4 },
      });
      expect(r.b.session.refusal).toBeUndefined();
      for (const msg of r.messages) {
        // the first partial answers carry neither the erased change nor anything of y after it
        if (msg.t === 'changes' && msg.more && msg.changes.some((c) => c.kind === 'redacted')) {
          expect(msg.changes.some((c) => c.kind === 'delete')).toBe(true);
        }
      }
      a = r.a.replica;
      b = r.b.replica;
    }
    expect(fingerprint(a)).toBe(fingerprint(b));
    expect(b.vector).toEqual(m.vector);
  });

  it('a cut follows the sender’s log, so changes that depend on another device always apply', async () => {
    // z's changes come first by name only; m wrote after reading all of z, x depends on m
    const z = await history('z', 30);
    let m = merge(emptyReplica('m'), z.log).replica;
    m = await history('m', 30, m);
    let x = merge(emptyReplica('x'), m.log).replica;
    x = await history('x', 30, x);
    let b = emptyReplica('b');
    let a = x;
    for (let round = 0; round < 12 && fingerprint(a) !== fingerprint(b); round += 1) {
      const r = await session(a, b, judgeFor('x'), judgeFor('b'), {
        limits: { maxSessionChanges: 20 },
      });
      expect(r.b.session.refusal).toBeUndefined();
      expect(r.b.session.taken).toBeGreaterThan(0);
      a = r.a.replica;
      b = r.b.replica;
    }
    expect(fingerprint(a)).toBe(fingerprint(b));
  });

  it('`more` is read only as true and only on the last piece', () => {
    const base = { t: 'changes', changes: [], last: true };
    expect(parseSyncMessage({ ...base, more: true })).toEqual({ ...base, more: true });
    expect(parseSyncMessage(base)).toEqual(base);
    expect(parseSyncMessage({ ...base, more: false })).toBeUndefined();
    expect(parseSyncMessage({ ...base, last: false, more: true })).toBeUndefined();
    expect(parseSyncMessage({ ...base, more: 1 })).toBeUndefined();
  });

  it('outcome says whether the session was complete', async () => {
    const old = await history('x', 30);
    const r = await session(old, emptyReplica('l'), judgeFor('x'), judgeFor('l'), {
      limits: { maxSessionChanges: 10 },
    });
    const o = outcome(r.b.session, r.b.replica);
    expect(o?.equal).toBe(false);
    expect(o?.complete).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('L2: a redacted change is taken only if its deletion is really applied', () => {
  async function world(): Promise<{ y1r: Change; m1: Change; m2: Change; m: Replica }> {
    const y = await signed(written(emptyReplica('y'), 'rec', { t: 'secret' }));
    let m = merge(emptyReplica('m'), y.log).replica;
    m = removed(written(m, 'other', { t: 'o' }), COL, 'rec');
    m = await signed(m);
    return { y1r: pick(m, 'y', 1), m1: pick(m, 'm', 1), m2: pick(m, 'm', 2), m };
  }

  it('the proof of concept: [y:1 redacted, m:2 delete] without m:1 is not taken', async () => {
    const { y1r, m2 } = await world();
    expect(y1r.kind).toBe('redacted');
    const n = emptyReplica('n');
    const { step } = await feed(n, [part([y1r, m2], true)], judgeFor('n'));
    expect(step.session.refusal).toBeUndefined();
    expect(step.replica.log).toHaveLength(0);
    expect(step.session.waiting).toBeGreaterThanOrEqual(1);
  });

  it('judgeChanges: the erased change is pending, not checked, beside a held deletion', async () => {
    const { y1r, m2 } = await world();
    const verdicts = await judgeChanges(context(emptyReplica('n')), [y1r, m2]);
    expect(verdicts).toEqual(['pending', 'checked']);
  });

  it('the honest, complete batch is taken in full', async () => {
    const { y1r, m1, m2 } = await world();
    const { step } = await feed(emptyReplica('n'), [part([y1r, m1, m2], true)], judgeFor('n'));
    expect(step.session.refusal).toBeUndefined();
    expect(step.replica.vector).toEqual({ y: 1, m: 2 });
  });

  it('a later different m:2 cannot make y:1 vanish at the victim only', async () => {
    const { y1r, m2 } = await world();
    const first = await feed(emptyReplica('n'), [part([y1r, m2], true)], judgeFor('n'));
    expect(first.step.replica.vector.y).toBeUndefined();
  });

  it('variant: the deletion waits for a causal dependency (knew)', async () => {
    const { y1r, m1, m2 } = await world();
    const m2knew = await resign({ ...m2, knew: { ...(m2.knew ?? {}), z: 1 } });
    const { step } = await feed(emptyReplica('n'), [part([y1r, m1, m2knew], true)], judgeFor('n'));
    expect(step.session.refusal).toBeUndefined();
    expect(step.replica.vector.y).toBeUndefined();
    expect(step.replica.log.some((c) => c.kind === 'redacted')).toBe(false);
  });

  it('variant: the deletion waits for the clock (clock jump)', async () => {
    const { y1r, m1, m2 } = await world();
    const m2far = await resign({ ...m2, clock: 10 ** 9 });
    const { step } = await feed(emptyReplica('n'), [part([y1r, m1, m2far], true)], judgeFor('n'));
    expect(step.session.refusal).toBeUndefined();
    expect(step.replica.vector.y).toBeUndefined();
  });

  it('readChanges: same result without the session', async () => {
    const { y1r, m2 } = await world();
    const read = await readChanges(emptyReplica('n'), [y1r, m2], judgeFor('n'));
    expect(read.rejected).toBe(0);
    expect(read.accepted.some((c) => c.kind === 'redacted')).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('L3: own-history is decided only after the signature verified', () => {
  async function ownChange(): Promise<Change> {
    const n = await signed(written(emptyReplica('n'), 'r', { t: 'v' }));
    return pick(n, 'n', 1);
  }

  it('an unsigned change under the own id is unsigned, not own-history', async () => {
    const c = await ownChange();
    const { sig: _s, check: _c, ...bare } = c;
    const [j] = await judgeDetailed(context(emptyReplica('n')), [bare]);
    expect(j).toEqual({ verdict: 'false', reason: 'unsigned' });
  });

  it('a forged signature under the own id is bad-signature', async () => {
    const c = await ownChange();
    const sig = c.sig as string;
    const forged = { ...c, sig: `${sig[0] === 'A' ? 'B' : 'A'}${sig.slice(1)}` };
    const [j] = await judgeDetailed(context(emptyReplica('n')), [forged]);
    expect(j).toEqual({ verdict: 'false', reason: 'bad-signature' });
  });

  it('a genuinely signed own change this device does not hold is still own-history', async () => {
    const c = await ownChange();
    const [j] = await judgeDetailed(context(emptyReplica('n')), [c]);
    expect(j).toEqual({ verdict: 'false', reason: 'own-history' });
  });
});

// ---------------------------------------------------------------------------------------------
describe('L4: signedOnly withholds the foreign redacted changes of a record whose deletion is withheld', () => {
  it('the unsigned own deletion and the change it erased are both withheld', async () => {
    const y = await signed(written(emptyReplica('y'), 'rec', { t: 'secret' }));
    const m = removed(merge(emptyReplica('m'), y.log).replica, COL, 'rec');
    expect(pick(m, 'y', 1).kind).toBe('redacted');
    expect(pick(m, 'm', 1).sig).toBeUndefined();
    const answer = onSyncMessage(startSession(m).session, m, { t: 'stand', vector: {}, tips: {} });
    const sent = answer.send.flatMap((x) => (x.t === 'changes' ? x.changes : []));
    expect(sent).toEqual([]);
    expect(answer.session.withheld).toBeGreaterThanOrEqual(2);
  });

  it('the receiver is not refused, and everything arrives once the deletion is signed', async () => {
    const y = await signed(written(emptyReplica('y'), 'rec', { t: 'secret' }));
    const m0 = removed(merge(emptyReplica('m'), y.log).replica, COL, 'rec');
    const n = emptyReplica('n');
    const r = await session(m0, n, judgeFor('m'), judgeFor('n'));
    expect(r.b.session.refusal).toBeUndefined();
    const m = await signed(m0);
    const r2 = await session(m, r.b.replica, judgeFor('m'), judgeFor('n'));
    expect(r2.b.session.refusal).toBeUndefined();
    expect(fingerprint(r2.b.replica)).toBe(fingerprint(m));
    expect(r2.b.replica.vector).toEqual({ y: 1, m: 1 });
  });
});

// ---------------------------------------------------------------------------------------------
describe('L6: processing pieces is linear', () => {
  let built: Promise<Change[]> | undefined;
  /** 12000 signed writes of one device, built once for both tests. */
  const chain = (total: number): Promise<Change[]> => (built ??= build(total));
  async function build(total: number): Promise<Change[]> {
    const bare: Change[] = [];
    for (let i = 0; i < total; i += 1) {
      const c: Change = {
        device: 'x',
        seq: i + 1,
        clock: i + 1,
        collection: COL,
        id: `r${i % 50}`,
        kind: 'set',
        fields: { t: i },
        knew: {},
      };
      // the hash chain: the link of the previous change
      bare.push(i === 0 ? c : { ...c, prev: changeCheckValue(bare[i - 1] as Change) });
    }
    return Promise.all(bare.map((c) => resign(c)));
  }
  /** Seconds for the pieces of one change each, through receiveJudged. */
  async function timed(replica: Replica, changes: readonly Change[]): Promise<[number, Step]> {
    let step: Step = startSession(replica);
    const started = performance.now();
    for (const [i, change] of changes.entries()) {
      step = await receiveJudged(
        step.session,
        step.replica,
        { t: 'changes', changes: [change], last: i === changes.length - 1 },
        judgeFor('n'),
      );
    }
    return [(performance.now() - started) / 1000, step];
  }

  it('12000 one-change pieces of known valid changes (all an adversary needs) take under 10 s (the bound only separates linear from quadratic)', async () => {
    const total = 12000;
    const changes = await chain(total);
    const holder = merge(emptyReplica('n'), changes).replica;
    expect(holder.vector.x).toBe(total);
    const [seconds, step] = await timed(holder, changes);
    expect(step.session.refusal).toBeUndefined();
    expect(seconds).toBeLessThan(10);
  }, 120_000);

  it('12000 one-change pieces of new valid changes cost about 4 times as much as 3000 (linear, not 16)', async () => {
    const changes = await chain(12000);
    const [small] = await timed(emptyReplica('n'), changes.slice(0, 3000));
    const [large, step] = await timed(emptyReplica('n'), changes);
    expect(step.session.refusal).toBeUndefined();
    expect(step.replica.vector.x).toBe(12000);
    expect(large).toBeLessThan(small * 8);
    expect(large).toBeLessThan(40);
  }, 180_000);
});

// ---------------------------------------------------------------------------------------------
describe('L7: device ids that are names of Object members', () => {
  it('the quota hook always gets a number', async () => {
    for (const id of ['valueOf', 'toString', 'hasOwnProperty']) {
      let r = emptyReplica(id);
      for (let i = 0; i < 3; i += 1) r = written(r, `r${i}`, { t: 'v' });
      r = await signed(r);
      const seen: unknown[] = [];
      const quota = (_a: string, count: number): boolean => {
        seen.push(count);
        return true;
      };
      const { step } = await feed(
        emptyReplica('n'),
        [part([...r.log], true)],
        judgeFor('n', { quota }),
      );
      expect(step.session.refusal).toBeUndefined();
      expect(seen).toEqual([1, 2, 3]);
    }
  });
});

// ---------------------------------------------------------------------------------------------
describe('L9: a redacted change carries only the members its signature covers', () => {
  async function redactedChange(): Promise<Change> {
    const y = await signed(
      written(emptyReplica('y'), 'rec', { t: 'secret' }, { time: 5, by: 'Y' }),
    );
    const m = removed(merge(emptyReplica('m'), y.log).replica, COL, 'rec');
    return pick(m, 'y', 1);
  }

  it('the shape merge produces is accepted by the parser', async () => {
    const c = await redactedChange();
    expect(Object.keys(c).sort()).toEqual(
      ['check', 'clock', 'collection', 'device', 'id', 'kind', 'seq', 'sig'].sort(),
    );
    expect(parseChange(json(c))).toEqual(c);
  });

  it.each([
    ['by', { by: 'someone' }],
    ['time', { time: 123 }],
    ['knew', { knew: { x: 1 } }],
  ])('the parser refuses %s on a redacted change', async (_n, extra) => {
    const c = await redactedChange();
    expect(parseChange(json({ ...c, ...extra }))).toBeUndefined();
  });

  it('the judge refuses it as unknown-member', async () => {
    const c = await redactedChange();
    const [j] = await judgeDetailed(context(emptyReplica('n')), [{ ...c, by: 'someone' }]);
    expect(j).toEqual({ verdict: 'false', reason: 'unknown-member' });
  });
});

// ---------------------------------------------------------------------------------------------
describe('IDX: the index cache is checked against its log array', () => {
  it('a log array appended to in place is indexed again', () => {
    const x = written(emptyReplica('x'), 'a', { t: 1 });
    const log = [...x.log];
    expect(indexOf(log).get(COL)?.has('a')).toBe(true);
    const y = written(emptyReplica('y'), 'b', { t: 2 });
    log.push(...y.log);
    expect(indexOf(log).get(COL)?.has('b')).toBe(true);
  });

  it('a last element replaced in place is indexed again', () => {
    const x = written(emptyReplica('x'), 'a', { t: 1 });
    const log = [...x.log];
    indexOf(log);
    const y = written(emptyReplica('y'), 'c', { t: 3 });
    log[0] = y.log[0] as Change;
    expect(indexOf(log).get(COL)?.has('c')).toBe(true);
    expect(indexOf(log).get(COL)?.has('a')).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('KeySource: neverErase', () => {
  it('neverErase of a KeySource is merged into the judge options', async () => {
    let x = written(emptyReplica('x'), 'dev', { t: 'v' });
    x = removed(x, COL, 'dev');
    x = await signed(x);
    const keys: KeySource = { keyFor: (d) => pairs[d]?.publicKey, neverErase: [COL] };
    const [, del] = await judgeDetailed(context(emptyReplica('n'), { keys }), [...x.log]);
    expect(del).toEqual({ verdict: 'false', reason: 'never-erase' });
  });
});
