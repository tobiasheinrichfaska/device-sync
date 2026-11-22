// Regression tests of the fourth security review (log layer). Each was written from the reviewer's
// proof of concept first and fails on the code before the fix.
//   F2  more than 50 devices in a version vector ended all synchronisation
//   F3  a partial session could repeat itself for ever (a budget that cut every applicable change)
//   F4  a number signed twice that differs only in the head stayed invisible
//   F5  tips are unproven claims: neutral reason, and the one proof (`proveEquivocation`)
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  LIMITS,
  changeAt,
  changeLink,
  emptyReplica,
  fingerprint,
  insertSignatures,
  judgeDetailed,
  merge,
  onSyncMessage,
  parseSyncMessage,
  proveEquivocation,
  receive,
  receiveJudged,
  remove,
  signChange,
  signOwnChanges,
  startSession,
  tipConflict,
  tipsOf,
  write,
  type Change,
  type JudgeOptions,
  type KeySource,
  type Limits,
  type Replica,
  type Step,
  type SyncMessage,
} from '../../src/log/index.ts';
import { COL, ok, prng } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
const NAMES = ['e', 'm', 'h', 'k', 'a', 'b', 'c', 'q'] as const;
const pairs: Record<string, CryptoKeyPair> = {};
beforeAll(async () => {
  for (const id of NAMES) pairs[id] = (await generateDeviceKeys()).signing;
}, 60_000);

const keys: KeySource = { keyFor: (device) => pairs[device]?.publicKey };
const judgeFor = (me: string, extra: Partial<JudgeOptions> = {}): JudgeOptions => ({
  appId: APP,
  dataSet: SET,
  keys,
  ownDevice: me,
  allowFinalDelete: () => true,
  ...extra,
});
async function signed(replica: Replica): Promise<Replica> {
  const key = (pairs[replica.device] as CryptoKeyPair).privateKey;
  return insertSignatures(replica, await signOwnChanges(APP, key, replica, SET));
}
const resign = (change: Change): Promise<Change> =>
  signChange(APP, (pairs[change.device] as CryptoKeyPair).privateKey, change, SET);
const json = <T>(m: T): T => JSON.parse(JSON.stringify(m)) as T;
const at = (r: Replica, device: string, seq: number): Change => {
  const c = r.log.find((x) => x.device === device && x.seq === seq);
  if (!c) throw new Error(`no ${device}#${seq}`);
  return c;
};
const put = (r: Replica, id: string, fields: Record<string, unknown>): Replica =>
  ok(write(r, COL, id, fields, {}));

/** A whole judged session between two devices, messages delivered in order, both ways. */
async function session(
  a: Replica,
  b: Replica,
  judgeA: JudgeOptions,
  judgeB: JudgeOptions,
  limits?: Partial<Limits>,
): Promise<{ a: Step; b: Step }> {
  const options = limits ? { limits } : {};
  let sa: Step = startSession(a);
  let sb: Step = startSession(b);
  let toA: SyncMessage[] = [...sb.send];
  let toB: SyncMessage[] = [...sa.send];
  for (let guard = 0; guard < 2000 && (toA.length > 0 || toB.length > 0); guard += 1) {
    const m = toB.shift();
    if (m) {
      sb = await receiveJudged(sb.session, sb.replica, json(m), judgeB, options);
      toA = [...toA, ...sb.send];
    }
    const n = toA.shift();
    if (n) {
      sa = await receiveJudged(sa.session, sa.replica, json(n), judgeA, options);
      toB = [...toB, ...sa.send];
    }
  }
  return { a: sa, b: sb };
}

/** The same without judging (plain `receive`, nothing signed), for sessions that only move data. */
function plainSession(a: Replica, b: Replica): { a: Step; b: Step } {
  const options = { signedOnly: false };
  let sa: Step = startSession(a);
  let sb: Step = startSession(b);
  let toA: SyncMessage[] = [...sb.send];
  let toB: SyncMessage[] = [...sa.send];
  for (let guard = 0; guard < 2000 && (toA.length > 0 || toB.length > 0); guard += 1) {
    const m = toB.shift();
    if (m) {
      sb = receive(sb.session, sb.replica, json(m), options);
      toA = [...toA, ...sb.send];
    }
    const n = toA.shift();
    if (n) {
      sa = receive(sa.session, sa.replica, json(n), options);
      toB = [...toB, ...sa.send];
    }
  }
  return { a: sa, b: sb };
}

// ---------------------------------------------------------------------------------------------
describe('F2: a version vector of more than 50 devices does not end synchronisation', () => {
  /** `count` devices each wrote one note; one replica holds them all. */
  function crowd(count: number): Replica {
    let all = emptyReplica('hub');
    for (let i = 0; i < count; i += 1) {
      const one = put(emptyReplica(`d${i}`), `n${i}`, { t: i });
      all = merge(all, one.log).replica;
    }
    return all;
  }

  for (const count of [51, 60, 2000]) {
    it(`${count} devices in the vector: sessions go on in both directions, also for new honest changes`, () => {
      const hub = crowd(count);
      expect(Object.keys(hub.vector)).toHaveLength(count);
      let other = emptyReplica('other');
      const first = plainSession(hub, other);
      for (const side of [first.a, first.b]) {
        expect(side.session.refusal).toBeUndefined();
        expect(side.session.truncated).toBeUndefined();
      }
      expect(first.a.session.peer).toBeDefined();
      expect(fingerprint(first.b.replica)).toBe(fingerprint(hub));
      other = put(first.b.replica, 'mine', { t: 'new' });
      const second = plainSession(first.a.replica, other);
      expect(second.a.session.refusal).toBeUndefined();
      expect(second.b.session.refusal).toBeUndefined();
      expect(fingerprint(second.a.replica)).toBe(fingerprint(other));
      // and the other way: the hub writes, the 'other' (whose own stand is now large) takes it
      const hub2 = put(second.a.replica, 'again', { t: 2 });
      const third = plainSession(hub2, second.b.replica);
      expect(fingerprint(third.b.replica)).toBe(fingerprint(hub2));
      const done = third.a.session;
      expect(done.peer?.fingerprint).toBe(fingerprint(hub2));
    }, 60_000);
  }

  it('the full stack with signatures: 55 devices that each wrote and signed a note', async () => {
    const devices = await Promise.all(
      Array.from({ length: 55 }, async (_, i) => ({
        id: `s${i}`,
        pair: (await generateDeviceKeys()).signing,
      })),
    );
    const map = new Map(devices.map((d) => [d.id, d.pair]));
    const source: KeySource = { keyFor: (device) => map.get(device)?.publicKey };
    let a = emptyReplica('hub');
    for (const d of devices) {
      let r = put(emptyReplica(d.id), `n-${d.id}`, { t: d.id });
      r = insertSignatures(r, await signOwnChanges(APP, d.pair.privateKey, r, SET));
      a = merge(a, r.log).replica;
    }
    const judge = (me: string): JudgeOptions => ({
      appId: APP,
      dataSet: SET,
      keys: source,
      ownDevice: me,
    });
    const b = emptyReplica('fresh');
    const out = await session(a, b, judge('hub'), judge('fresh'));
    expect(out.b.session.refusal).toBeUndefined();
    expect(out.a.session.refusal).toBeUndefined();
    expect(fingerprint(out.b.replica)).toBe(fingerprint(a));
  }, 60_000);

  it('a stand over the receiver limit ends the session gracefully (truncated), it is not a refusal', () => {
    const tight = { limits: { maxStandDevices: 5 } };
    const big = crowd(8);
    const receiver = emptyReplica('r');
    const step = receive(
      startSession(receiver).session,
      receiver,
      json(startSession(big).send[0]),
      {
        ...tight,
        signedOnly: false,
      },
    );
    expect(step.session.refusal).toBeUndefined();
    expect(step.session.truncated).toBe(true);
    expect(step.session.limit).toBe('stand-devices');
    expect(step.send).toEqual([]);
    // exactly at the limit it is read
    const atLimit = receive(
      startSession(receiver).session,
      receiver,
      json(startSession(crowd(5)).send[0]),
      tight,
    );
    expect(atLimit.session.truncated).toBeUndefined();
    expect(atLimit.send.length).toBeGreaterThan(0);
    // a done over the limit ends it the same way
    const overDone = receive(
      startSession(receiver).session,
      receiver,
      { t: 'done', vector: big.vector, fingerprint: '0'.repeat(32) },
      tight,
    );
    expect(overDone.session.refusal).toBeUndefined();
    expect(overDone.session.truncated).toBe(true);
  });

  it('a hostile stand with 300000 devices costs bounded work (not read at all)', () => {
    const vector = Object.fromEntries(Array.from({ length: 300_000 }, (_, i) => [`d${i}`, 1]));
    const receiver = emptyReplica('r');
    const started = performance.now();
    const step = receive(startSession(receiver).session, receiver, {
      t: 'stand',
      vector,
      tips: {},
    });
    expect(performance.now() - started).toBeLessThan(5000);
    expect(step.session.refusal).toBeUndefined();
    expect(step.session.truncated).toBe(true);
    expect(parseSyncMessage({ t: 'stand', vector, tips: {} })).toEqual({
      t: 'overflow',
      of: 'stand',
    });
  });

  it('the message size still bounds a stand: one over maxMessageChars is too large as well', () => {
    const many = crowd(200);
    const stand = json(startSession(many).send[0]);
    expect(parseSyncMessage(stand)).toMatchObject({ t: 'stand' });
    expect(parseSyncMessage(stand, { limits: { maxMessageChars: 1000 } })).toEqual({
      t: 'overflow',
      of: 'stand',
    });
  });
});

// ---------------------------------------------------------------------------------------------
describe('F3: a partial session always makes progress', () => {
  /** A field value of about 15950 JSON characters (the largest the limits allow per field). */
  const wide = (tag: string): unknown[] =>
    Array.from({ length: 8 }, (_, i) => `${tag}${i}`.padEnd(1990, 'x'));
  /** A change of about 558000 characters: 35 fields of the largest value. */
  const bigFields = (tag: string): Record<string, unknown> =>
    Object.fromEntries(Array.from({ length: 35 }, (_, i) => [`f${i}`, wide(`${tag}-${i}-`)]));

  /** E writes the record `victim`, then `count` big changes, then deletes `victim` for good. */
  async function history(count: number, fields: (i: number) => Record<string, unknown>) {
    let e = put(emptyReplica('e'), 'victim', { secret: 'x' });
    for (let i = 0; i < count; i += 1) e = put(e, `big${i}`, fields(i));
    e = ok(remove(e, COL, 'victim', {}));
    return signed(e);
  }

  it('the proof of concept with the default limits: 32 big changes (17.9 million characters), then the deletion', async () => {
    const e = await history(32, (i) => bigFields(`c${i}`));
    const chars = e.log.reduce((sum, c) => sum + JSON.stringify(c).length, 0);
    expect(chars).toBeGreaterThan(LIMITS.maxSessionChars);
    const holder = merge(emptyReplica('h'), e.log).replica;
    let fresh = emptyReplica('k');
    let sessions = 0;
    let first: Step | undefined;
    for (; sessions < 4 && fresh.vector.e !== 34; sessions += 1) {
      const out = await session(holder, fresh, judgeFor('h'), judgeFor('k'));
      expect(out.a.session.refusal).toBeUndefined();
      expect(out.b.session.refusal).toBeUndefined();
      first ??= out.a;
      fresh = out.b.replica;
    }
    // the group travelled whole in the first session, although it is larger than the budget
    expect(first?.session.sent).toBeGreaterThan(0);
    expect(fresh.vector.e).toBe(34);
    expect(fingerprint(fresh)).toBe(fingerprint(holder));
    expect(sessions).toBeLessThanOrEqual(2);
  }, 120_000);

  it('the answer to a stand holds at least one applicable group, never 0 changes with `more`', async () => {
    const e = await history(6, (i) => ({ t: 'y'.repeat(1900), i }));
    const tight = {
      limits: { maxSessionChars: 1500, maxSessionChanges: 2, maxGroupChars: 500_000 },
    };
    const step = onSyncMessage(
      startSession(e).session,
      e,
      { t: 'stand', vector: {}, tips: {} },
      tight,
    );
    const sent = step.send.flatMap((m) => (m.t === 'changes' ? m.changes : []));
    expect(sent.length).toBeGreaterThan(0);
    // the erased change travels only together with its deletion, and the numbering is gapless
    expect(sent.map((c) => c.seq)).toEqual(sent.map((_, i) => i + 1));
    expect(sent.some((c) => c.kind === 'redacted')).toBe(sent.some((c) => c.kind === 'delete'));
    for (const c of sent) {
      if (c.kind === 'redacted') expect(sent.some((d) => d.kind === 'delete')).toBe(true);
    }
  });

  it('an honest history with a large record followed by its deletion, with scaled-down limits', async () => {
    const e = await history(5, (i) => ({ t: 'z'.repeat(1900), i }));
    const limits: Partial<Limits> = {
      maxSessionChanges: 3,
      maxSessionChars: 2500,
      maxGroupChanges: 100,
      maxGroupChars: 200_000,
      pieceBytes: 3000,
    };
    const holder = merge(emptyReplica('h'), e.log).replica;
    let fresh = emptyReplica('k');
    for (let i = 0; i < 6 && fresh.vector.e !== 7; i += 1) {
      const out = await session(holder, fresh, judgeFor('h'), judgeFor('k'), limits);
      expect(out.a.session.refusal).toBeUndefined();
      expect(out.b.session.refusal).toBeUndefined();
      fresh = out.b.replica;
    }
    expect(fresh.vector.e).toBe(7);
    expect(fingerprint(fresh)).toBe(fingerprint(holder));
  }, 60_000);

  it('a change that depends on something the budget cut away is not sent without it', async () => {
    // e writes, m (knowing e:1) writes: with a budget of one change the answer must not hold m:1 alone
    const e = await signed(put(emptyReplica('e'), 'r', { t: 'one' }));
    const m = await signed(put(merge(emptyReplica('m'), e.log).replica, 'r2', { t: 'two' }));
    const both = merge(e, m.log).replica;
    expect(at(both, 'm', 1).knew).toMatchObject({});
    const step = onSyncMessage(
      startSession(both).session,
      both,
      { t: 'stand', vector: {}, tips: {} },
      { limits: { maxSessionChanges: 1 } },
    );
    const sent = step.send.flatMap((x) => (x.t === 'changes' ? x.changes : []));
    expect(sent.length).toBeGreaterThan(0);
    for (const c of sent) {
      for (const [d, n] of Object.entries(c.knew ?? {})) {
        expect(sent.some((x) => x.device === d && x.seq >= n)).toBe(true);
      }
    }
  });

  it('property: random histories with big changes and deletions, random small budgets: every session sequence converges', async () => {
    const devices = ['a', 'b', 'c'];
    let runs = 0;
    let withErasure = 0;
    let sessions = 0;
    for (let run = 0; run < 150; run += 1) {
      const rnd = prng(31_000 + run);
      const reps = new Map(devices.map((d) => [d, emptyReplica(d)]));
      const steps = 5 + Math.floor(rnd() * 12);
      for (let s = 0; s < steps; s += 1) {
        const d = devices[Math.floor(rnd() * devices.length)] as string;
        let r = reps.get(d) as Replica;
        if (rnd() < 0.3) {
          const other = reps.get(devices[Math.floor(rnd() * devices.length)] as string) as Replica;
          r = merge(r, other.log).replica;
        }
        const rec = `r${Math.floor(rnd() * 3)}`;
        const roll = rnd();
        if (roll < 0.62) {
          const size = rnd() < 0.4 ? 1500 + Math.floor(rnd() * 400) : 40;
          const out = write(r, COL, rec, { t: 'q'.repeat(size), n: Math.floor(rnd() * 9) }, {});
          if (out.ok) r = out.replica;
        } else if (roll < 0.8) {
          const out = remove(r, COL, rec, {});
          if (out.ok) r = out.replica;
        }
        reps.set(d, await signed(r));
      }
      const limits: Partial<Limits> = {
        maxSessionChanges: 1 + Math.floor(rnd() * 4),
        maxSessionChars: 400 + Math.floor(rnd() * 3000),
        maxGroupChanges: 1000,
        maxGroupChars: 400_000,
        pieceBytes: 1500 + Math.floor(rnd() * 3000),
      };
      if ([...reps.values()].some((r) => r.log.some((c) => c.kind === 'redacted')))
        withErasure += 1;
      let converged = false;
      for (let round = 0; round < 30 && !converged; round += 1) {
        const x = devices[round % 3] as string;
        const y = devices[(round + 1 + (round % 2)) % 3] as string;
        if (x === y) continue;
        const out = await session(
          reps.get(x) as Replica,
          reps.get(y) as Replica,
          judgeFor(x),
          judgeFor(y),
          limits,
        );
        sessions += 1;
        expect(out.a.session.refusal, `run ${run} round ${round}`).toBeUndefined();
        expect(out.b.session.refusal, `run ${run} round ${round}`).toBeUndefined();
        reps.set(x, out.a.replica);
        reps.set(y, out.b.replica);
        const prints = new Set([...reps.values()].map(fingerprint));
        const vectors = new Set(
          [...reps.values()].map((r) => JSON.stringify(Object.entries(r.vector).sort())),
        );
        converged = prints.size === 1 && vectors.size === 1;
      }
      expect(converged, `run ${run}: budgets ${JSON.stringify(limits)}`).toBe(true);
      runs += 1;
    }
    process.stderr.write(
      `\nF3 property: ${runs} runs, ${withErasure} with erased changes, ${sessions} sessions, all converged\n`,
    );
    expect(withErasure).toBeGreaterThan(30);
  }, 180_000);
});

// ---------------------------------------------------------------------------------------------
describe('F4: a number signed twice that differs only in the head is seen at the first stand', () => {
  /** m signs m:1 twice with the same content, once for record alice and once for bob. */
  async function twoHeads(): Promise<{ va: Replica; vb: Replica }> {
    const base = emptyReplica('m');
    const va = await signed(put(base, 'alice', { amount: 100 }));
    const vb = await signed(put(base, 'bob', { amount: 100 }));
    return { va, vb };
  }

  it('the proof of concept: same content, other record; the two holders end the first session, nothing is hidden', async () => {
    const { va, vb } = await twoHeads();
    expect(at(va, 'm', 1).check).toBe(at(vb, 'm', 1).check); // the content check value is equal ...
    expect(changeLink(at(va, 'm', 1))).not.toBe(changeLink(at(vb, 'm', 1))); // ... the link is not
    const a = merge(emptyReplica('h'), va.log).replica;
    const b = merge(emptyReplica('k'), vb.log).replica;
    const out = await session(a, b, judgeFor('h'), judgeFor('k'));
    for (const side of [out.a, out.b]) {
      expect(side.session.refusal).toBe('diverged');
      expect(side.session.refusalReason).toBe('tip-mismatch');
      expect(side.session.subjectDevice).toBe('m');
    }
  });

  it('every member of the head counts: clock, collection, record, kind and prev change the link', async () => {
    const first = at(await signed(put(emptyReplica('m'), 'alice', { amount: 100 })), 'm', 1);
    const link = changeLink(first);
    expect(link).toHaveLength(43);
    for (const other of [
      { ...first, clock: first.clock + 1 },
      { ...first, collection: 'other' },
      { ...first, id: 'bob' },
      { ...first, device: 'x' },
      { ...first, seq: 2 },
      { ...first, kind: 'delete' as const },
      { ...first, prev: 'p'.repeat(43) },
    ]) {
      expect(changeLink(other), JSON.stringify(other).slice(0, 80)).not.toBe(link);
    }
    // an erased change keeps the link it had
    const erased = {
      device: first.device,
      seq: first.seq,
      clock: first.clock,
      collection: first.collection,
      id: first.id,
      kind: 'redacted' as const,
      check: first.check as string,
      sig: first.sig as string,
    };
    expect(changeLink(erased)).toBe(link);
    // an unsigned change has the link it will have once signed
    const bare = put(emptyReplica('m'), 'alice', { amount: 100 }).log[0] as Change;
    expect(changeLink(bare)).toBe(link);
  });

  it('a successor of the other version is refused as soon as it meets the held predecessor (prev covers the head)', async () => {
    const { va, vb } = await twoHeads();
    const next = await signed(put(va, 'alice', { amount: 101 }));
    const holder = merge(emptyReplica('k'), vb.log).replica; // holds the OTHER version of m:1
    const out = await session(
      merge(emptyReplica('h'), next.log).replica,
      holder,
      judgeFor('h'),
      judgeFor('k'),
    );
    // h holds the version the stand of k names another link for: the session ends there ...
    expect(out.a.session.refusal).toBe('diverged');
    expect(out.a.session.subjectDevice).toBe('m');
    // ... and judged on its own the successor meets two signed changes of one author: equivocation
    const verdicts = await judgeDetailed({ ...judgeFor('k'), state: holder }, [at(next, 'm', 2)]);
    expect(verdicts).toEqual([{ verdict: 'false', reason: 'equivocation' }]);
  });
});

// ---------------------------------------------------------------------------------------------
describe('F5: a tip is an unproven claim; only two verifying signatures prove equivocation', () => {
  it('a forged tip never yields a blame: neutral reason, no refusalDevice', async () => {
    const m = await signed(put(emptyReplica('m'), 'r', { t: 1 }));
    const honest = merge(emptyReplica('h'), m.log).replica;
    const stand = json(startSession(honest).send[0]) as { tips: Record<string, string> };
    stand.tips.m = 'z'.repeat(43); // an attacker changes the tip in transit
    const step = receive(startSession(honest).session, honest, stand);
    expect(step.session.refusal).toBe('diverged');
    expect(step.session.refusalReason).toBe('tip-mismatch');
    expect(step.session.refusalDevice).toBeUndefined();
    expect(step.session.subjectDevice).toBe('m');
    expect(step.replica).toBe(honest);
    expect(tipConflict(honest, honest.vector, stand.tips)).toBe('m');
  });

  describe('proveEquivocation', () => {
    let first: Change;
    let second: Change;
    beforeAll(async () => {
      const base = emptyReplica('m');
      first = at(await signed(put(base, 'alice', { amount: 100 })), 'm', 1);
      second = at(await signed(put(base, 'bob', { amount: 100 })), 'm', 1);
    });
    const key = (): CryptoKey => (pairs.m as CryptoKeyPair).publicKey;

    it('two different signed versions of one number are proven', async () => {
      expect(await proveEquivocation(first, second, key(), APP, SET)).toBe(true);
      expect(await proveEquivocation(second, first, key(), APP, SET)).toBe(true);
    });

    it('one change twice (also a re-parsed copy) proves nothing', async () => {
      expect(await proveEquivocation(first, first, key(), APP, SET)).toBe(false);
      expect(await proveEquivocation(first, json(first), key(), APP, SET)).toBe(false);
    });

    it('unsigned, invalid, foreign or mismatched changes prove nothing', async () => {
      const { sig: _s, ...unsigned } = second;
      expect(await proveEquivocation(first, unsigned as Change, key(), APP, SET)).toBe(false);
      const badSig = { ...second, sig: (first.sig as string).replace(/.$/, 'A') };
      expect(await proveEquivocation(first, badSig, key(), APP, SET)).toBe(false);
      // the second version signed by somebody else
      const forged = await signChange(APP, (pairs.q as CryptoKeyPair).privateKey, second, SET);
      expect(await proveEquivocation(first, forged, key(), APP, SET)).toBe(false);
      // the wrong key, app or data set
      expect(
        await proveEquivocation(first, second, (pairs.q as CryptoKeyPair).publicKey, APP, SET),
      ).toBe(false);
      expect(await proveEquivocation(first, second, key(), 'other', SET)).toBe(false);
      expect(await proveEquivocation(first, second, key(), APP, 'other')).toBe(false);
      expect(await proveEquivocation(first, second, key(), APP, '')).toBe(false);
      // another number or another device
      expect(await proveEquivocation(first, { ...second, seq: 2 }, key(), APP, SET)).toBe(false);
      expect(await proveEquivocation(first, { ...second, device: 'q' }, key(), APP, SET)).toBe(
        false,
      );
      // content that does not match its check value
      const tampered = { ...second, fields: { amount: 999 } };
      expect(await proveEquivocation(first, tampered, key(), APP, SET)).toBe(false);
    });

    it('an erased version counts (it keeps its signature) and the evidence accessor finds the held one', async () => {
      const base = emptyReplica('m');
      let r = put(base, 'alice', { amount: 100 });
      r = ok(remove(r, COL, 'alice', {}));
      r = await signed(r);
      const erased = at(r, 'm', 1);
      expect(erased.kind).toBe('redacted');
      expect(await proveEquivocation(erased, second, key(), APP, SET)).toBe(true);
      expect(changeAt(r, 'm', 1)).toBe(erased);
      expect(changeAt(r, 'm', 3)).toBeUndefined();
      expect(changeAt(r, 'nobody', 1)).toBeUndefined();
    });
  });

  it('what an app does: on tip-mismatch fetch the other version with changeAt and prove it', async () => {
    const base = emptyReplica('m');
    const va = await signed(put(base, 'alice', { amount: 100 }));
    const vb = await signed(put(base, 'bob', { amount: 100 }));
    const a = merge(emptyReplica('h'), va.log).replica;
    const b = merge(emptyReplica('k'), vb.log).replica;
    const out = await session(a, b, judgeFor('h'), judgeFor('k'));
    const subject = out.a.session.subjectDevice as string;
    const mine = changeAt(a, subject, 1) as Change;
    const theirs = json(changeAt(b, subject, 1)) as Change;
    expect(
      await proveEquivocation(mine, theirs, (pairs[subject] as CryptoKeyPair).publicKey, APP, SET),
    ).toBe(true);
    // a forged tip leaves nothing to prove: the "other version" is the same change
    const honest = merge(emptyReplica('x1'), va.log).replica;
    expect(
      await proveEquivocation(
        mine,
        changeAt(honest, 'm', 1) as Change,
        (pairs.m as CryptoKeyPair).publicKey,
        APP,
        SET,
      ),
    ).toBe(false);
  });
});

// keep the unused helper imports honest
void resign;
void tipsOf;
