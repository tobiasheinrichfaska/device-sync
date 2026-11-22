// Regression tests of the third security review, round 3 (hash chain and erasure cost). N4: a
// number signed twice is seen at the first session (`prev`, `tips`); N6: the fixpoint of erased changes
// is not quadratic. Each test was written from the proof of concept first.
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  LIMITS,
  changeLink,
  emptyReplica,
  insertSignatures,
  judgeChanges,
  judgeDetailed,
  merge,
  onSyncMessage,
  parseChange,
  parseSyncMessage,
  pieces,
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
  type Replica,
  type Step,
  type SyncMessage,
} from '../../src/log/index.ts';
import { admit, emptyJudging, settle } from '../../src/log/signing.ts';
import { COL, ok, prng, removed, written } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
const IDS = ['x', 'm', 'h', 'k', 'a', 'b', 'c', 'd'] as const;
const pairs: Record<string, CryptoKeyPair> = {};
beforeAll(async () => {
  for (const id of IDS) pairs[id] = (await generateDeviceKeys()).signing;
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
const at = (r: Replica, device: string, seq: number): Change => {
  const c = r.log.find((x) => x.device === device && x.seq === seq);
  if (!c) throw new Error(`no ${device}#${seq}`);
  return c;
};

/** The new replica of a write that was taken, the old one when the record is deleted for good. */
const attempt = (result: ReturnType<typeof write>, old: Replica): Replica =>
  result.ok ? result.replica : old;

/** A whole session between two devices, messages delivered in order, both ways. */
async function session(
  a: Replica,
  b: Replica,
  judgeA: JudgeOptions,
  judgeB: JudgeOptions,
): Promise<{ a: Step; b: Step }> {
  let sa: Step = startSession(a);
  let sb: Step = startSession(b);
  let toA: SyncMessage[] = [...sb.send];
  let toB: SyncMessage[] = [...sa.send];
  for (let guard = 0; guard < 500 && (toA.length > 0 || toB.length > 0); guard += 1) {
    const m = toB.shift();
    if (m) {
      sb = await receiveJudged(sb.session, sb.replica, json(m), judgeB);
      toA = [...toA, ...sb.send];
    }
    const n = toA.shift();
    if (n) {
      sa = await receiveJudged(sa.session, sa.replica, json(n), judgeA);
      toB = [...toB, ...sa.send];
    }
  }
  return { a: sa, b: sb };
}

// ---------------------------------------------------------------------------------------------
describe('N4: a number signed twice is seen at the first session (hash chain and tips)', () => {
  /** M signs the number m:1 in two versions (here the device is called x). */
  async function twoVersions(): Promise<{ va: Replica; vb: Replica; base: Replica }> {
    const base = emptyReplica('x');
    const va = await signed(written(base, 'r1', { t: 'version a' }));
    const vb = await signed(written(base, 'r1', { t: 'version b' }));
    return { va, vb, base };
  }

  it('two honest devices holding the two versions refuse each other at the stand, naming the author', async () => {
    const { va, vb } = await twoVersions();
    const h1 = merge(emptyReplica('h'), va.log).replica;
    const h2 = merge(emptyReplica('k'), vb.log).replica;
    expect(h1.vector).toEqual(h2.vector); // equal stands: nothing would be sent
    const r = await session(h1, h2, judgeFor('h'), judgeFor('k'));
    for (const side of [r.a, r.b]) {
      expect(side.session.refusal).toBe('forged');
      expect(side.session.refusalReason).toBe('equivocation');
      expect(side.session.refusalDevice).toBe('x');
    }
    // nothing changed on either side
    expect(r.a.replica.log).toEqual(h1.log);
    expect(r.b.replica.log).toEqual(h2.log);
  });

  it('it is also seen at the first stand of an unjudged session (onSyncMessage / receive)', async () => {
    const { va, vb } = await twoVersions();
    const h1 = merge(emptyReplica('h'), va.log).replica;
    const h2 = merge(emptyReplica('k'), vb.log).replica;
    const step = onSyncMessage(
      startSession(h2).session,
      h2,
      startSession(h1).send[0] as SyncMessage,
    );
    expect(step.session.refusalReason).toBe('equivocation');
    const viaReceive = receive(startSession(h2).session, h2, json(startSession(h1).send[0]));
    expect(viaReceive.session.refusalDevice).toBe('x');
  });

  it('two devices holding the same version are never refused', async () => {
    const { va } = await twoVersions();
    const h1 = merge(emptyReplica('h'), va.log).replica;
    const h2 = merge(emptyReplica('k'), va.log).replica;
    const r = await session(h1, h2, judgeFor('h'), judgeFor('k'));
    expect(r.a.session.refusal).toBeUndefined();
    expect(r.b.session.refusal).toBeUndefined();
  });

  it('a device ahead of the other on the same chain is not refused (the tip names a number the receiver holds)', async () => {
    let x = emptyReplica('x');
    for (let i = 0; i < 4; i += 1) x = written(x, `r${i}`, { t: i });
    x = await signed(x);
    const behind = merge(emptyReplica('h'), x.log.slice(0, 2)).replica;
    const r = await session(
      behind,
      merge(emptyReplica('k'), x.log).replica,
      judgeFor('h'),
      judgeFor('k'),
    );
    expect(r.a.session.refusal).toBeUndefined();
    expect(r.b.session.refusal).toBeUndefined();
    expect(r.a.replica.vector.x).toBe(4);
  });

  it('the hash chain: a successor whose prev names another predecessor is equivocation (held and in-batch)', async () => {
    let x = emptyReplica('x');
    x = written(written(x, 'r1', { t: 1 }), 'r2', { t: 2 });
    x = await signed(x);
    const [one, two] = [at(x, 'x', 1), at(x, 'x', 2)];
    const forgedTwo = await resign({ ...two, prev: 'z'.repeat(43) });
    // held predecessor
    const holder = merge(emptyReplica('h'), [one]).replica;
    expect(await judgeDetailed(context(holder), [forgedTwo])).toEqual([
      { verdict: 'false', reason: 'equivocation' },
    ]);
    expect(await judgeChanges(context(holder), [two])).toEqual(['checked']);
    // predecessor in the same batch, both orders
    for (const batch of [
      [one, forgedTwo],
      [forgedTwo, one],
    ]) {
      const [j1, j2] = await judgeDetailed(context(emptyReplica('h')), batch);
      expect([j1?.reason, j2?.reason]).toContain('equivocation');
    }
    // a held successor that names another version of the number
    const forgedOne = await resign({ ...one, clock: one.clock + 5, fields: { t: 'other' } });
    const holdsAll = merge(emptyReplica('h'), x.log).replica;
    expect((await judgeDetailed(context(holdsAll), [forgedOne]))[0]).toEqual({
      verdict: 'false',
      reason: 'equivocation',
    });
  });

  it('a signed change without prev after the first, or with prev on the first, is bad-prev', async () => {
    let x = emptyReplica('x');
    x = await signed(written(written(x, 'r1', { t: 1 }), 'r2', { t: 2 }));
    const { prev: _p, ...bare } = at(x, 'x', 2);
    const noPrev = await resign(bare as Change);
    expect((await judgeDetailed(context(emptyReplica('h')), [noPrev]))[0]).toEqual({
      verdict: 'false',
      reason: 'bad-prev',
    });
    const first = await resign({ ...at(x, 'x', 1), prev: 'p'.repeat(43) });
    expect((await judgeDetailed(context(emptyReplica('h')), [first]))[0]).toEqual({
      verdict: 'false',
      reason: 'bad-prev',
    });
  });

  it('prev survives redaction: the erased change keeps it, its signature and its successor still match', async () => {
    let x = emptyReplica('x');
    x = written(x, 'other', { t: 0 }); // x:1
    x = written(x, 'rec', { t: 'secret' }); // x:2
    const before = x.log.find((c) => c.seq === 2) as Change;
    x = removed(x, COL, 'rec'); // x:3 deletes it: x:2 is erased
    x = await signed(x);
    const erased = at(x, 'x', 2);
    expect(erased.kind).toBe('redacted');
    expect(erased.prev).toBe(changeLink(at(x, 'x', 1)));
    expect(erased.prev).toBe(before.prev);
    expect(at(x, 'x', 3).prev).toBe(changeLink(erased));
    expect(changeLink(erased)).toBe(erased.check);
    const j = await judgeDetailed(context(emptyReplica('h')), [...x.log]);
    expect(j.map((v) => v.verdict)).toEqual(['checked', 'checked', 'checked']);
    // the parser keeps it, too
    expect(parseChange(json(erased))).toEqual(erased);
  });

  it('forwarding valid chains is unaffected: a third device passes x on, everybody converges', async () => {
    let x = emptyReplica('x');
    for (let i = 0; i < 5; i += 1) x = written(x, `r${i % 2}`, { t: i });
    x = await signed(x);
    const mid = (await session(x, emptyReplica('h'), judgeFor('x'), judgeFor('h'))).b.replica;
    const end = await session(mid, emptyReplica('k'), judgeFor('h'), judgeFor('k'));
    expect(end.b.session.refusal).toBeUndefined();
    expect(end.b.replica.vector.x).toBe(5);
    expect(end.b.replica.log).toEqual(x.log);
  });

  it('tips: the link of the change at the vector position, per device; a tip of a number not held proves nothing', async () => {
    let x = emptyReplica('x');
    x = await signed(written(written(x, 'r1', { t: 1 }), 'r2', { t: 2 }));
    const tips = tipsOf(x);
    expect(tips).toEqual({ x: changeLink(at(x, 'x', 2)) });
    expect(tipConflict(x, x.vector, tips)).toBeUndefined();
    expect(tipConflict(x, { x: 2 }, { x: 'q'.repeat(43) })).toBe('x');
    expect(tipConflict(x, { x: 3 }, { x: 'q'.repeat(43) })).toBeUndefined();
    expect(tipConflict(emptyReplica('n'), { x: 2 }, { x: 'q'.repeat(43) })).toBeUndefined();
  });

  it('the parser: prev and tips are strict', () => {
    const c = (extra: Record<string, unknown>) => ({
      device: 'a',
      seq: 2,
      clock: 1,
      collection: 'items',
      id: 'r',
      kind: 'set',
      fields: { t: 1 },
      knew: {},
      prev: 'p'.repeat(43),
      ...extra,
    });
    expect(parseChange(c({}))).toBeDefined();
    expect(parseChange(c({ prev: undefined }))).toBeUndefined(); // missing after the first
    expect(parseChange(c({ prev: 'short' }))).toBeUndefined();
    expect(parseChange(c({ prev: 5 }))).toBeUndefined();
    expect(parseChange(c({ seq: 1 }))).toBeUndefined(); // prev on the first
    expect(parseChange(c({ seq: 1, prev: undefined }))).toBeDefined();
    const stand = (tips: unknown, vector: unknown = { a: 2 }) => ({ t: 'stand', vector, tips });
    expect(parseSyncMessage(stand({ a: 'p'.repeat(43) }))).toBeDefined();
    expect(parseSyncMessage(stand({}))).toBeDefined();
    expect(parseSyncMessage({ t: 'stand', vector: { a: 2 } })).toBeUndefined(); // tips are required
    expect(parseSyncMessage(stand({ b: 'p'.repeat(43) }))).toBeUndefined(); // not in the vector
    expect(parseSyncMessage(stand({ a: 'p'.repeat(43) }, { a: 0 }))).toBeUndefined(); // number 0 has no tip
    expect(parseSyncMessage(stand({ a: 'short' }))).toBeUndefined();
    expect(parseSyncMessage(stand([]))).toBeUndefined();
    expect(parseSyncMessage(stand(JSON.parse('{"__proto__":"x"}')))).toBeUndefined();
    const many = Object.fromEntries(
      Array.from({ length: LIMITS.maxDevices + 1 }, (_, i) => [`d${i}`, 'p'.repeat(43)]),
    );
    const vector = Object.fromEntries(Object.keys(many).map((k) => [k, 1]));
    expect(parseSyncMessage(stand(many, vector))).toBeUndefined();
  });

  it('honest randomized simulation: 3000 runs of several devices, writes, soft and final deletions, random sessions never refuse', async () => {
    let sessions = 0;
    let withErasure = 0;
    for (let run = 0; run < 3000; run += 1) {
      const rnd = prng(9000 + run);
      const devices = ['a', 'b', 'c'];
      let reps = new Map<string, Replica>(devices.map((d) => [d, emptyReplica(d)]));
      const steps = 4 + Math.floor(rnd() * 10);
      for (let s = 0; s < steps; s += 1) {
        const d = devices[Math.floor(rnd() * devices.length)] as string;
        const r = reps.get(d) as Replica;
        const rec = `r${Math.floor(rnd() * 3)}`;
        const roll = rnd();
        let out: Replica = r;
        if (roll < 0.55) out = attempt(write(r, COL, rec, { t: Math.floor(rnd() * 100) }), r);
        else if (roll < 0.7) out = attempt(remove(r, COL, rec), r);
        else {
          const other = devices[Math.floor(rnd() * devices.length)] as string;
          if (other === d) continue;
          const peer = reps.get(other) as Replica;
          // a plain (unjudged) session in both directions: stands with tips, then the changes
          let sa: Step = startSession(r);
          let sb: Step = startSession(peer);
          let toA: SyncMessage[] = [...sb.send];
          let toB: SyncMessage[] = [...sa.send];
          for (let g = 0; g < 50 && (toA.length > 0 || toB.length > 0); g += 1) {
            const m = toB.shift();
            if (m) {
              sb = receive(sb.session, sb.replica, json(m), { signedOnly: false });
              toA = [...toA, ...sb.send];
            }
            const n = toA.shift();
            if (n) {
              sa = receive(sa.session, sa.replica, json(n), { signedOnly: false });
              toB = [...toB, ...sa.send];
            }
          }
          sessions += 1;
          expect(sa.session.refusal, `run ${run}`).toBeUndefined();
          expect(sb.session.refusal, `run ${run}`).toBeUndefined();
          reps = new Map(reps).set(d, sa.replica).set(other, sb.replica);
          continue;
        }
        reps = new Map(reps).set(d, out);
      }
      if ([...reps.values()].some((r) => r.log.some((c) => c.kind === 'redacted')))
        withErasure += 1;
    }
    process.stderr.write(
      `\nhonest simulation: 3000 runs, ${sessions} sessions, ${withErasure} runs with erased changes, no refusal\n`,
    );
    expect(sessions).toBeGreaterThan(4000);
    expect(withErasure).toBeGreaterThan(500);
  }, 120_000);

  it('honest randomized simulation with real signatures: 300 runs, judged sessions never refuse', async () => {
    let sessions = 0;
    for (let run = 0; run < 300; run += 1) {
      const rnd = prng(31000 + run);
      const devices = ['a', 'b', 'c'];
      let reps = new Map<string, Replica>(devices.map((d) => [d, emptyReplica(d)]));
      const steps = 4 + Math.floor(rnd() * 6);
      for (let s = 0; s < steps; s += 1) {
        const d = devices[Math.floor(rnd() * devices.length)] as string;
        const r = reps.get(d) as Replica;
        const roll = rnd();
        if (roll < 0.5) {
          reps = new Map(reps).set(
            d,
            await signed(attempt(write(r, COL, `r${Math.floor(rnd() * 3)}`, { t: s }), r)),
          );
        } else if (roll < 0.65) {
          reps = new Map(reps).set(
            d,
            await signed(attempt(remove(r, COL, `r${Math.floor(rnd() * 3)}`), r)),
          );
        } else {
          const other = devices[Math.floor(rnd() * devices.length)] as string;
          if (other === d) continue;
          const out = await session(r, reps.get(other) as Replica, judgeFor(d), judgeFor(other));
          sessions += 1;
          expect(out.a.session.refusal, `run ${run}`).toBeUndefined();
          expect(out.b.session.refusal, `run ${run}`).toBeUndefined();
          reps = new Map(reps).set(d, out.a.replica).set(other, out.b.replica);
        }
      }
    }
    process.stderr.write(
      `\nsigned honest simulation: 300 runs, ${sessions} judged sessions, no refusal\n`,
    );
    expect(sessions).toBeGreaterThan(300);
  }, 120_000);
});

// ---------------------------------------------------------------------------------------------
describe('N6: the fixpoint of erased changes is not quadratic', () => {
  /**
   * One author: x:2k-1 writes r(k+1), x:2k deletes r(k). Cut after x:2n-2 (`more`): the erased write
   * of x:2n-3 has no deletion in sight, and every deletion before it depends on that gap being
   * filled, a chain of n links.
   */
  async function attack(n: number): Promise<Change[]> {
    let x = emptyReplica('x');
    for (let k = 1; k <= n; k += 1) {
      x = ok(write(x, COL, `r${k + 1}`, { t: k }));
      x = ok(remove(x, COL, `r${k}`));
    }
    const all = (await signed(x)).log;
    return all.slice(0, 2 * n - 2);
  }

  async function timedSettle(
    changes: Change[],
  ): Promise<{ ms: number; taken: number; refused: boolean }> {
    const state = emptyReplica('n');
    const admission = await admit(state, emptyJudging(), changes, judgeFor('n'));
    if (!admission.ok) throw new Error('refused');
    const started = performance.now();
    const read = await settle(state, admission.judging, judgeFor('n'), { more: true });
    const ms = performance.now() - started;
    const taken = merge(state, read.accepted).applied;
    return { ms, taken, refused: read.rejected > 0 };
  }

  it('settle of 500 / 1000 / 2000 / 4000 chained changes: nothing taken, no refusal, linear time', async () => {
    const sizes = [500, 1000, 2000, 4000];
    const full = await attack(2001);
    const results: Record<number, number> = {};
    for (const size of sizes) {
      const r = await timedSettle(full.slice(0, size));
      expect(r.refused).toBe(false);
      expect(r.taken).toBe(0);
      results[size] = r.ms;
    }
    process.stderr.write(
      `\nsettle of the erasure chain: ${sizes.map((s) => `${s}: ${(results[s] as number).toFixed(0)} ms`).join(', ')}\n`,
    );
    expect(results[4000] as number).toBeLessThan(2500);
    expect((results[4000] as number) / Math.max(results[2000] as number, 1)).toBeLessThan(3);
  }, 120_000);

  it('the session path: a cut answer with the chain takes nothing, refuses nothing, and repeats the same', async () => {
    const changes = await attack(60);
    const judge = judgeFor('n');
    for (let again = 0; again < 2; again += 1) {
      let step: Step = startSession(emptyReplica('n'));
      for (const piece of pieces(changes, { limits: { maxChanges: 40 } }, true)) {
        step = await receiveJudged(step.session, step.replica, json(piece), judge);
      }
      expect(step.session.refusal).toBeUndefined();
      expect(step.session.taken).toBe(0);
    }
  });

  it('what can be applied still is: a chain that ends in its deletion is taken whole', async () => {
    let x = emptyReplica('x');
    for (let k = 1; k <= 5; k += 1) {
      x = ok(write(x, COL, `r${k + 1}`, { t: k }));
      x = ok(remove(x, COL, `r${k}`));
    }
    x = ok(remove(x, COL, 'r6')); // the last write is erased by its deletion, too
    const all = (await signed(x)).log;
    const state = emptyReplica('n');
    const admission = await admit(state, emptyJudging(), all, judgeFor('n'));
    if (!admission.ok) throw new Error('refused');
    const read = await settle(state, admission.judging, judgeFor('n'));
    expect(read.rejected).toBe(0);
    expect(merge(state, read.accepted).applied).toBe(all.length);
  });
});
