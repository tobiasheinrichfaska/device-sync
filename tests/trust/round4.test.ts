// Regression tests of the fourth security review (trust layer). Each was written from the reviewer's
// proof of concept first and fails on the code before the fix.
//   F1  devices that fall out of trust without being removed were not checkable: their old changes
//       blocked honest devices for ever, and the verdict depended on what `merge` currently held
//   F6  removal by equal-rank devices: no id tie-break; what persists, what the viewer decides
//   F7  amplification in signature checks (keys times writes)
import { beforeAll, describe, expect, it } from 'vitest';
import {
  generateDeviceKeys,
  importPublicKey,
  publicKeys,
  verifyText,
} from '../../src/core/index.ts';
import {
  changeSigningText,
  emptyReplica,
  fingerprint,
  merge,
  readChanges,
  receiveJudged,
  startSession,
  type Change,
  type JudgeOptions,
  type Replica,
  type Step,
  type SyncMessage,
} from '../../src/log/index.ts';
import {
  DEVICE_COLLECTION,
  computeTrust,
  deviceKeySource,
  deviceNeverErase,
  deviceStatus,
  newDeviceId,
  vouchAll,
  vouchRoles,
  type KnownDevice,
  type TrustOptions,
} from '../../src/trust/index.ts';
import { derive, deriveAsync, MAX_CANDIDATE_KEYS } from '../../src/trust/derive.ts';
import {
  APP,
  SET,
  dev,
  drop,
  emptyOf,
  enter,
  holding,
  known,
  names,
  opts,
  prng,
  signed,
  writeRaw,
  type Dev,
} from './helpers.ts';

const NOTES = 'notes';
const VIEWER = 'device-' + '7'.repeat(32);
const json = <T>(m: T): T => JSON.parse(JSON.stringify(m)) as T;

const judgeFor = (me: string, direct: KnownDevice[], o: TrustOptions): JudgeOptions => ({
  appId: APP,
  dataSet: SET,
  ownDevice: me,
  neverErase: deviceNeverErase(),
  keys: deviceKeySource({ ...o, direct }),
});

interface Talk {
  readonly x: Step;
  readonly y: Step;
}
/** One judged session between two devices (messages delivered in order, both ways). */
async function talk(x: Replica, y: Replica, jx: JudgeOptions, jy: JudgeOptions): Promise<Talk> {
  let sx: Step = startSession(x);
  let sy: Step = startSession(y);
  let toX: SyncMessage[] = [...sy.send];
  let toY: SyncMessage[] = [...sx.send];
  for (let guard = 0; guard < 400 && (toX.length > 0 || toY.length > 0); guard += 1) {
    const m = toY.shift();
    if (m) {
      sy = await receiveJudged(sy.session, sy.replica, json(m), jy);
      toX = [...toX, ...sy.send];
    }
    const n = toX.shift();
    if (n) {
      sx = await receiveJudged(sx.session, sx.replica, json(n), jx);
      toY = [...toY, ...sx.send];
    }
  }
  return { x: sx, y: sy };
}

const sameVector = (reps: readonly Replica[]): boolean =>
  new Set(reps.map((r) => JSON.stringify(Object.entries(r.vector).sort()))).size === 1;

// ---------------------------------------------------------------------------------------------
describe('F1: a device that falls out of trust without being removed stays checkable', () => {
  const O = opts(vouchRoles(['admin']));
  let a: Dev, b: Dev, r: Dev, s: Dev, c: Dev, x: Dev;
  beforeAll(async () => {
    [a, b, r, s, c, x] = [
      await dev('A'),
      await dev('B'),
      await dev('R'),
      await dev('S'),
      await dev('C'),
      await dev('X'),
    ];
  });
  const direct = (): KnownDevice[] => [known(a, 'admin')];

  /** A enters admin R and member B; R enters S; S writes a note. Returns everybody's replicas. */
  async function world() {
    let ra = await enter(a, emptyOf(a), r, 'admin', O);
    ra = await enter(a, ra, b, 'member', O);
    let rr = merge(emptyOf(r), ra.log).replica;
    rr = await enter(r, rr, s, 'member', O);
    let rs = merge(emptyOf(s), rr.log).replica;
    rs = await signed(writeRaw(rs, NOTES, 'n1', { text: 'from s' }), s);
    return { ra, rr, rs };
  }

  it('the proof of concept: A removes R (normal administration) and enters C; B and A edit the note of S; everybody converges', async () => {
    const { ra, rr, rs } = await world();
    // A learns everything, then removes R and enters C
    let a1 = merge(merge(ra, rr.log).replica, rs.log).replica;
    a1 = await drop(a, a1, r, O);
    a1 = await enter(a, a1, c, 'member', O);
    // B holds what A had before the removal, and edits the note of S
    let b1 = merge(merge(merge(emptyOf(b), ra.log).replica, rr.log).replica, rs.log).replica;
    b1 = await signed(writeRaw(b1, NOTES, 'n1', { text: 'from b' }), b);
    // A edits it too, after it has met B's edit
    a1 = merge(a1, b1.log).replica;
    a1 = await signed(writeRaw(a1, NOTES, 'n1', { text: 'from a' }), a);
    let c1 = emptyOf(c);
    // sessions through A, then A enters a device X that C must learn about as well
    const jA = judgeFor(a.id, direct(), O);
    const jB = judgeFor(b.id, direct(), O);
    const jC = judgeFor(c.id, direct(), O);
    for (let round = 0; round < 3; round += 1) {
      const t1 = await talk(a1, b1, jA, jB);
      [a1, b1] = [t1.x.replica, t1.y.replica];
      const t2 = await talk(a1, c1, jA, jC);
      [a1, c1] = [t2.x.replica, t2.y.replica];
      for (const step of [t1.x, t1.y, t2.x, t2.y]) expect(step.session.refusal).toBeUndefined();
    }
    a1 = await enter(a, a1, x, 'member', O);
    for (let round = 0; round < 2; round += 1) {
      const t2 = await talk(a1, c1, jA, jC);
      [a1, c1] = [t2.x.replica, t2.y.replica];
      const t1 = await talk(a1, b1, jA, jB);
      [a1, b1] = [t1.x.replica, t1.y.replica];
    }
    // C holds everything A holds: the changes of S, A's later edits, and the entry of X
    expect(fingerprint(c1)).toBe(fingerprint(a1));
    expect(fingerprint(b1)).toBe(fingerprint(a1));
    expect(sameVector([a1, b1, c1])).toBe(true);
    expect(c1.vector[s.id]).toBe(1);
    // C's own view lists the others (a device never lists itself); A's view lists C, too
    const t = await computeTrust(c1, direct(), O);
    expect(names(t.trusted)).toEqual(['A', 'B', 'X']);
    expect(names((await computeTrust(a1, direct(), O)).trusted)).toEqual(['A', 'B', 'C', 'X']);
    // the last session had nothing left waiting
    const last = await talk(a1, c1, jA, jC);
    expect(last.x.session.waiting).toBe(0);
    expect(last.y.session.waiting).toBe(0);
    expect(last.x.session.sent + last.y.session.sent).toBe(0);
  }, 60_000);

  it('S is checkable but not trusted; R stays removed and checkable', async () => {
    const { ra, rr, rs } = await world();
    const removed = await drop(a, merge(ra, rr.log).replica, r, O);
    const view = holding(VIEWER, removed, rr, rs);
    const status = await deviceStatus(view, s.id, { ...O, direct: direct() });
    expect(status).toEqual({
      trusted: false,
      checkable: true,
      removed: false,
      reasons: ['not-vouched'],
    });
    expect(await deviceStatus(view, r.id, { ...O, direct: direct() })).toMatchObject({
      trusted: false,
      checkable: true,
      removed: true,
    });
    const t = await computeTrust(view, direct(), O);
    expect(names(t.trusted)).toEqual(['A', 'B']);
    expect(names(t.checkable)).toEqual(['A', 'B', 'R', 'S']);
  });

  it('a device with a key conflict stays not checkable (its keys are ambiguous)', async () => {
    let ra = await enter(a, emptyOf(a), r, 'admin', O);
    ra = await enter(a, ra, b, 'admin', O);
    let rr = merge(emptyOf(r), ra.log).replica;
    rr = await enter(r, rr, s, 'member', O);
    // B writes another signing key into the entry of S: two vouchers disagree
    let rb = merge(emptyOf(b), rr.log).replica;
    rb = await signed(writeRaw(rb, DEVICE_COLLECTION, s.id, { sig: c.intro.sig }), b);
    const view = holding(VIEWER, ra, rr, rb);
    const status = await deviceStatus(view, s.id, { ...O, direct: direct() });
    expect(status.reasons).toContain('key-conflict');
    expect(status.checkable).toBe(false);
  });

  describe('verdicts do not depend on what merge currently holds (removal first, after, or hidden behind a causal hold)', () => {
    /** S wrote a note (s:1) and `removed: false` into R's entry (s:2); A saw both, then removed R. */
    async function ordered() {
      const { ra, rr, rs } = await world();
      let rs2 = rs;
      rs2 = merge(rs2, ra.log).replica;
      rs2 = await signed(writeRaw(rs2, DEVICE_COLLECTION, r.id, { removed: false }), s);
      let a1 = merge(merge(ra, rr.log).replica, rs2.log).replica;
      a1 = await drop(a, a1, r, O);
      const removal = a1.log.filter((ch) => ch.device === a.id).at(-1) as Change;
      expect(removal.knew).toMatchObject({ [s.id]: 2 }); // the removal depends on s:2
      const fromS = rs2.log.filter((ch) => ch.device === s.id);
      return { ra, rr, a1, removal, fromS };
    }
    const judge = (me: string): JudgeOptions => judgeFor(me, direct(), O);

    it('(1) the removal is already merged', async () => {
      const { a1, rr, fromS } = await ordered();
      const viewer = merge(merge(emptyOf(VIEWER), a1.log).replica, rr.log).replica;
      const res = await readChanges(viewer, fromS, judge(VIEWER));
      expect(res.rejected).toBe(0);
      expect(res.accepted.filter((ch) => ch.device === s.id)).toHaveLength(2);
      expect(res.pending).toEqual([]);
    });

    it('(2) the removal arrives in the same batch, before or after the changes of S', async () => {
      const { ra, rr, a1, fromS } = await ordered();
      const fromA = a1.log.filter((ch) => ch.device === a.id);
      const fromR = rr.log.filter((ch) => ch.device === r.id);
      for (const batch of [
        [...fromA, ...fromR, ...fromS],
        [...fromS, ...fromR, ...fromA],
      ]) {
        const viewer = merge(emptyOf(VIEWER), ra.log).replica;
        const res = await readChanges(viewer, batch, judge(VIEWER));
        expect(res.rejected).toBe(0);
        expect(res.pending).toEqual([]);
        expect(res.accepted.filter((ch) => ch.device === s.id)).toHaveLength(2);
      }
    });

    it('(3) the removal is held behind a causal hold (s:2 is missing): the changes of S are checked all the same', async () => {
      const { ra, rr, a1, removal, fromS } = await ordered();
      const fromR = rr.log.filter((ch) => ch.device === r.id);
      const fromA = a1.log.filter((ch) => ch.device === a.id);
      expect(fromA).toContain(removal);
      for (const batch of [
        [...fromA, ...fromR, ...fromS.slice(0, 1)],
        [...fromS.slice(0, 1), ...fromR, ...fromA],
      ]) {
        const viewer = merge(emptyOf(VIEWER), ra.log).replica;
        const res = await readChanges(viewer, batch, judge(VIEWER));
        expect(res.rejected).toBe(0);
        expect(res.pending).toEqual([]);
        expect(res.accepted.filter((ch) => ch.device === s.id)).toHaveLength(1);
        // the removal itself waits for s:2 (it is verified, merge holds it), it is not refused
        expect(res.accepted).toContain(removal);
      }
    });

    it('(4) the changes of S come first, the removal later: the same verdict', async () => {
      const { ra, rr, a1, fromS } = await ordered();
      const viewer = merge(merge(emptyOf(VIEWER), ra.log).replica, rr.log).replica;
      const first = await readChanges(viewer, fromS, judge(VIEWER));
      expect(first.accepted).toHaveLength(2);
      const later = merge(viewer, first.accepted).replica;
      const second = await readChanges(
        later,
        a1.log.filter((ch) => ch.device === a.id),
        judge(VIEWER),
      );
      expect(second.rejected).toBe(0);
    });
  });

  describe('simulation: honest devices after the removal of a member that introduced others', () => {
    const RUNS = 300;
    let all: Dev[];
    beforeAll(async () => {
      all = [
        await dev('A'),
        await dev('B'),
        await dev('R'),
        await dev('S'),
        await dev('C'),
        await dev('D'),
      ];
    }, 60_000);

    it(`${RUNS} runs: all honest devices converge, nobody blocks`, async () => {
      const [A, B, R, S, C, D] = all as [Dev, Dev, Dev, Dev, Dev, Dev];
      const dir = [known(A, 'admin')];
      let sessions = 0;
      let withHold = 0;
      let removedEarly = 0;
      for (let run = 0; run < RUNS; run += 1) {
        const rnd = prng(52_000 + run);
        const reps = new Map<string, Replica>(all.map((d) => [d.id, emptyOf(d)]));
        const rep = (d: Dev): Replica => reps.get(d.id) as Replica;
        const judge = (d: Dev): JudgeOptions => judgeFor(d.id, dir, O);
        const sync = async (x: Dev, y: Dev): Promise<void> => {
          const out = await talk(rep(x), rep(y), judge(x), judge(y));
          sessions += 1;
          expect(out.x.session.refusal, `run ${run}`).toBeUndefined();
          expect(out.y.session.refusal, `run ${run}`).toBeUndefined();
          reps.set(x.id, out.x.replica);
          reps.set(y.id, out.y.replica);
        };
        const some = async (): Promise<void> => {
          for (let i = Math.floor(rnd() * 2); i > 0; i -= 1) {
            const x = all[Math.floor(rnd() * 6)] as Dev;
            const y = all[Math.floor(rnd() * 6)] as Dev;
            if (x !== y) await sync(x, y);
          }
        };
        const note = async (d: Dev, id: string): Promise<void> => {
          reps.set(d.id, await signed(writeRaw(rep(d), NOTES, id, { text: `${d.name}${run}` }), d));
        };
        // A enters R (admin) and B (admin or member)
        let ra = await enter(A, rep(A), R, 'admin', O);
        ra = await enter(A, ra, B, rnd() < 0.5 ? 'admin' : 'member', O);
        reps.set(A.id, ra);
        // R holds A's log and enters S, S writes notes
        await sync(A, R);
        reps.set(R.id, await enter(R, rep(R), S, 'member', O));
        await sync(R, S);
        for (let i = 1 + Math.floor(rnd() * 3); i > 0; i -= 1)
          await note(S, `n${Math.floor(rnd() * 3)}`);
        await some();
        if (rnd() < 0.4) {
          // S writes into R's entry (a field that the removal will have to name): the removal can hang behind it
          reps.set(
            S.id,
            await signed(writeRaw(rep(S), DEVICE_COLLECTION, R.id, { removed: false }), S),
          );
          withHold += 1;
        }
        await some();
        // A learns what it learns, removes R, enters C and D
        if (rnd() < 0.8) await sync(A, S);
        if (rnd() < 0.5) await sync(A, R);
        reps.set(A.id, await drop(A, rep(A), R, O));
        if (rnd() < 0.5) removedEarly += 1;
        reps.set(A.id, await enter(A, rep(A), C, 'member', O));
        await some();
        if (rnd() < 0.6) reps.set(A.id, await enter(A, rep(A), D, 'member', O));
        for (const d of [B, C, S, A]) if (rnd() < 0.6) await note(d, `n${Math.floor(rnd() * 3)}`);
        await some();
        // everybody meets A, twice (a hub): this is what "nobody blocks" means
        for (let pass = 0; pass < 2; pass += 1) {
          for (const d of [B, C, D, R, S]) await sync(d, A);
        }
        const reps2 = all.map(rep);
        const prints = new Set(reps2.map((r) => fingerprint(r)));
        expect(prints.size, `run ${run}: fingerprints`).toBe(1);
        expect(sameVector(reps2), `run ${run}: vectors`).toBe(true);
      }
      process.stderr.write(
        `\nF1 simulation: ${RUNS} runs, ${sessions} sessions, ${withHold} with a removal behind a causal hold, all honest devices converged\n`,
      );
      expect(withHold).toBeGreaterThan(60);
    }, 240_000);
  });
});

// ---------------------------------------------------------------------------------------------
describe('F6: removal by devices of equal rank has no id tie-break', () => {
  const O = opts(vouchAll());
  const A_ROLE = 'admin';
  let a: Dev;
  let pool: Dev[];
  beforeAll(async () => {
    a = await dev('A');
    pool = [];
    for (let i = 0; i < 8; i += 1) pool.push(await dev(`P${i}`));
  }, 60_000);

  const byId = (list: readonly Dev[]): Dev[] => [...list].sort((p, q) => (p.id < q.id ? -1 : 1));
  const view = (...logs: Replica[]) => holding(VIEWER, ...logs);

  it('two equal devices that remove each other are both removed, whichever id is smaller', async () => {
    const pairs: [Dev, Dev][] = [
      [pool[0] as Dev, pool[1] as Dev],
      [pool[1] as Dev, pool[0] as Dev],
    ];
    for (const [first, second] of pairs) {
      let base = await enter(a, emptyOf(a), first, A_ROLE, O);
      base = await enter(a, base, second, A_ROLE, O);
      const byFirst = await drop(first, merge(emptyOf(first), base.log).replica, second, O);
      const bySecond = await drop(second, merge(emptyOf(second), base.log).replica, first, O);
      const t = await computeTrust(view(base, byFirst, bySecond), [known(a, A_ROLE)], O);
      expect(names(t.trusted)).toEqual(['A']);
      expect(t.removed).toEqual([first.id, second.id].sort());
    }
  });

  for (const which of ['the smallest', 'the largest'] as const) {
    it(`proof of concept a: an admin with ${which} id removes 6 equal devices (3 admins); the counter-removals count`, async () => {
      const sorted = byId(pool.slice(0, 7));
      const m = which === 'the smallest' ? (sorted[0] as Dev) : (sorted[6] as Dev);
      const six = sorted.filter((d) => d !== m);
      const admins = six.slice(0, 3);
      let base = await enter(a, emptyOf(a), m, A_ROLE, O);
      for (const [i, d] of six.entries()) {
        base = await enter(a, base, d, i < 3 ? A_ROLE : 'member', O);
      }
      const logs: Replica[] = [base];
      // M removes all six; the three admins remove M
      let rm = merge(emptyOf(m), base.log).replica;
      for (const d of six) rm = await drop(m, rm, d, O);
      logs.push(rm);
      for (const adm of admins) {
        logs.push(await drop(adm, merge(emptyOf(adm), base.log).replica, m, O));
      }
      const t = await computeTrust(view(...logs), [known(a, A_ROLE)], O);
      // everything of that rank is removed, in either id order; a removal persists
      expect(names(t.trusted)).toEqual(['A']);
      expect(t.removed).toHaveLength(7);
      // only a device of LOWER rank can undo the damage: A removes M, so M's removals do not count
      const byA = await drop(a, merge(emptyOf(a), base.log).replica, m, O);
      const healed = await computeTrust(view(...logs, byA), [known(a, A_ROLE)], O);
      expect(healed.removed).toEqual([m.id]);
      expect(names(healed.trusted)).toEqual(['A', ...six.map((d) => d.name).sort()].sort());
    });
  }

  describe('proof of concept b: M removes C, then B (equal rank) removes M', () => {
    let m: Dev, b: Dev, c: Dev, s: Dev;
    beforeAll(() => {
      [m, b, c, s] = [pool[0] as Dev, pool[1] as Dev, pool[2] as Dev, pool[3] as Dev];
    });
    async function logs(): Promise<Replica[]> {
      let base = await enter(a, emptyOf(a), m, A_ROLE, O);
      base = await enter(a, base, b, A_ROLE, O);
      base = await enter(a, base, c, A_ROLE, O);
      const rc = await enter(c, merge(emptyOf(c), base.log).replica, s, 'member', O);
      const byM = await drop(m, merge(emptyOf(m), base.log).replica, c, O);
      const byB = await drop(b, merge(emptyOf(b), base.log).replica, m, O);
      return [base, rc, byM, byB];
    }

    it('a viewer who knows only A: M and C are removed (the same rank, both acted), B stays, S is checkable but not trusted', async () => {
      const t = await computeTrust(view(...(await logs())), [known(a, A_ROLE)], O);
      // (the devices are called P0 to P3 here: M = P0, B = P1, C = P2, S = P3)
      expect(names(t.trusted)).toEqual(['A', 'P1']);
      expect(t.removed).toEqual([c.id, m.id].sort());
      expect(names(t.checkable)).toEqual(['A', 'P0', 'P1', 'P2', 'P3']);
      expect(t.checkableById.has(s.id)).toBe(true);
    });

    it('a viewer who also met B in person: B has a lower rank, M is removed first and its removal of C does not count: C and S are trusted', async () => {
      const t = await computeTrust(
        view(...(await logs())),
        [known(a, A_ROLE), known(b, A_ROLE)],
        O,
      );
      expect(names(t.trusted)).toEqual(['A', 'P1', 'P2', 'P3']);
      expect(t.removed).toEqual([m.id]);
    });

    it('the two viewers differ because the set of devices met in person is part of the input (per viewer, by design)', async () => {
      const all = view(...(await logs()));
      const chain = await computeTrust(all, [known(a, A_ROLE)], O);
      const met = await computeTrust(all, [known(a, A_ROLE), known(b, A_ROLE)], O);
      expect(names(chain.trusted)).not.toEqual(names(met.trusted));
      // but each viewer's result does not depend on the order of the log
      for (const order of [(await logs()).reverse(), await logs()]) {
        const again = await computeTrust(view(...order), [known(a, A_ROLE), known(b, A_ROLE)], O);
        expect(names(again.trusted)).toEqual(names(met.trusted));
      }
    });
  });
});

// ---------------------------------------------------------------------------------------------
describe('F7: the cost of checking signatures does not multiply keys by writes', () => {
  const O = opts(vouchAll());
  const POOL = 200;
  let a: Dev, m: Dev, b: Dev;
  let crowd: Dev[];
  beforeAll(async () => {
    a = await dev('A');
    m = await dev('M');
    b = await dev('B');
    // 200 more devices: their entries are what B writes, their signing keys are the foreign keys M writes
    crowd = [];
    for (let i = 0; i < POOL; i += 1) {
      const id = newDeviceId(Uint8Array.from([0xc0, i >> 8, i & 255, ...new Uint8Array(13)]));
      const keys = await generateDeviceKeys();
      crowd.push({
        id,
        name: `K${i}`,
        keys,
        intro: { device: id, name: `K${i}`, ...(await publicKeys(keys)) },
      });
    }
  }, 120_000);

  /** B (a voucher entered by A) wrote `writes` entries; M (a voucher) wrote `keys` foreign keys into B's entry. */
  async function poisoned(keys: number, writes: number): Promise<Replica> {
    let ra = await enter(a, emptyOf(a), m, 'admin', O);
    ra = await enter(a, ra, b, 'admin', O);
    let rb = merge(emptyOf(b), ra.log).replica;
    for (const d of crowd.slice(0, writes)) {
      rb = writeRaw(rb, DEVICE_COLLECTION, d.id, {
        name: d.name,
        sig: d.intro.sig,
        dh: d.intro.dh,
      });
    }
    rb = await signed(rb, b);
    let rm = merge(emptyOf(m), ra.log).replica;
    for (const d of crowd.slice(0, keys)) {
      rm = writeRaw(rm, DEVICE_COLLECTION, b.id, { sig: d.intro.sig });
    }
    rm = await signed(rm, m);
    return merge(merge(merge(emptyOf(VIEWER), ra.log).replica, rb.log).replica, rm.log).replica;
  }

  /** How many signature checks a cold derivation asks for (each really verified), and how long it takes. */
  async function cost(replica: Replica): Promise<{ checks: number; ms: number }> {
    const direct = [known(a, 'admin')];
    const started = performance.now();
    const run = derive(replica, direct, O);
    let checks = 0;
    let step = run.next();
    while (!step.done) {
      checks += 1;
      const { write, sigKey } = step.value;
      const key = await importPublicKey(sigKey, 'sig');
      const sig = write.change.sig;
      const good =
        key !== undefined &&
        sig !== undefined &&
        (await verifyText(key, changeSigningText(APP, write.change, SET), sig));
      step = run.next(good);
    }
    return { checks, ms: performance.now() - started };
  }

  it('the candidate keys of an entry are capped', () => {
    expect(MAX_CANDIDATE_KEYS).toBe(8);
  });

  it('200 foreign keys written into the entry of a voucher with 200 written entries: the checks stay linear (cold)', async () => {
    const small = await cost(await poisoned(50, 50));
    const large = await cost(await poisoned(200, 200));
    process.stderr.write(
      `\nF7: 50x50 ${small.checks} checks ${small.ms.toFixed(0)} ms; 200x200 ${large.checks} checks ${large.ms.toFixed(0)} ms (before the fix: keys x writes)\n`,
    );
    // keys x writes would be 40000 checks; with the cap it is at most 9 per write plus the entries
    expect(large.checks).toBeLessThan(9 * 200 + 2000);
    expect(large.checks).toBeLessThan(small.checks * 6);
    expect(large.ms).toBeLessThan(5000);
    // and the real thing, with a generous bound
    const started = performance.now();
    const trust = await deriveAsync(
      json(await poisoned(200, 200)) as unknown as Replica,
      [known(a, 'admin')],
      O,
    );
    expect(performance.now() - started).toBeLessThan(5000);
    expect(trust.trust.trusted.length).toBeGreaterThan(0);
  }, 120_000);

  it('the keys are capped per entry: 60 foreign keys in each of 25 voucher entries cost about 8 checks per voucher, not 60', async () => {
    const VOUCHERS = 25;
    const KEYS = 60;
    let ra = await enter(a, emptyOf(a), m, 'admin', O);
    const vouchers = crowd.slice(0, VOUCHERS);
    for (const v of vouchers) ra = await enter(a, ra, v, 'admin', O);
    // every voucher writes one entry of its own
    const logs: Replica[] = [ra];
    for (const [i, v] of vouchers.entries()) {
      const target = crowd[100 + i] as Dev;
      const rv = merge(emptyOf(v), ra.log).replica;
      logs.push(
        await signed(
          writeRaw(rv, DEVICE_COLLECTION, target.id, {
            name: target.name,
            sig: target.intro.sig,
            dh: target.intro.dh,
          }),
          v,
        ),
      );
    }
    // M buries the real key of every voucher under foreign keys that are newer
    let rm = merge(emptyOf(m), ra.log).replica;
    for (const v of vouchers) {
      for (let j = 0; j < KEYS; j += 1) {
        rm = writeRaw(rm, DEVICE_COLLECTION, v.id, { sig: (crowd[125 + j] as Dev).intro.sig });
      }
    }
    logs.push(await signed(rm, m));
    const view = holding(VIEWER, ...logs);
    const { checks } = await cost(view);
    process.stderr.write(`\nF7 spread: ${VOUCHERS} vouchers x ${KEYS} keys: ${checks} checks\n`);
    // the writes of M itself (25 x 60) are checked once each; what the keys add is bounded by 8 per voucher
    expect(checks).toBeLessThan(VOUCHERS * KEYS + 40 * VOUCHERS + 200);
  }, 120_000);

  it('honest key rotation is unchanged: a voucher that writes a second key for a device makes it key-conflicted', async () => {
    let ra = await enter(a, emptyOf(a), b, 'admin', O);
    const d = crowd[0] as Dev;
    const e = crowd[1] as Dev;
    ra = await enter(a, ra, d, undefined, O);
    ra = await signed(writeRaw(ra, DEVICE_COLLECTION, d.id, { sig: e.intro.sig }), a);
    const t = await computeTrust(ra, [known(a, 'admin')], O);
    expect(t.reasons.get(d.id)).toContain('key-conflict');
    expect(t.checkableById.has(d.id)).toBe(false);
  });

  it('keys written by a removed device are not used for the entry that is read as checkable', async () => {
    let ra = await enter(a, emptyOf(a), m, 'admin', O);
    ra = await enter(a, ra, b, 'admin', O);
    const byA = await drop(a, ra, m, O);
    let rm = merge(emptyOf(m), ra.log).replica;
    rm = await signed(
      writeRaw(rm, DEVICE_COLLECTION, b.id, { sig: (crowd[0] as Dev).intro.sig }),
      m,
    );
    const t = await computeTrust(holding(VIEWER, byA, rm), [known(a, 'admin')], O);
    expect(t.removed).toEqual([m.id]);
    expect(t.checkableById.get(b.id)?.sig).toBe(b.intro.sig);
    expect(t.checkableById.get(m.id)?.sig).toBe(m.intro.sig);
  });
});

void [VIEWER, emptyReplica, JSON];
