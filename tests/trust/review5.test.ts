// Round 3 review, third pass: a compromised voucher cannot neutralise its own removal or poison other
// entries (N3), an unverified removal does not shadow a verified one (N9), a voucher that withdraws a
// role later (N10), and the semantics after the write cut-off was taken out (N1/N2/N7/N8): a removed
// device stays checkable, honest devices never block each other.
import { beforeAll, describe, expect, it } from 'vitest';
import {
  fingerprint,
  merge,
  readChanges,
  receiveJudged,
  signChange,
  startSession,
  type Change,
  type JudgeOptions,
  type Replica,
  type Step,
  type SyncMessage,
} from '../../src/log/index.ts';
import {
  DEVICE_COLLECTION,
  addDevice,
  computeTrust,
  deviceKeySource,
  deviceNeverErase,
  deviceStatus,
  removeDevice,
  vouchAll,
  vouchRoles,
  type KnownDevice,
  type TrustOptions,
} from '../../src/trust/index.ts';
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
  ok,
  opts,
  signed,
  writeRaw,
  type Dev,
} from './helpers.ts';

const ALL: TrustOptions = opts(vouchAll());
const VIEWER = 'device-' + 'f'.repeat(32);

/** `author` holds the given logs and writes raw fields into the entry of `target`, signed. */
async function scribble(
  author: Dev,
  logs: readonly Replica[],
  target: Dev,
  fields: Record<string, unknown>,
): Promise<Replica> {
  const mine = logs.reduce((r, x) => merge(r, x.log).replica, emptyOf(author));
  return signed(writeRaw(mine, DEVICE_COLLECTION, target.id, fields), author);
}

const viewsOf = (a: Dev, b: Dev): { label: string; direct: KnownDevice[] }[] => [
  { label: 'knows B only through the chain', direct: [known(a)] },
  { label: 'met B in person', direct: [known(a), known(b)] },
];

describe('N3: a compromised voucher cannot neutralise its own removal or poison others', () => {
  let a: Dev, b: Dev, x: Dev, m: Dev;
  beforeAll(async () => {
    [a, b, x, m] = [await dev('A'), await dev('B'), await dev('X'), await dev('M')];
  });

  /** A enters B, X and M. */
  const ledger = async (): Promise<Replica> => {
    let r = await enter(a, emptyOf(a), b, undefined, ALL);
    r = await enter(a, r, x, undefined, ALL);
    return enter(a, r, m, undefined, ALL);
  };

  for (const poisonAfterRemoval of [false, true]) {
    for (const reversed of [false, true]) {
      const when = poisonAfterRemoval ? 'after' : 'before';
      it(`(a) B removes M, M writes another sig into B (${when} the removal, ${reversed ? 'reverse' : 'forward'} merge): both viewers agree, B trusted, M removed`, async () => {
        const base = await ledger();
        const byB = await drop(b, merge(emptyOf(b), base.log).replica, m, ALL);
        const poison = await scribble(m, poisonAfterRemoval ? [base, byB] : [base], b, {
          sig: m.intro.sig,
        });
        const logs = reversed ? [poison, byB, base] : [base, byB, poison];
        const view = holding(VIEWER, ...logs);
        for (const { label, direct } of viewsOf(a, b)) {
          const t = await computeTrust(view, direct, ALL);
          expect(names(t.trusted), label).toEqual(['A', 'B', 'X']);
          expect(t.removed, label).toEqual([m.id]);
          const s = await deviceStatus(view, b.id, { ...ALL, direct });
          expect(s.reasons, label).not.toContain('key-conflict');
          expect(s.reasons, label).not.toContain('key-mismatch');
        }
      });

      it(`(b) M writes foreign keys into B and X (${when} A removes it, ${reversed ? 'reverse' : 'forward'}): A removes M, B and X stay trusted`, async () => {
        const base = await ledger();
        const byA = await drop(a, base, m, ALL);
        const poisonB = await scribble(m, poisonAfterRemoval ? [byA] : [base], b, {
          sig: m.intro.sig,
        });
        const poisonX = await scribble(
          m,
          poisonAfterRemoval ? [byA, poisonB] : [base, poisonB],
          x,
          { dh: m.intro.dh },
        );
        const logs = reversed ? [poisonX, poisonB, byA] : [byA, poisonB, poisonX];
        const view = holding(VIEWER, ...logs);
        for (const { label, direct } of viewsOf(a, b)) {
          const t = await computeTrust(view, direct, ALL);
          expect(names(t.trusted), label).toEqual(['A', 'B', 'X']);
          expect(t.removed, label).toEqual([m.id]);
          for (const d of [b, x]) {
            const s = await deviceStatus(view, d.id, { ...ALL, direct });
            expect(s.trusted, label).toBe(true);
            expect(s.reasons, label).toEqual([]);
          }
        }
        // the entry of X needs no healing: addDevice writes nothing
        const mine = holding(a, byA, poisonB, poisonX);
        expect(ok(addDevice(mine, { ...ALL, direct: [] }, x.intro, undefined, {}))).toBe(mine);
      });

      it(`(c) M writes removed:true for B and X (${when} A removes it, ${reversed ? 'reverse' : 'forward'}): A removes M, B and X stay trusted`, async () => {
        const base = await ledger();
        const byA = await drop(a, base, m, ALL);
        const marks = await scribble(m, poisonAfterRemoval ? [byA] : [base], b, {
          removed: true,
        });
        const marks2 = await scribble(m, [marks], x, { removed: true });
        const logs = reversed ? [marks2, byA] : [byA, marks2];
        const view = holding(VIEWER, ...logs);
        for (const { label, direct } of viewsOf(a, b)) {
          const t = await computeTrust(view, direct, ALL);
          expect(names(t.trusted), label).toEqual(['A', 'B', 'X']);
          expect(t.removed, label).toEqual([m.id]);
        }
      });
    }
  }

  it('M is removed by nobody: its removals and its foreign keys count while it is trusted (fail closed, inherent to vouching)', async () => {
    const base = await ledger();
    const poison = await scribble(m, [base], b, { sig: m.intro.sig });
    const marks = await scribble(m, [poison], x, { removed: true });
    const t = await computeTrust(holding(VIEWER, base, marks), [known(a)], ALL);
    expect(names(t.trusted)).toEqual(['A', 'M']);
    expect(t.removed).toEqual([x.id]);
    const s = await deviceStatus(holding(VIEWER, base, marks), b.id, {
      ...ALL,
      direct: [known(a)],
    });
    expect(s.reasons).toContain('key-conflict');
  });

  it('removals of equal rank are decided by the smaller id: deliberate and deterministic', async () => {
    // B and M are both entered by A (rank 1) and remove each other: the smaller id acts first and wins
    const base = await ledger();
    const byB = await drop(b, merge(emptyOf(b), base.log).replica, m, ALL);
    const byM = await drop(m, merge(emptyOf(m), base.log).replica, b, ALL);
    expect(b.id < m.id).toBe(true);
    for (const logs of [
      [base, byB, byM],
      [byM, byB, base],
    ]) {
      const t = await computeTrust(holding(VIEWER, ...logs), [known(a)], ALL);
      expect(names(t.trusted)).toEqual(['A', 'B', 'X']);
      expect(t.removed).toEqual([m.id]);
    }
  });

  it('a lower rank acts first: A (met) removes B and B cannot remove A back', async () => {
    const base = await ledger();
    const byA = await drop(a, base, b, ALL);
    const byB = await drop(b, merge(emptyOf(b), base.log).replica, a, ALL);
    const t = await computeTrust(holding(VIEWER, base, byA, byB), [known(a)], ALL);
    expect(names(t.trusted)).toEqual(['A', 'M', 'X']);
    expect(t.removed).toEqual([b.id]);
  });
});

describe('N9: only verified writes count for a removal', () => {
  let a: Dev, b: Dev, x: Dev, wrong: Dev;
  beforeAll(async () => {
    [a, b, x, wrong] = [await dev('A'), await dev('B'), await dev('X'), await dev('W')];
  });

  it('an unverifiable newer removed:true of a voucher does not shadow its valid older one', async () => {
    let base = await enter(a, emptyOf(a), b, undefined, ALL);
    base = await enter(a, base, x, undefined, ALL);
    const mine = merge(emptyOf(b), base.log).replica;
    const two = writeRaw(
      writeRaw(mine, DEVICE_COLLECTION, x.id, { removed: true }),
      DEVICE_COLLECTION,
      x.id,
      {
        removed: true,
      },
    );
    const real = await signed(two, b);
    const bChanges = real.log.filter((c) => c.device === b.id);
    expect(bChanges).toHaveLength(2);
    const second = bChanges[1] as Change;
    const forged = await signChange(APP, wrong.keys.signing.privateKey, second, SET);
    const view = merge(holding(VIEWER, base), [bChanges[0] as Change, forged]).replica;
    const t = await computeTrust(view, [known(a)], ALL);
    expect(t.removed).toEqual([x.id]);
    expect(names(t.trusted)).toEqual(['A', 'B']);
  });
});

describe('N9: an unverifiable removal removes nobody', () => {
  let a: Dev, b: Dev, x: Dev, wrong: Dev;
  beforeAll(async () => {
    [a, b, x, wrong] = [await dev('A'), await dev('B'), await dev('X'), await dev('W')];
  });

  it('a removed:true whose signature does not verify under the voucher key counts for nothing', async () => {
    let base = await enter(a, emptyOf(a), b, undefined, ALL);
    base = await enter(a, base, x, undefined, ALL);
    const mine = writeRaw(merge(emptyOf(b), base.log).replica, DEVICE_COLLECTION, x.id, {
      removed: true,
    });
    const real = await signed(mine, b);
    const forged = await signChange(
      APP,
      wrong.keys.signing.privateKey,
      real.log.find((c) => c.device === b.id) as Change,
      SET,
    );
    const view = merge(holding(VIEWER, base), [forged]).replica;
    const t = await computeTrust(view, [known(a)], ALL);
    expect(t.removed).toEqual([]);
    expect(names(t.trusted)).toEqual(['A', 'B', 'X']);
  });
});

describe('N10: a voucher that withdraws a role later', () => {
  let a: Dev, x: Dev, y: Dev, z: Dev;
  const ADMIN = opts(vouchRoles(['admin']));
  beforeAll(async () => {
    [a, x, y, z] = [await dev('A'), await dev('X'), await dev('Y'), await dev('Z')];
  });

  it('potential trust only grows (a device that joined stays), the voucher flag follows the newest entry; result is order independent', async () => {
    let ra = await enter(a, emptyOf(a), x, 'admin', ADMIN);
    ra = await enter(a, ra, z, 'admin', ADMIN);
    const rx = await enter(x, merge(emptyOf(x), ra.log).replica, y, 'member', ADMIN);
    // Z writes role member into the entry of X, later than A's entry (Z holds A's log only)
    const rz = await scribble(z, [ra], x, { role: 'member' });
    const logs = [ra, rx, rz];
    const results: string[] = [];
    for (const order of [
      logs,
      [...logs].reverse(),
      [logs[1] as Replica, logs[2] as Replica, logs[0] as Replica],
    ]) {
      const t = await computeTrust(holding(VIEWER, ...order), [known(a, 'admin')], ADMIN);
      results.push(JSON.stringify([names(t.trusted), t.trusted.map((d) => d.role)]));
    }
    expect(new Set(results).size).toBe(1);
    const t = await computeTrust(holding(VIEWER, ...logs), [known(a, 'admin')], ADMIN);
    // Y joined while X still vouched and stays; X itself no longer vouches (its newest role is member)
    expect(names(t.trusted)).toEqual(['A', 'X', 'Y', 'Z']);
    expect(t.trusted.find((d) => d.name === 'X')?.role).toBe('member');
  });
});

describe('semantics without a write cut-off: a removed device stays checkable', () => {
  const NOTES = 'notes';
  let a: Dev, b: Dev, r: Dev;
  const O = opts(vouchRoles(['admin']));
  beforeAll(async () => {
    [a, b, r] = [await dev('A'), await dev('B'), await dev('R')];
  });

  const judgeFor = (me: string, direct: KnownDevice[]): JudgeOptions => ({
    appId: APP,
    dataSet: SET,
    ownDevice: me,
    neverErase: deviceNeverErase(),
    keys: deviceKeySource({ ...O, direct }),
  });

  async function talk(x: Replica, y: Replica, jx: JudgeOptions, jy: JudgeOptions) {
    let sx: Step = startSession(x);
    let sy: Step = startSession(y);
    let toX: SyncMessage[] = [...sy.send];
    let toY: SyncMessage[] = [...sx.send];
    for (let guard = 0; guard < 200 && (toX.length > 0 || toY.length > 0); guard += 1) {
      const m = toY.shift();
      if (m) {
        sy = await receiveJudged(sy.session, sy.replica, JSON.parse(JSON.stringify(m)), jy);
        toX = [...toX, ...sy.send];
      }
      const n = toX.shift();
      if (n) {
        sx = await receiveJudged(sx.session, sx.replica, JSON.parse(JSON.stringify(n)), jx);
        toY = [...toY, ...sx.send];
      }
    }
    return { sx, sy };
  }

  it('later changes of a removed device verify and are checked; nothing is ignored', async () => {
    const ra0 = await enter(a, emptyOf(a), r, 'member', O);
    let rr = merge(emptyOf(r), ra0.log).replica;
    for (const id of ['n1', 'n2', 'n3'])
      rr = await signed(writeRaw(rr, NOTES, id, { text: id }), r);
    const ra = await drop(a, ra0, r, O);
    const fromR = rr.log.filter((c) => c.device === r.id);
    const res = await readChanges(
      emptyOf(VIEWER),
      [...ra.log, ...fromR],
      judgeFor(VIEWER, [known(a, 'admin')]),
    );
    expect(res.rejected).toBe(0);
    expect(res.accepted.filter((c) => c.device === r.id).map((c) => c.seq)).toEqual([1, 2, 3]);
    expect('ignored' in res).toBe(false);
    const view = holding(VIEWER, ra, rr);
    expect(await deviceStatus(view, r.id, { ...O, direct: [known(a, 'admin')] })).toEqual({
      trusted: false,
      checkable: true,
      removed: true,
      reasons: ['removed'],
    });
  });

  it('the N2 scenario converges: R wrote two notes, A holds one and removes R, B overwrites naming the second', async () => {
    let ra = await enter(a, emptyOf(a), r, 'member', O);
    ra = await enter(a, ra, b, 'admin', O);
    let rr = merge(emptyOf(r), ra.log).replica;
    rr = await signed(writeRaw(rr, NOTES, 'n1', { text: 'one' }), r);
    rr = await signed(writeRaw(rr, NOTES, 'n1', { text: 'two' }), r);
    const fromR = (rep: Replica) => rep.log.filter((c) => c.device === r.id);
    // A holds R:1 only and removes R
    const holdsOne = merge(ra, fromR(rr).slice(0, 1)).replica;
    const ra2 = await signed(ok(removeDevice(holdsOne, O, r.id, {})), a);
    // B holds all of R, overwrites the field: its change names R:2
    let rb = merge(merge(emptyOf(b), ra.log).replica, fromR(rr)).replica;
    rb = await signed(writeRaw(rb, NOTES, 'n1', { text: 'b' }), b);
    expect(rb.log.at(-1)?.knew).toMatchObject({ [r.id]: 2 });
    const direct = [known(a, 'admin')];
    const { sx, sy } = await talk(ra2, rb, judgeFor(a.id, direct), judgeFor(b.id, direct));
    expect(sx.session.refusal).toBeUndefined();
    expect(sy.session.refusal).toBeUndefined();
    expect(fingerprint(sx.replica)).toBe(fingerprint(sy.replica));
    expect(sx.replica.vector).toEqual(sy.replica.vector);
    expect(sx.replica.vector[r.id]).toBe(2);
    expect(sx.session.waiting).toBe(0);
    expect(sy.session.waiting).toBe(0);
  });

  it('N4 with trust: M signed m:1 twice, A and B hold one version each; the first session refuses, also after M is removed', async () => {
    let base = await enter(a, emptyOf(a), r, 'member', O);
    base = await enter(a, base, b, 'admin', O);
    const mk = () => merge(emptyOf(r), base.log).replica;
    const va = await signed(writeRaw(mk(), NOTES, 'n1', { text: 'version a' }), r);
    const vb = await signed(writeRaw(mk(), NOTES, 'n1', { text: 'version b' }), r);
    const fromR = (rep: Replica) => rep.log.filter((c) => c.device === r.id);
    const removedByA = await drop(a, base, r, O);
    const ra = merge(merge(emptyOf(a), removedByA.log).replica, fromR(va)).replica;
    const rb = merge(merge(emptyOf(b), removedByA.log).replica, fromR(vb)).replica;
    expect(ra.vector).toEqual(rb.vector);
    const direct = [known(a, 'admin')];
    const { sx, sy } = await talk(ra, rb, judgeFor(a.id, direct), judgeFor(b.id, direct));
    for (const s of [sx, sy]) {
      expect(s.session.refusalReason).toBe('equivocation');
      expect(s.session.refusalDevice).toBe(r.id);
    }
  });
});

describe('N5 safety: a key source that checks signatures itself may see what is waiting, nothing else', () => {
  const O = opts(vouchRoles(['admin']));
  let a: Dev, x: Dev, z: Dev;
  beforeAll(async () => {
    [a, x, z] = [await dev('A'), await dev('X'), await dev('Z')];
  });
  const judge = (direct: KnownDevice[]): JudgeOptions => ({
    appId: APP,
    dataSet: SET,
    ownDevice: VIEWER,
    neverErase: deviceNeverErase(),
    keys: deviceKeySource({ ...O, direct }),
  });
  const note = (d: Dev) => signed(writeRaw(emptyOf(d), 'notes', 'n1', { text: 'x' }), d);

  it('an author introduced by a device nobody vouches for stays pending (valid signatures, no chain from a met device)', async () => {
    const byZ = await enter(z, emptyOf(z), x, 'member', O);
    const res = await readChanges(
      emptyOf(VIEWER),
      [...byZ.log, ...(await note(x)).log],
      judge([known(a, 'admin')]),
    );
    expect(res.accepted).toEqual([]);
    expect(res.rejected).toBe(0);
    expect(res.pending).toHaveLength(2);
  });

  it('a chain is read in one go, and a link whose signature is wrong refuses the batch', async () => {
    const byA = await enter(a, emptyOf(a), x, 'admin', O);
    const byX = await enter(x, merge(emptyOf(x), byA.log).replica, z, 'member', O);
    const good = await readChanges(
      emptyOf(VIEWER),
      [...(await note(z)).log, ...byX.log],
      judge([known(a, 'admin')]),
    );
    expect(good.rejected).toBe(0);
    expect(good.accepted).toHaveLength(3);
    const wrong = await signChange(
      APP,
      z.keys.signing.privateKey,
      byX.log[byX.log.length - 1] as Change,
      SET,
    );
    const bad = await readChanges(
      emptyOf(VIEWER),
      [...(await note(z)).log, wrong, ...byA.log],
      judge([known(a, 'admin')]),
    );
    expect(bad.rejected).toBeGreaterThan(0);
    expect(bad.accepted).toEqual([]);
  });

  it("a change that claims the receiver's own id does not vouch for anybody while it waits", async () => {
    // X forges an entry for itself under the viewer's id (signed with its own key), then writes a note
    let rv = writeRaw(emptyOf(VIEWER), DEVICE_COLLECTION, x.id, {
      name: x.intro.name,
      sig: x.intro.sig,
      dh: x.intro.dh,
      role: 'admin',
    });
    rv = await signed(rv, x);
    const res = await readChanges(
      emptyOf(VIEWER),
      [...rv.log, ...(await note(x)).log],
      judge([known(a, 'admin')]),
    );
    expect(res.accepted).toEqual([]);
  });
});
