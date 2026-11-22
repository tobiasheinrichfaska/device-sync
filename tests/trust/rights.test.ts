// Rights at the receiver that look at the batch and the author's role (`JudgeOptions.rights`,
// docs/rights.md), with the real trust layer, real keys and real signatures. The cases are the
// acceptance cases of the earlier implementation's file exchange: the edit of a row another device made
// in the SAME batch, the rule that names the author's role, a removed device that cannot finally delete
// through a device that has not heard of the removal, and a batch that is refused as a whole.
import { beforeAll, describe, expect, it } from 'vitest';
import {
  checkRights,
  emptyReplica,
  findRecord,
  judgeChanges,
  merge,
  readChanges,
  receiveJudged,
  remove,
  startSession,
  write,
  type Change,
  type JudgeOptions,
  type Replica,
  type RightsOptions,
} from '../../src/log/index.ts';
import {
  computeTrustSync,
  deviceKeySource,
  deviceNeverErase,
  rightsView,
  vouchRoles,
  type KnownDevice,
  type TrustView,
} from '../../src/trust/index.ts';
import { APP, SET, dev, drop, emptyOf, enter, known, opts, signed, type Dev } from './helpers.ts';

const O = opts(vouchRoles(['office']));

/** The rule of the earlier implementation, as a rights hook: the office changes all, an LB only its own rows. */
const rule = (
  author: string,
  change: Change,
  state: Replica,
  view: TrustView,
): boolean | string => {
  const role = view.roleOf(author);
  if (role === 'office') return true;
  if (role === undefined || !role.startsWith('lb:')) return 'no-role';
  const person = role.slice(3);
  if (change.kind === 'delete') return 'final-delete-office-only';
  if (change.collection !== 'plan') return 'office-only';
  const owner = change.id.split('|')[2];
  if (owner !== person) return 'other-person';
  const was = findRecord(state, 'plan', change.id)?.fields.lb?.value;
  if (was === undefined && !('lb' in (change.fields ?? {}))) return 'unknown-row';
  if (
    (was !== undefined && was !== person) ||
    (change.fields && 'lb' in change.fields && change.fields.lb !== person)
  ) {
    return 'other-person';
  }
  return true;
};

const rights = (direct: () => readonly KnownDevice[]): RightsOptions<TrustView> => ({
  view: rightsView(direct, O),
  rank: (author, view) => (view.roleOf(author) === 'office' ? 0 : 1),
  mayWrite: rule,
  allowFinalDelete: (author, _c, _s, view) =>
    view.trusted(author) && view.roleOf(author) === 'office' ? true : 'not-office',
});

const judgeFor = (
  receiver: Dev,
  direct: readonly KnownDevice[],
  extra: Partial<JudgeOptions> = {},
): JudgeOptions => ({
  appId: APP,
  dataSet: SET,
  ownDevice: receiver.id,
  neverErase: deviceNeverErase(),
  keys: deviceKeySource({ ...O, direct }),
  ...extra,
});

const put = async (
  d: Dev,
  r: Replica,
  id: string,
  fields: Record<string, unknown>,
): Promise<Replica> => {
  const out = write(r, 'plan', id, fields, { time: 1, by: d.name });
  if (!out.ok) throw new Error(out.reason);
  return signed(out.replica, d);
};

let lb: Dev, office: Dev, other: Dev, recv: Dev;
beforeAll(async () => {
  // the ids sort in this order: lb < office: the LB's id is SMALLER (the earlier test used ids that way)
  lb = await dev('lb-art');
  office = await dev('office');
  other = await dev('office2');
  recv = await dev('receiver');
});

/** The office enters the LB and makes a row; the LB edits that row; a third device holds both logs, nothing before. */
async function sameBatch() {
  let a = await enter(office, emptyOf(office), lb, 'lb:art', O);
  a = await put(office, a, 'Mo|VM1|art', { tag: 'Mo', lb: 'art', stufen: ['1-3'] });
  const c = await put(lb, merge(emptyOf(lb), a.log).replica, 'Mo|VM1|art', { stufen: ['4-6'] });
  const direct = [known(office, 'office'), known(lb, 'lb:art')];
  return { a, c, direct, batch: [...c.log, ...a.log] as Change[] };
}

describe("the earlier implementation's acceptance cases", () => {
  it('an LB edit of a row the office made in the SAME batch passes, whatever the device ids', async () => {
    const { direct, batch } = await sameBatch();
    expect(lb.id < office.id).toBe(true);
    const r = emptyOf(recv);
    const read = await readChanges(
      r,
      batch,
      judgeFor(recv, direct, { rights: rights(() => direct) }),
    );
    expect(read.rejections).toEqual([]);
    expect(read.accepted.length).toBe(batch.length);
    expect(
      merge(r, read.accepted).replica.collections.plan?.['Mo|VM1|art']?.fields.stufen?.value,
    ).toEqual(['4-6']);
  });

  it('without the batch-aware state the same batch is refused (the plain hook sees only the state before)', async () => {
    const { direct, batch } = await sameBatch();
    const plain: JudgeOptions['mayWrite'] = (author, change, state) =>
      rule(author, change, state, {
        roleOf: (d) => (d === office.id ? 'office' : 'lb:art'),
      } as TrustView) === true;
    const read = await readChanges(
      emptyOf(recv),
      batch,
      judgeFor(recv, direct, { mayWrite: plain }),
    );
    expect(read.rejected).toBeGreaterThan(0);
    expect(read.rejections[0]).toMatchObject({ reason: 'not-allowed' });
  });

  it("the order is the app's rank: without one, by device id, the LB edit is asked first and refused with its code", async () => {
    const { direct, batch } = await sameBatch();
    const { rank: _rank, ...noRank } = rights(() => direct);
    const read = await readChanges(
      emptyOf(recv),
      batch,
      judgeFor(recv, direct, { rights: noRank }),
    );
    expect(read.rejections.map((x) => [x.reason, x.detail, x.change.device])).toEqual([
      ['not-allowed', 'unknown-row', lb.id],
    ]);
  });

  it('a row an LB adds in the batch is its own for its next change in it', async () => {
    let a = await enter(office, emptyOf(office), lb, 'lb:art', O);
    const direct = [known(office, 'office'), known(lb, 'lb:art')];
    let c = merge(emptyOf(lb), a.log).replica;
    c = await put(lb, c, 'Di|VM1|art', { tag: 'Di', lb: 'art', stufen: ['1-3'] });
    c = await put(lb, c, 'Di|VM1|art', { stufen: ['4-6'] });
    a = merge(a, []).replica;
    const read = await readChanges(
      emptyOf(recv),
      c.log as Change[],
      judgeFor(recv, direct, { rights: rights(() => direct) }),
    );
    expect(read.rejections).toEqual([]);
    expect(read.accepted.length).toBe(c.log.length);
  });

  it("an LB cannot take another person's fixed slot: the batch is refused as a whole, with the code", async () => {
    const { a, direct } = await sameBatch();
    const c = await put(lb, merge(emptyOf(lb), a.log).replica, 'Mo|VM1|enno', {
      tag: 'Mo',
      lb: 'art',
    });
    const read = await readChanges(
      emptyOf(recv),
      [...a.log, ...c.log.filter((x) => x.device === lb.id)],
      judgeFor(recv, direct, { rights: rights(() => direct) }),
    );
    expect(read.rejected).toBe(1);
    expect(read.accepted).toEqual([]);
    expect(read.rejections[0]).toMatchObject({ reason: 'not-allowed', detail: 'other-person' });
  });

  it('a removed office device cannot finally delete through a device that has not heard of the removal', async () => {
    const o2 = other;
    // office enters office2 and the LB; office2 deletes a row for good; office then removes office2
    let a = await enter(office, emptyOf(office), o2, 'office', O);
    a = await enter(office, a, lb, 'lb:art', O);
    a = await put(office, a, 'Mo|VM1|enno', { tag: 'Mo', lb: 'enno' });
    const atO2 = merge(emptyOf(o2), a.log).replica;
    const del = remove(atO2, 'plan', 'Mo|VM1|enno', { time: 3 });
    if (!del.ok) throw new Error(del.reason);
    const o2log = (await signed(del.replica, o2)).log.filter((x) => x.device === o2.id);
    const aWeg = await drop(office, a, o2, O);
    const direct = [known(office, 'office')];
    const judge = judgeFor(recv, direct, { rights: rights(() => direct) });
    // the receiver has heard of the removal: the deletion is refused with the code, nothing is taken
    const informed = merge(emptyOf(recv), aWeg.log).replica;
    const refused = await readChanges(informed, o2log, judge);
    expect(refused.rejections.map((x) => [x.reason, x.detail])).toEqual([
      ['delete-not-allowed', 'not-office'],
    ]);
    expect(findRecord(informed, 'plan', 'Mo|VM1|enno')?.deleted).toBe(false);
    // the same deletion from an office device that was not removed passes
    const fine = merge(emptyOf(recv), a.log).replica;
    expect((await readChanges(fine, o2log, judge)).rejections).toEqual([]);
    // an LB never deletes for good
    const lbDel = remove(merge(emptyOf(lb), a.log).replica, 'plan', 'Mo|VM1|enno', { time: 3 });
    if (!lbDel.ok) throw new Error(lbDel.reason);
    const lbLog = (await signed(lbDel.replica, lb)).log.filter((x) => x.device === lb.id);
    expect((await readChanges(fine, lbLog, judge)).rejections.map((x) => x.reason)).toEqual([
      'delete-not-allowed',
    ]);
  });

  it('what an LB wrote before it was removed still passes on (the removed device keeps its vouched role for its past)', async () => {
    let a = await enter(office, emptyOf(office), lb, 'lb:art', O);
    const direct = [known(office, 'office')];
    const c = await put(lb, merge(emptyOf(lb), a.log).replica, 'Di|VM1|art', {
      tag: 'Di',
      lb: 'art',
    });
    a = await drop(office, a, lb, O);
    const lbLog = c.log.filter((x) => x.device === lb.id);
    const read = await readChanges(
      merge(emptyOf(recv), a.log).replica,
      lbLog,
      judgeFor(recv, direct, { rights: rights(() => direct) }),
    );
    expect(read.rejections).toEqual([]);
    const view = rightsView(direct, O)(merge(emptyOf(recv), a.log).replica);
    expect(view.roleOf(lb.id)).toBe('lb:art');
    expect(view.trusted(lb.id)).toBe(false);
    expect(view.fallenOut(lb.id)).toBe(true);
  });
});

describe('batch semantics', () => {
  it('the view is built once per judged batch, from the replica with every verified change merged', async () => {
    const { direct, batch } = await sameBatch();
    let built = 0;
    const counted: RightsOptions<TrustView> = {
      ...rights(() => direct),
      view: (b) => {
        built += 1;
        return rightsView(direct, O)(b);
      },
    };
    await readChanges(emptyOf(recv), batch, judgeFor(recv, direct, { rights: counted }));
    expect(built).toBe(1);
  });

  it('the verdict does not depend on the order of the batch or on how it is cut into pieces', async () => {
    const { direct, batch } = await sameBatch();
    const judge = judgeFor(recv, direct, { rights: rights(() => direct) });
    const verdicts: string[] = [];
    for (const order of [batch, [...batch].reverse(), [...batch.slice(1), ...batch.slice(0, 1)]]) {
      const r = await readChanges(emptyOf(recv), order, judge);
      verdicts.push(JSON.stringify([r.rejected, r.accepted.length]));
    }
    expect(new Set(verdicts).size).toBe(1);
    // pieces of a session: one change per piece, the LB's pieces first
    for (const cut of [1, 2, 100]) {
      const sorted = [...batch].sort((x, y) =>
        x.device === lb.id ? -1 : y.device === lb.id ? 1 : 0,
      );
      let step = {
        session: startSession(emptyOf(recv)).session,
        replica: emptyOf(recv),
        send: [] as unknown[],
      };
      for (let i = 0; i < sorted.length; i += cut) {
        const piece = sorted.slice(i, i + cut);
        step = (await receiveJudged(
          step.session,
          emptyOf(recv),
          { t: 'changes', changes: piece, last: i + cut >= sorted.length },
          judge,
        )) as never;
        expect(step.session.refusal, `cut ${cut}`).toBeUndefined();
      }
      expect(step.session.taken).toBe(new Set(batch.map((c) => `${c.device}#${c.seq}`)).size);
    }
  });

  it('judgeChanges applies the stage to the changes that verified, and names the code', async () => {
    const { direct, batch } = await sameBatch();
    const ctx = {
      ...judgeFor(recv, direct, { rights: rights(() => direct) }),
      state: emptyOf(recv),
    };
    expect(await judgeChanges(ctx, batch)).toEqual(batch.map(() => 'checked'));
    const bad = { ...ctx, rights: { ...rights(() => direct), mayWrite: () => 'nope' } };
    expect(await judgeChanges(bad, batch)).toContain('false');
  });

  it('with no rights hook nothing changes: the plain hooks decide as before', async () => {
    const { direct, batch } = await sameBatch();
    const read = await readChanges(
      emptyOf(recv),
      batch,
      judgeFor(recv, direct, { mayWrite: () => true }),
    );
    expect(read.rejections).toEqual([]);
    const noDelete = await readChanges(emptyOf(recv), batch, judgeFor(recv, direct));
    expect(noDelete.rejections).toEqual([]);
  });
});

describe('answers fail closed', () => {
  const base = (): { recv: Replica; change: Change } => ({
    recv: emptyReplica('x'),
    change: {
      device: 'd',
      seq: 1,
      clock: 1,
      collection: 'plan',
      id: 'r',
      kind: 'set',
      fields: { a: 1 },
      knew: {},
    },
  });
  const hooked = (mayWrite: RightsOptions['mayWrite']): RightsOptions => ({
    view: () => 0,
    ...(mayWrite ? { mayWrite } : {}),
  });
  it('a text refuses with that code, false without one, anything else with invalid-rule-answer', () => {
    const { recv: r, change } = base();
    const run = (answer: unknown) =>
      checkRights(
        r,
        [change],
        hooked(() => answer as never),
      ).map((x) => x.detail);
    expect(run(true)).toEqual([]);
    expect(run('why')).toEqual(['why']);
    expect(run(false)).toEqual([undefined]);
    expect(run('')).toEqual(['invalid-rule-answer']);
    expect(run('x'.repeat(121))).toEqual(['invalid-rule-answer']);
    expect(run(0)).toEqual(['invalid-rule-answer']);
    expect(run(null)).toEqual(['invalid-rule-answer']);
    expect(
      checkRights(
        r,
        [change],
        hooked(() => {
          throw new Error('boom');
        }),
      ).map((x) => x.detail),
    ).toEqual(['invalid-rule-answer']);
  });
  it('a view or a rank that throws, or a rank that is not a whole number, refuses everything', () => {
    const { recv: r, change } = base();
    const refused = (o: RightsOptions) => checkRights(r, [change], o).map((x) => x.detail);
    expect(
      refused({
        view: () => {
          throw new Error('x');
        },
      }),
    ).toEqual(['invalid-rule-answer']);
    expect(
      refused({
        view: () => 0,
        rank: () => {
          throw new Error('x');
        },
      }),
    ).toEqual(['invalid-rule-answer']);
    expect(refused({ view: () => 0, rank: () => 0.5 })).toEqual(['invalid-rule-answer']);
    expect(refused({ view: () => 0, rank: () => Number.NaN })).toEqual(['invalid-rule-answer']);
  });
});

describe('cost', () => {
  const batchOf = (n: number, authors: number): Change[] => {
    const seq = new Map<string, number>();
    return Array.from({ length: n }, (_, i): Change => {
      const device = `dev${String(i % authors).padStart(3, '0')}`;
      const s = (seq.get(device) ?? 0) + 1;
      seq.set(device, s);
      return {
        device,
        seq: s,
        clock: i + 1,
        collection: 'plan',
        id: `r${i % 997}`,
        kind: 'set',
        fields: { n: i, who: device },
        knew: {},
      };
    });
  };
  const run = (n: number) => {
    const changes = batchOf(n, 40);
    let calls = 0;
    const o: RightsOptions = {
      view: () => 0,
      mayWrite: (_a, c, state) => {
        calls += 1;
        // reads the state the way a rule does: the record may exist already
        void findRecord(state, c.collection, c.id);
        return true;
      },
    };
    const t = performance.now();
    const refused = checkRights(emptyReplica('recv'), changes, o);
    return { ms: performance.now() - t, refused: refused.length, calls };
  };
  it('is linear in the batch: 8000 changes cost about four times 2000, and the hook is called once per change', () => {
    run(500); // warm up
    const small = Math.min(run(2000).ms, run(2000).ms);
    const big = run(8000);
    expect(big.refused).toBe(0);
    expect(big.calls).toBe(8000);
    expect(big.ms).toBeLessThan(3000);
    expect(big.ms / Math.max(small, 1)).toBeLessThan(12);
  });
  it('the allowed changes are folded: a later hook call sees an earlier change of the batch', () => {
    const seen: unknown[] = [];
    const changes = batchOf(6, 1);
    checkRights(emptyReplica('recv'), changes, {
      view: () => 0,
      mayWrite: (_a, c, state) => {
        seen.push(findRecord(state, c.collection, c.id)?.fields.n?.value);
        return true;
      },
    });
    // r0..r5 are distinct records: nothing seen yet for each; a repeated id sees its predecessor
    expect(seen).toEqual([undefined, undefined, undefined, undefined, undefined, undefined]);
    const twice: Change[] = [
      {
        device: 'd',
        seq: 1,
        clock: 1,
        collection: 'plan',
        id: 'r',
        kind: 'set',
        fields: { n: 1 },
        knew: {},
      },
      {
        device: 'd',
        seq: 2,
        clock: 2,
        collection: 'plan',
        id: 'r',
        kind: 'set',
        fields: { n: 2 },
        knew: { d: 1 },
      },
    ];
    const got: unknown[] = [];
    checkRights(emptyReplica('recv'), twice, {
      view: () => 0,
      mayWrite: (_a, _c, state) => {
        got.push(findRecord(state, 'plan', 'r')?.fields.n?.value);
        return true;
      },
    });
    expect(got).toEqual([undefined, 1]);
  });
});

describe('the synchronous trust', () => {
  it('computeTrustSync is the derivation of the judged log, no signature checked again', async () => {
    const { a } = await sameBatch();
    const t = computeTrustSync(merge(emptyOf(recv), a.log).replica, [known(office, 'office')], O);
    expect(t.trusted.map((d) => d.device).sort()).toEqual([lb.id, office.id].sort());
  });
});
