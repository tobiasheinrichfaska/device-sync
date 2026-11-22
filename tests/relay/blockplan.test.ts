// Blocks reported again and again: once, then daily, 60 days (90 for a device on an old access); the plan
// is read strictly; a round runs against the client. The earlier implementation's cases, re-expressed.
import { describe, expect, it } from 'vitest';
import {
  BLOCK_PLAN,
  RelayClient,
  blockAndNote,
  cleanBlockPlan,
  dueBlocks,
  markReported,
  noteBlock,
  planDay,
  planFromReports,
  readBlockPlan,
  repeatBlocks,
  type BlockPlanEntry,
  type FetchLike,
} from '../../src/relay/index.ts';
import { ALPHA, mintProof, serverForR2 } from './helpers.ts';
import { memoryStore, newSigner } from './helpers-r2.ts';

const G = (n: number): string => `geraet-${String(n).padStart(32, '0')}`;
const DAY_MS = 86_400_000;

describe('blocks reported again: once, then daily, 60 days (90 for a device on an old access)', () => {
  it('a block lasts 60 days, 90 when the blocked device held an old access; the same device again keeps the longer end', () => {
    expect(BLOCK_PLAN.days).toBe(60);
    expect(BLOCK_PLAN.daysOldAccess).toBe(90);
    expect(noteBlock([], { device: G(1), today: '2026-11-21' })).toEqual([
      { device: G(1), since: '2026-11-21', until: '2027-01-20' },
    ]);
    expect(noteBlock([], { device: G(1), today: '2026-11-21', oldAccess: true })).toEqual([
      { device: G(1), since: '2026-11-21', until: '2027-02-19' },
    ]);
    const p = noteBlock([], { device: G(1), today: '2026-11-21', oldAccess: true });
    const again = noteBlock(p, { device: G(1), today: '2026-11-22' });
    expect(again).toHaveLength(1);
    expect(again[0]?.until).toBe('2027-02-19'); // not shortened
  });

  it('at a start every block that has not run out is due; during the run only those not yet reported today', () => {
    let plan = [1, 2, 3].reduce<BlockPlanEntry[]>(
      (p, n) => noteBlock(p, { device: G(n), today: '2026-11-21' }),
      [],
    );
    expect(dueBlocks(plan, { today: '2026-11-21' })).toEqual([G(1), G(2), G(3)]);
    plan = markReported(plan, [G(1), G(2)], '2026-11-21');
    expect(dueBlocks(plan, { today: '2026-11-21' })).toEqual([G(3)]);
    expect(dueBlocks(plan, { today: '2026-11-21', start: true }).sort()).toEqual([
      G(1),
      G(2),
      G(3),
    ]);
    expect(dueBlocks(plan, { today: '2026-11-22' }).sort()).toEqual([G(1), G(2), G(3)]);
  });

  it('the longest unreported first, at most 25 a round (the relay takes 30 an hour)', () => {
    expect(BLOCK_PLAN.perRound).toBe(25);
    let plan = Array.from({ length: 30 }, (_, i) => i + 1).reduce<BlockPlanEntry[]>(
      (p, n) => noteBlock(p, { device: G(n), today: '2026-11-21' }),
      [],
    );
    plan = markReported(plan, [G(1)], '2026-11-20');
    const due = dueBlocks(plan, { today: '2026-11-21', start: true });
    expect(due).toHaveLength(25);
    expect(due).not.toContain(G(1)); // reported yesterday: after the ones never reported
    expect(dueBlocks(plan, { today: '2026-11-21', start: true, max: 3 })).toHaveLength(3);
  });

  it('a block that ran out is dropped: on its last day it still counts', () => {
    const plan = noteBlock([], { device: G(1), today: '2026-11-21' }); // until 2027-01-20
    expect(dueBlocks(plan, { today: '2027-01-20', start: true })).toEqual([G(1)]);
    expect(dueBlocks(plan, { today: '2027-01-21', start: true })).toEqual([]);
    expect(cleanBlockPlan(plan, '2027-01-21')).toEqual([]);
    expect(cleanBlockPlan(plan, '2027-01-20')).toEqual(plan);
  });

  it('the stored plan is read strictly: a damaged entry is dropped, never trusted', () => {
    const good = { device: G(1), since: '2026-11-21', until: '2027-01-20', last: '2026-11-22' };
    expect(readBlockPlan([good, good, { ...good, device: G(2), last: undefined }])).toEqual([
      good,
      { device: G(2), since: '2026-11-21', until: '2027-01-20' },
    ]);
    expect(
      readBlockPlan([
        { ...good, device: 'x' },
        { ...good, since: 'yesterday' },
        { ...good, until: 5 },
        { ...good, last: 'x' },
        { ...good, since: '2026-02-30' },
        { ...good, extra: 1 },
        null,
        'x',
        [],
      ]),
    ).toEqual([]);
    expect(readBlockPlan('x')).toEqual([]);
    expect(readBlockPlan(undefined)).toEqual([]);
    expect(
      readBlockPlan(Array.from({ length: 700 }, (_, i) => ({ ...good, device: G(i + 1) }))),
    ).toHaveLength(BLOCK_PLAN.maxEntries);
  });

  it('the plan is bounded: the 501st block pushes the oldest out', () => {
    let plan: BlockPlanEntry[] = [];
    for (let i = 1; i <= 501; i += 1) plan = noteBlock(plan, { device: G(i), today: '2026-11-21' });
    expect(plan).toHaveLength(500);
    expect(plan[0]?.device).toBe(G(2));
  });

  it('reports of other devices are taken like own blocks: from the day of the block, the longer end, never a day in the future', () => {
    const plan = planFromReports(
      [],
      [
        { device: G(1), since: '2026-11-10' },
        { device: G(2), since: '2026-12-30' }, // a wrong clock: counts as today
        { device: G(3), since: '2026-01-01' }, // ran out
        { device: G(4), since: '2026-10-01', oldAccess: true },
        { device: 'x', since: '2026-11-10' },
        { device: G(5), since: 'nope' },
      ],
      '2026-11-21',
    );
    expect(plan).toEqual([
      { device: G(1), since: '2026-11-10', until: '2027-01-09' },
      { device: G(2), since: '2026-11-21', until: '2027-01-20' },
      { device: G(4), since: '2026-10-01', until: '2026-12-30' },
    ]);
    const kept = planFromReports(
      markReported(noteBlock([], { device: G(1), today: '2026-11-15' }), [G(1)], '2026-11-20'),
      [{ device: G(1), since: '2026-11-10' }],
      '2026-11-21',
    );
    expect(kept).toEqual([
      { device: G(1), since: '2026-11-10', until: '2027-01-14', last: '2026-11-20' },
    ]);
  });
});

describe('blocking and its repetition against the relay', () => {
  const T0 = Date.UTC(2026, 10, 21, 12);

  async function office(net?: (inner: FetchLike) => FetchLike) {
    const server = serverForR2({ now: () => clock.ms });
    const clock = { ms: T0 };
    const { signer } = await newSigner();
    let active: FetchLike | undefined;
    const client = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: ALPHA.app,
      origin: ALPHA.origin,
      fetch: (u, i) => (active ?? server.fetch)(u, i),
      store: memoryStore(),
      clock: () => clock.ms,
      signer,
      maxAttempts: 1,
    });
    const r = await client.enrol({ proof: await mintProof('alpha', clock.ms), role: 'buero' });
    if (!r.ok) throw new Error(r.kind);
    if (net) active = net(server.fetch);
    return {
      client,
      clock,
      server,
      own: r.value.device,
      setNet: (n: FetchLike | undefined) => (active = n),
    };
  }

  it('blocking sends the id, notes the block (60 days, 90 for an old access) and marks it reported', async () => {
    const { client } = await office();
    const a = await blockAndNote(client, [], G(7), { today: planDay(T0) });
    expect(a.result.ok).toBe(true);
    expect(a.plan).toEqual([
      { device: G(7), since: '2026-11-21', until: '2027-01-20', last: '2026-11-21' },
    ]);
    const b = await blockAndNote(client, a.plan, G(8), { today: planDay(T0), oldAccess: true });
    expect(b.plan.find((e) => e.device === G(8))?.until).toBe('2027-02-19');
  });

  it('the note is made first: a block the net did not take is repeated by the next round', async () => {
    const { client, clock, setNet } = await office();
    setNet(() => Promise.reject(new TypeError('offline')));
    const r = await blockAndNote(client, [], G(7), { today: planDay(T0) });
    expect(r.result.ok).toBe(false);
    expect(r.plan).toEqual([{ device: G(7), since: '2026-11-21', until: '2027-01-20' }]);
    setNet(undefined);
    const again = await repeatBlocks(client, r.plan, { today: planDay(clock.ms) });
    expect(again.reported).toBe(1);
    expect(again.plan[0]?.last).toBe('2026-11-21');
  });

  it('at a start all are reported again; during the run only once a day; after 60 days nothing', async () => {
    const { client, clock } = await office();
    let { plan } = await blockAndNote(client, [], G(7), { today: planDay(T0) });
    const round = async (start: boolean) => {
      const r = await repeatBlocks(client, plan, { today: planDay(clock.ms), start });
      plan = r.plan;
      return r.reported;
    };
    expect(await round(false)).toBe(0); // reported today already
    expect(await round(true)).toBe(1); // a start: again
    clock.ms = T0 + DAY_MS;
    expect(await round(false)).toBe(1); // the next day
    expect(await round(false)).toBe(0);
    clock.ms = T0 + 31 * DAY_MS;
    expect((await client.renew()).ok).toBe(true); // a certificate lives 60 days and is renewed from day 30
    expect(await round(false)).toBe(1);
    clock.ms = T0 + 60 * DAY_MS; // the last day still counts
    expect(await round(true)).toBe(1);
    clock.ms = T0 + 61 * DAY_MS;
    expect(await round(true)).toBe(0);
    expect(plan).toEqual([]);
  });

  it('a refusal for lack of rights counts as reported (it would be the same again); a failure of the net ends the round and the rest follows', async () => {
    const { client, clock, setNet } = await office();
    let plan: BlockPlanEntry[] = [];
    for (const n of [7, 8])
      plan = (await blockAndNote(client, plan, G(n), { today: planDay(T0) })).plan;
    clock.ms = T0 + DAY_MS;
    setNet((_u, init) => {
      const body = JSON.parse(init.body as string) as { geraet: string };
      return Promise.resolve(
        body.geraet === G(7)
          ? new Response(JSON.stringify({ fehler: 'x', art: 'rolle-nicht-erlaubt' }), {
              status: 403,
              headers: { 'Content-Type': 'application/json' },
            })
          : new Response(JSON.stringify({ geraet: body.geraet, gesperrt: true }), {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }),
      );
    });
    const first = await repeatBlocks(client, plan, { today: planDay(clock.ms), start: true });
    expect(first.reported).toBe(1);
    expect(first.plan.every((e) => e.last === planDay(clock.ms))).toBe(true);
    // now the net is down: the round ends at the first failure, nothing is marked, the rest stays open
    setNet(() => Promise.reject(new TypeError('offline')));
    clock.ms = T0 + 2 * DAY_MS;
    const down = await repeatBlocks(client, first.plan, { today: planDay(clock.ms) });
    expect(down.reported).toBe(0);
    expect(down.open).toBe(2);
  });

  it('at most 25 a round (the relay takes 30 an hour); the rest at the next round', async () => {
    const { client, clock, server } = await office();
    server.control.setLimits({ blocksPerHour: 1000, blocklistPerGroup: 1000 });
    let plan: BlockPlanEntry[] = [];
    for (let i = 1; i <= 30; i += 1) plan = noteBlock(plan, { device: G(i), today: planDay(T0) });
    clock.ms = T0 + DAY_MS;
    const r = await repeatBlocks(client, plan, { today: planDay(clock.ms), start: true });
    expect(r.reported).toBe(25);
    expect(r.open).toBe(5);
    expect((await repeatBlocks(client, r.plan, { today: planDay(clock.ms) })).reported).toBe(5);
  });

  it('blocking itself: nothing is noted and nothing is repeated (a blocked device cannot report)', async () => {
    const { client, own } = await office();
    const r = await blockAndNote(client, [], own, { today: planDay(T0) });
    expect(r.result.ok).toBe(true);
    expect(r.plan).toEqual([]);
    expect(await client.state()).toBe('blocked');
  });

  it("the relay's refusal is handed back as it is (a member's device may not block an office device)", async () => {
    const server = serverForR2();
    const mk = async (role: string) => {
      const { signer } = await newSigner();
      const c = new RelayClient({
        baseUrl: 'https://relay.test',
        appId: 'alpha',
        origin: ALPHA.origin,
        fetch: server.fetch,
        store: memoryStore(),
        clock: server.now,
        signer,
      });
      const r = await c.enrol({ proof: await mintProof('alpha', server.now()), role });
      if (!r.ok) throw new Error(r.kind);
      return { c, id: r.value.device };
    };
    const o = await mk('buero');
    const m = await mk('lb:art');
    const r = await blockAndNote(m.c, [], o.id, { today: planDay(server.now()) });
    expect(r.result).toMatchObject({ ok: false, kind: 'role-not-allowed' });
    // the block stays noted (the note is made first); the round counts the refusal as reported
    const round = await repeatBlocks(m.c, r.plan, { today: planDay(server.now()), start: true });
    expect(round.reported).toBe(0);
    expect(round.plan[0]?.last).toBe(planDay(server.now()));
  });
});
