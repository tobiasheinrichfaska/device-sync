// Several data sets and the mailbox in the sync driver: three devices, real keys and signatures, the
// real trust layer, the repository's reference relay. Two devices that are never online together
// converge through the third (envelopes, mailbox, receipts); a set only some devices may read is
// never sent to the others; a hostile peer's envelopes and packets are refused.
import { describe, expect, it } from 'vitest';
import { sealEnvelope, openEnvelope, sealFile, type Envelope } from '../../src/core/index.ts';
import { FRAMING_LIMITS, splitPayload } from '../../src/relay/index.ts';
import { channelKeys, openChannel, sealChannel } from '../../src/channel/index.ts';
import { emptyReplica, write, type Replica } from '../../src/log/index.ts';
import {
  EMPTY_MAILBOX,
  addEnvelopes,
  receiptsOf,
  writeReceiptRecord,
  type Mailbox,
} from '../../src/post/index.ts';
import {
  syncOnce,
  totals,
  type PostConfig,
  type SetConfig,
  type SyncReport,
} from '../../src/sync/index.ts';
import { APP, chaotic, prng, world, type Member, type World } from './helpers.ts';

const PLAN = 'plan';
const CH = 'times:c';

interface Node {
  readonly m: Member;
  sets: Record<string, Replica>;
  mailbox: Mailbox;
  reports: SyncReport[];
}

const day = (w: World): string => new Date(w.now()).toISOString().slice(0, 10);

function nodes(w: World, sets: Record<string, SetConfig>, post: PostConfig | undefined): Node[] {
  return w.members.map((m) => {
    m.config = { ...m.config, sets, ...(post ? { post } : {}) };
    return { m, sets: {}, mailbox: EMPTY_MAILBOX, reports: [] };
  });
}

async function stepNode(w: World, n: Node): Promise<SyncReport> {
  const res = await syncOnce(n.m.config, n.m.state, n.m.replica, w.now(), {
    sets: n.sets,
    mailbox: n.mailbox,
  });
  if (!res.ok) throw new Error(res.reason);
  n.m.replica = res.replica;
  n.sets = { ...res.sets };
  n.mailbox = res.mailbox;
  n.reports.push(res.report);
  return res.report;
}

async function run(w: World, list: readonly Node[], times: number): Promise<void> {
  for (let i = 0; i < times; i += 1) {
    for (const n of list) await stepNode(w, n);
    w.advance(1000);
  }
}

const put = (
  n: Node,
  set: string,
  collection: string,
  id: string,
  fields: Record<string, unknown>,
) => {
  const r = write(n.sets[set] ?? emptyReplica(n.m.id), collection, id, fields, { time: 1 });
  if (!r.ok) throw new Error(r.reason);
  n.sets = { ...n.sets, [set]: r.replica };
};
const val = (n: Node, set: string, collection: string, id: string, f: string): unknown =>
  n.sets[set]?.collections[collection]?.[id]?.fields[f]?.value;

describe('several data sets', () => {
  it('every registered set converges between the devices that may exchange it', async () => {
    const w = await world(['A', 'B', 'C']);
    const [a, b, c] = nodes(w, { [PLAN]: {}, other: {} }, undefined) as [Node, Node, Node];
    put(a, PLAN, 'rows', 'r1', { v: 'one' });
    put(c, 'other', 'rows', 'r2', { v: 'two' });
    await run(w, [a, b, c], 10);
    for (const n of [a, b, c]) {
      expect(val(n, PLAN, 'rows', 'r1', 'v')).toBe('one');
      expect(val(n, 'other', 'rows', 'r2', 'v')).toBe('two');
    }
    expect(Object.keys(a.m.replica.vector).length).toBeGreaterThan(0);
  });

  it('a set a peer may not read is never sent to it, asked of it or taken from it', async () => {
    const w = await world(['A', 'B', 'C']);
    const [a, b, c] = nodes(
      w,
      {
        [PLAN]: {},
        secret: {
          // only A and B exchange it
          mayExchange: (peer) => peer.device !== (w.members[2] as Member).id,
        },
      },
      undefined,
    ) as [Node, Node, Node];
    // C does not register the rule for itself (its own hook says nobody but it)
    c.m.config = {
      ...c.m.config,
      sets: { [PLAN]: {}, secret: { mayExchange: () => false } },
    };
    put(a, 'secret', 'rows', 's1', { v: 'for B' });
    put(c, 'secret', 'rows', 's2', { v: 'from C' });
    await run(w, [a, b, c], 12);
    expect(val(b, 'secret', 'rows', 's1', 'v')).toBe('for B');
    expect(val(a, 'secret', 'rows', 's2', 'v')).toBeUndefined();
    expect(val(b, 'secret', 'rows', 's2', 'v')).toBeUndefined();
    expect(val(c, 'secret', 'rows', 's1', 'v')).toBeUndefined();
    // the asks C sends for it and the answers it would get are refused at A and B, never merged
    expect(Object.keys(c.sets.secret?.vector ?? {})).toEqual([c.m.id]);
  });

  it('a packet for a set that is not registered is dropped as unknown-set', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = nodes(w, { [PLAN]: {}, extra: {} }, undefined) as [Node, Node];
    b.m.config = { ...b.m.config, sets: { [PLAN]: {} } };
    put(a, 'extra', 'rows', 'x', { v: 1 });
    await run(w, [a, b], 6);
    expect(totals(b.m.state)['unknown-set'] ?? 0).toBeGreaterThan(0);
    expect(b.sets.extra).toBeUndefined();
  });

  it('refuses a registry with a bad name, the main set name or a replica of another device', async () => {
    const w = await world(['A', 'B']);
    const m = w.members[0] as Member;
    const call = (cfg: object, held = {}) =>
      syncOnce({ ...m.config, ...cfg }, m.state, m.replica, w.now(), held);
    expect(await call({ sets: { 'bad name': {} } })).toEqual({ ok: false, reason: 'bad-input' });
    expect(await call({ sets: { main: {} } })).toEqual({ ok: false, reason: 'bad-input' });
    expect(await call({ sets: { x: {} } }, { sets: { y: emptyReplica(m.id) } })).toEqual({
      ok: false,
      reason: 'bad-input',
    });
    expect(await call({ sets: { x: {} } }, { sets: { x: emptyReplica('someone-else') } })).toEqual({
      ok: false,
      reason: 'bad-input',
    });
  });
});

describe('envelopes and the mailbox over a relay that keeps a message 30 seconds', () => {
  const setup = async () => {
    const w = await world(['A', 'B', 'C']);
    const [a, b, c] = w.members as [Member, Member, Member];
    const post: PostConfig = {
      receipts: (sets) => {
        const plan = sets.get(PLAN);
        return plan ? receiptsOf(plan) : [];
      },
      mayAcknowledge: (by) => by === c.id,
    };
    const list = nodes(w, { [PLAN]: {} }, post) as [Node, Node, Node];
    return { w, a, b, c, list, post };
  };

  it('A and C are never online together: B carries the envelope, C opens it, the receipt clears it', async () => {
    const { w, list } = await setup();
    const [A, B, C] = list;
    // A writes the channel for C and seals it
    let ch = emptyReplica(A.m.id);
    const r = write(ch, 'times', 't1', { text: 'monday 8-16' }, { time: 1 });
    if (!r.ok) throw new Error(r.reason);
    ch = r.replica;
    const sealed = await sealChannel({
      appId: APP,
      author: { device: A.m.id, signing: A.m.keys.signing.privateKey },
      channel: CH,
      replica: ch,
      readers: [C.m.intro.dh],
      day: day(w),
      random: (n) => crypto.getRandomValues(new Uint8Array(n)),
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    expect(sealed.envelopes.length).toBe(1);
    const added = addEnvelopes(APP, A.mailbox, sealed.envelopes, day(w));
    if (!added.ok) throw new Error(added.reason);
    A.mailbox = added.mailbox;

    // phase 1: A and B are online, C is not
    await run(w, [A, B], 10);
    expect(B.mailbox.items.map((e) => e.id)).toEqual(sealed.envelopes.map((e) => e.id));
    expect(C.mailbox.items.length).toBe(0);

    // the relay forgets everything after 30 s; phase 2: B and C are online, A is not
    w.advance(60_000);
    await run(w, [B, C], 10);
    expect(C.mailbox.items.length).toBe(1);
    expect(C.reports.flatMap((x) => x.received).length).toBe(1);

    // C opens it with its own keys; the author is vouched by the device list
    const trust = C.reports[C.reports.length - 1]!.trust;
    const keys = channelKeys(trust, { device: C.m.id, publicKey: C.m.keys.signing.publicKey });
    const opened = await openChannel({
      appId: APP,
      own: { device: C.m.id, agreements: [C.m.keys.agreement] },
      envelopes: C.mailbox.items,
      authorKey: keys.authorKey,
      keys: keys.keys,
      mayWrite: (d, ch) => d === A.m.id && ch === CH,
    });
    expect(opened.rejected).toEqual([]);
    expect(opened.taken.length).toBe(1);
    expect(opened.replicas[CH]?.collections.times?.t1?.fields.text?.value).toBe('monday 8-16');

    // C writes its receipt into the plan set; it travels C → B → A like any data
    const receipt = writeReceiptRecord(C.sets[PLAN] ?? emptyReplica(C.m.id), opened.taken, day(w), {
      time: 2,
    });
    if (!receipt.ok) throw new Error(receipt.reason);
    C.sets = { ...C.sets, [PLAN]: receipt.replica };
    await run(w, [B, C], 8);
    // B holds the receipt, C is an allowed acknowledger: B drops the envelope it carried
    expect(B.mailbox.items.length).toBe(0);
    expect(B.reports.some((x) => x.acknowledged > 0)).toBe(true);

    // A comes back: it gets the receipt through B and drops its own copy; nobody hands it back
    w.advance(60_000);
    await run(w, [A, B], 10);
    expect(A.mailbox.items.length).toBe(0);
    expect(B.mailbox.items.length).toBe(0);
    // C acknowledged its own envelope too (its receipt covers it), so no copy is left anywhere
    expect(C.mailbox.items.length).toBe(0);
    // and the plan converged without C and A ever meeting
    expect(JSON.stringify(Object.entries(A.sets[PLAN]?.vector ?? {}).sort())).toBe(
      JSON.stringify(Object.entries(B.sets[PLAN]?.vector ?? {}).sort()),
    );
  });

  it('without envelope traffic configured, packets of the mailbox are dropped and the mailbox is untouched', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = nodes(w, {}, { mayAcknowledge: () => false }) as [Node, Node];
    b.m.config = { ...b.m.config, post: undefined } as never;
    delete (b.m.config as { post?: unknown }).post;
    const sealed = await sealEnvelope({
      appId: APP,
      author: { device: a.m.id, signing: a.m.keys.signing.privateKey },
      recipients: [b.m.intro.dh],
      channel: 'x',
      day: day(w),
      body: new Uint8Array([1, 2, 3]),
      random: (n) => crypto.getRandomValues(new Uint8Array(n)),
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    const added = addEnvelopes(APP, a.mailbox, [sealed.envelope], day(w));
    if (added.ok) a.mailbox = added.mailbox;
    await run(w, [a, b], 8);
    expect(b.mailbox.items.length).toBe(0);
    expect(totals(b.m.state)['post-disabled'] ?? 0).toBeGreaterThan(0);
  });

  it('a mailbox larger than one exchange moves in several rounds, newest first, and settles', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = nodes(w, {}, { mayAcknowledge: () => false }) as [Node, Node];
    const made: Envelope[] = [];
    for (let i = 0; i < 130; i += 1) {
      const s = await sealEnvelope({
        appId: APP,
        author: { device: a.m.id, signing: a.m.keys.signing.privateKey },
        recipients: [b.m.intro.dh],
        channel: 'bulk',
        day: day(w),
        body: new Uint8Array([i & 255, i >> 8]),
        random: (n) => crypto.getRandomValues(new Uint8Array(n)),
      });
      if (!s.ok) throw new Error(s.reason);
      made.push(s.envelope);
    }
    const added = addEnvelopes(APP, a.mailbox, made, day(w));
    if (!added.ok) throw new Error(added.reason);
    a.mailbox = added.mailbox;
    await run(w, [a, b], 30);
    // b took what a could offer per exchange (the newest 100 of the view, bounded by the supplier's quota of 400)
    expect(b.mailbox.items.length).toBeGreaterThanOrEqual(100);
    for (const e of b.mailbox.items) expect(made.some((m) => m.id === e.id)).toBe(true);
    // a settled mailbox is quiet: no more asks while neither side changes
    const framesBefore = a.reports.reduce((n, r) => n + r.framesSent, 0);
    await run(w, [a, b], 3);
    const framesAfter = a.reports.reduce((n, r) => n + r.framesSent, 0);
    expect(framesAfter - framesBefore).toBeLessThanOrEqual(3);
  });

  it('an envelope for a device that is not a reader cannot be opened by the carrier', async () => {
    const { w, list } = await setup();
    const [A, B, C] = list;
    const s = await sealEnvelope({
      appId: APP,
      author: { device: A.m.id, signing: A.m.keys.signing.privateKey },
      recipients: [C.m.intro.dh],
      channel: CH,
      day: day(w),
      body: new Uint8Array([9]),
      random: (n) => crypto.getRandomValues(new Uint8Array(n)),
    });
    if (!s.ok) throw new Error(s.reason);
    const added = addEnvelopes(APP, A.mailbox, [s.envelope], day(w));
    if (added.ok) A.mailbox = added.mailbox;
    await run(w, [A, B], 8);
    const carried = B.mailbox.items[0] as Envelope;
    const out = await openEnvelope({
      appId: APP,
      own: { agreement: B.m.keys.agreement },
      envelope: carried,
      authorKey: () => A.m.intro.sig,
    });
    expect(out).toEqual({ ok: false, reason: 'not-for-me' });
  });
});

describe('seeded schedules: sets and mailboxes converge through a hostile relay', () => {
  const batch = async (from: number, to: number): Promise<void> => {
    for (let seed = from; seed < to; seed += 1) {
      const r = prng(seed * 6007 + 3);
      const chaos = {
        loseDrop: r() * 0.2,
        duplicate: r() * 0.3,
        reorder: r() * 0.4,
        loseCollect: r() * 0.2,
        forgeFrom: r() * 0.1,
      };
      const rnd = prng(seed + 500);
      let ids: string[] = [];
      const w = await world(['A', 'B', 'C'], {
        seed,
        relayWrap: (m) => chaotic(m, rnd, chaos, () => ids),
      });
      ids = w.members.map((m) => m.relayId);
      const list = nodes(w, { [PLAN]: {}, other: {} }, {}) as [Node, Node, Node];
      const made: Envelope[] = [];
      for (let i = 0; i < 28; i += 1) {
        const n = list[Math.floor(r() * 3)] as Node;
        const roll = r();
        if (roll < 0.35) put(n, PLAN, 'rows', `p${seed}-${i}`, { v: i });
        else if (roll < 0.6) put(n, 'other', 'rows', `o${seed}-${i}`, { v: i });
        else if (roll < 0.75 && made.length < 12) {
          const reader = list[Math.floor(r() * 3)] as Node;
          const s = await sealEnvelope({
            appId: APP,
            author: { device: n.m.id, signing: n.m.keys.signing.privateKey },
            recipients: [reader.m.intro.dh],
            channel: 'bulk',
            day: day(w),
            body: new Uint8Array([i]),
            random: (k) => crypto.getRandomValues(new Uint8Array(k)),
          });
          if (!s.ok) throw new Error(s.reason);
          const box = addEnvelopes(APP, n.mailbox, [s.envelope], day(w));
          if (box.ok) {
            n.mailbox = box.mailbox;
            made.push(s.envelope);
          }
        }
        for (const x of list.filter(() => r() < 0.6)) await stepNode(w, x);
        w.advance(r() < 0.15 ? 40_000 : 1000);
      }
      // calm: an honest relay, everybody steps until nothing changes
      const honest = w.members.map((m) => m.client);
      list.forEach((n, i) => {
        n.m.config = { ...n.m.config, relay: honest[i] as never };
      });
      const key = (n: Node): string =>
        JSON.stringify([
          Object.entries(n.m.replica.vector).sort(),
          Object.entries(n.sets[PLAN]?.vector ?? {}).sort(),
          Object.entries(n.sets.other?.vector ?? {}).sort(),
          n.mailbox.items.map((e) => e.id).sort(),
        ]);
      for (let i = 0; i < 80; i += 1) {
        await run(w, list, 1);
        if (
          key(list[0] as Node) === key(list[1] as Node) &&
          key(list[0] as Node) === key(list[2] as Node)
        ) {
          break;
        }
      }
      const [a, b, c] = list as [Node, Node, Node];
      expect(key(b), `seed ${seed}`).toBe(key(a));
      expect(key(c), `seed ${seed}`).toBe(key(a));
      expect(a.mailbox.items.map((e) => e.id).sort(), `seed ${seed}`).toEqual(
        made.map((e) => e.id).sort(),
      );
      for (const n of list) {
        expect(totals(n.m.state)['round-refused'] ?? 0, `seed ${seed}`).toBe(0);
        expect(totals(n.m.state)['diverged'] ?? 0, `seed ${seed}`).toBe(0);
      }
    }
  };
  for (let k = 0; k < 40; k += 20) {
    it(`seeds ${k} to ${k + 19}`, () => batch(k, k + 20), 120_000);
  }
});

describe('hostile packets from a trusted peer', () => {
  async function inject(w: World, from: Member, to: Member, payload: Uint8Array): Promise<void> {
    const sealed = await sealFile({
      appId: APP,
      own: { device: from.id, agreement: from.keys.agreement },
      to: { device: to.id, dh: to.intro.dh },
      payload,
      random: crypto.getRandomValues(new Uint8Array(12)),
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    const id = Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) =>
      b.toString(16).padStart(2, '0'),
    ).join('');
    const split = splitPayload(APP, sealed.file, id, FRAMING_LIMITS);
    if (!split.ok) throw new Error(split.reason);
    for (const frame of split.frames) {
      const out = await from.client.drop([{ device: to.relayId, content: frame }]);
      if (!out.ok) throw new Error(out.kind);
    }
    void w;
  }
  const enc = (t: string): Uint8Array => new TextEncoder().encode(t);
  const mark = `${APP}-sync:2`;
  const postMark = `${APP}-post:2`;

  it('a mailbox message that does not open an exchange, junk, an unknown set and a bad round are dropped by code', async () => {
    const w = await world(['A', 'B']);
    const [A, B] = nodes(w, { [PLAN]: {} }, {}) as [Node, Node];
    const round = '0123456789abcdef';
    // an ids message with no exchange behind it
    await inject(
      w,
      B.m,
      A.m,
      enc(
        `{"m":"${mark}","r":"${round}","post":${JSON.stringify(`{"m":"${postMark}","t":"ids","ids":["AAAAAAAAAAAAAAAAAAAAAA"],"last":true}`)}}`,
      ),
    );
    // text that is no mailbox message
    await inject(w, B.m, A.m, enc(`{"m":"${mark}","r":"${round}","post":"hello"}`));
    // a log packet for a set nobody registered
    await inject(
      w,
      B.m,
      A.m,
      enc(`{"m":"${mark}","r":"${round}","s":"nothing","msg":{"t":"stand","vector":{},"tips":{}}}`),
    );
    // another member list, a bad round id, a set name of another spelling
    await inject(
      w,
      B.m,
      A.m,
      enc(`{"m":"${mark}","r":"${round}","s":"a","msg":{"t":"stand"},"x":1}`),
    );
    await inject(
      w,
      B.m,
      A.m,
      enc(`{"m":"${mark}","r":"XYZ","s":"plan","msg":{"t":"stand","vector":{},"tips":{}}}`),
    );
    await inject(
      w,
      B.m,
      A.m,
      enc(
        `{"m":"${mark}","r":"${round}","s":"bad name","msg":{"t":"stand","vector":{},"tips":{}}}`,
      ),
    );
    await stepNode(w, A);
    const t = totals(A.m.state);
    expect(t['stale-round']).toBe(1);
    expect(t['bad-packet']).toBe(4);
    expect(t['unknown-set']).toBe(1);
    expect(A.mailbox.items.length).toBe(0);
  });

  it('a message out of order ends the exchange with post-refused and changes nothing; a late one is stale', async () => {
    const w = await world(['A', 'B']);
    const [A, B] = nodes(w, { [PLAN]: {} }, {}) as [Node, Node];
    const round = 'fedcba9876543210';
    const days = JSON.stringify(`{"m":"${postMark}","t":"days","days":{}}`);
    await inject(w, B.m, A.m, enc(`{"m":"${mark}","r":"${round}","post":${days}}`));
    await inject(w, B.m, A.m, enc(`{"m":"${mark}","r":"${round}","post":${days}}`));
    // an `envelopes` message before `ids`
    const early = JSON.stringify(`{"m":"${postMark}","t":"envelopes","envelopes":[],"last":true}`);
    await inject(w, B.m, A.m, enc(`{"m":"${mark}","r":"${round}","post":${early}}`));
    await stepNode(w, A);
    const t = totals(A.m.state);
    // the second opening is a message out of order in the open exchange: it ends it; the late
    // `envelopes` then belongs to no exchange
    expect(t['post-refused']).toBe(1);
    expect(t['stale-round']).toBe(1);
    expect(A.mailbox.items.length).toBe(0);
  });

  it('forged envelopes brought by a trusted carrier stay in the mailbox as opaque text and are never opened as another author', async () => {
    const w = await world(['A', 'B', 'C']);
    const [A, B, C] = nodes(w, { [PLAN]: {} }, {}) as [Node, Node, Node];
    // B (a carrier) sealed an envelope as itself for C; claims nothing about A
    const s = await sealEnvelope({
      appId: APP,
      author: { device: B.m.id, signing: B.m.keys.signing.privateKey },
      recipients: [C.m.intro.dh],
      channel: CH,
      day: day(w),
      body: new Uint8Array([1, 2]),
      random: (k) => crypto.getRandomValues(new Uint8Array(k)),
    });
    if (!s.ok) throw new Error(s.reason);
    const box = addEnvelopes(APP, B.mailbox, [s.envelope], day(w));
    if (box.ok) B.mailbox = box.mailbox;
    await run(w, [A, B, C], 10);
    expect(C.mailbox.items.length).toBe(1);
    // C opens it and the author is B, whatever the carrier was (A carried it too)
    const trust = C.reports[C.reports.length - 1]!.trust;
    const keys = channelKeys(trust, { device: C.m.id, publicKey: C.m.keys.signing.publicKey });
    const out = await openChannel({
      appId: APP,
      own: { device: C.m.id, agreements: [C.m.keys.agreement] },
      envelopes: C.mailbox.items,
      authorKey: keys.authorKey,
      keys: keys.keys,
      mayWrite: () => true,
    });
    // the body is not a channel body: dropped, the author was B in any case
    expect(out.rejected.map((x) => x.code)).toEqual(['bad-body']);
  });
});
