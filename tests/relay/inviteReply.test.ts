// The answer of a new device to an invitation, carried by the relay in clear text: one spelling, bounded,
// sent at a limited pace and repeated until the invitation ends; the inviting device takes the replies out
// of what it collected and limits them. Against the reference server and in pure steps.
import { describe, expect, it } from 'vitest';
import {
  INVITE_REPLY_LIMITS,
  RelayClient,
  acknowledgeReply,
  emptyReplyInbox,
  encodeInviteReply,
  nextReplyAction,
  readInviteReply,
  startReply,
  stepReply,
  takeInviteReplies,
  type CollectedMessage,
  type FetchLike,
} from '../../src/relay/index.ts';
import { ALPHA, mintProof, serverForR2 } from './helpers.ts';
import { DEV, DEV2, memoryStore, mutateText, newSigner } from './helpers-r2.ts';
import { mulberry32 } from './helpers.ts';

const TEXT = 'eyJtIjoieCJ9'; // base64url, what the trust layer's reply text looks like
const NOW = 1_800_000_000_000;
const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);
const message = (from: string, content: Uint8Array): CollectedMessage => ({
  from,
  content,
  ageMs: 1,
});

describe('the reply message: one spelling, bounded', () => {
  it('is `{"m":"<app>-invitereply:2","reply":"<text>"}` in UTF-8 and reads back', () => {
    const bytes = encodeInviteReply('alpha', TEXT) as Uint8Array;
    expect(text(bytes)).toBe(`{"m":"alpha-invitereply:2","reply":"${TEXT}"}`);
    expect(readInviteReply('alpha', bytes)).toBe(TEXT);
    expect(readInviteReply('beta', bytes)).toBeUndefined(); // another app's marker
  });

  it('only a reply text of the trust layer (base64url, at most 2000 characters) goes in', () => {
    for (const bad of [
      '',
      'a b',
      'ä',
      '=',
      'x'.repeat(INVITE_REPLY_LIMITS.maxTextChars + 1),
      5 as never,
    ]) {
      expect(encodeInviteReply('alpha', bad), String(bad).slice(0, 20)).toBeUndefined();
    }
    expect(encodeInviteReply('alpha', 'x'.repeat(INVITE_REPLY_LIMITS.maxTextChars))).toBeDefined();
    expect(encodeInviteReply('Bad App', TEXT)).toBeUndefined();
  });

  it('refuses every other spelling and everything that is not a reply', () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    const good = `{"m":"alpha-invitereply:2","reply":"${TEXT}"}`;
    for (const bad of [
      ` ${good}`,
      `${good} `,
      `{"reply":"${TEXT}","m":"alpha-invitereply:2"}`, // other order
      `{"m":"alpha-invitereply:2","reply":"${TEXT}","x":1}`,
      `{"m":"alpha-invitereply:1","reply":"${TEXT}"}`,
      `{"m":"alpha-invitereply:2","reply":""}`,
      `{"m":"alpha-invitereply:2","reply":5}`,
      `{"m":"alpha-invitereply:2","reply":"a b"}`,
      `{"m":"alpha-invitereply:2","reply":"${TEXT}","reply":"${TEXT}"}`, // duplicate member
      `{"m":"alpha-invitereply:2","re\\u0070ly":"${TEXT}"}`, // an escape in a name
      '[]',
      'null',
      '{',
      '',
    ]) {
      expect(readInviteReply('alpha', enc(bad)), bad).toBeUndefined();
    }
    expect(readInviteReply('alpha', Uint8Array.of(0xff, 0xfe))).toBeUndefined();
    expect(readInviteReply('alpha', new Uint8Array(5000))).toBeUndefined();
    expect(readInviteReply('alpha', 'x' as never)).toBeUndefined();
    expect(readInviteReply('alpha', Uint8Array.of(0xef, 0xbb, 0xbf, ...enc(good)))).toBeUndefined(); // a BOM
  });

  it('3000 mutated inputs: never throws, and what is read is what encoding the text gives', () => {
    const rng = mulberry32(0x1eed);
    const valid = text(encodeInviteReply('alpha', TEXT) as Uint8Array);
    let accepted = 0;
    for (let i = 0; i < 3000; i += 1) {
      const input = new TextEncoder().encode(mutateText(rng, valid));
      let r: string | undefined;
      expect(() => {
        r = readInviteReply('alpha', input);
      }).not.toThrow();
      if (r !== undefined) {
        accepted += 1;
        expect(text(encodeInviteReply('alpha', r) as Uint8Array)).toBe(text(input));
      }
    }
    expect(accepted).toBeLessThan(300);
  });
});

describe('the sender: sent at a limited pace and repeated until the invitation ends', () => {
  it('starts only with an inviter id, a reply text and an end in the future', () => {
    const o = { to: DEV, text: TEXT, until: NOW + 1000 };
    expect(startReply('alpha', o, NOW)).toEqual({ ...o, sends: 0 });
    expect(startReply('alpha', { ...o, to: 'x' }, NOW)).toBeUndefined();
    expect(startReply('alpha', { ...o, text: 'a b' }, NOW)).toBeUndefined();
    expect(startReply('alpha', { ...o, until: NOW }, NOW)).toBeUndefined();
    expect(startReply('alpha', { ...o, until: 1.5 }, NOW)).toBeUndefined();
  });

  it('the decisions: send, wait out the interval, stop at the end or when acknowledged; a clock that went back sends', () => {
    const s = startReply('alpha', { to: DEV, text: TEXT, until: NOW + 100_000 }, NOW)!;
    expect(nextReplyAction(s, NOW)).toEqual({ do: 'send' });
    const sent = { ...s, sends: 1, lastSendMs: NOW };
    expect(nextReplyAction(sent, NOW + 10_000)).toEqual({ do: 'wait', waitMs: 20_000 });
    expect(nextReplyAction(sent, NOW + 30_000)).toEqual({ do: 'send' });
    expect(nextReplyAction(sent, NOW - 5_000)).toEqual({ do: 'send' });
    expect(nextReplyAction(sent, NOW + 100_000)).toEqual({ do: 'stop', reason: 'expired' });
    expect(nextReplyAction(acknowledgeReply(sent), NOW + 1)).toEqual({
      do: 'stop',
      reason: 'acknowledged',
    });
    expect(nextReplyAction(sent, NOW + 10_000, 5_000)).toEqual({ do: 'send' });
  });

  async function pair() {
    const server = serverForR2();
    const mk = async (net?: FetchLike) => {
      const { signer } = await newSigner();
      const c = new RelayClient({
        baseUrl: 'https://relay.test',
        appId: 'alpha',
        origin: ALPHA.origin,
        fetch: net ?? server.fetch,
        store: memoryStore(),
        clock: server.now,
        signer,
        maxAttempts: 1,
      });
      const r = await c.enrol({ proof: await mintProof('alpha', server.now()) });
      if (!r.ok) throw new Error(r.kind);
      return { c, id: r.value.device };
    };
    return { server, mk };
  }

  it('drops the reply at the inviter only, once per interval, until the end; the inviter takes it out of its collect', async () => {
    const { server, mk } = await pair();
    const inviter = await mk();
    const joining = await mk();
    let state = startReply(
      'alpha',
      { to: inviter.id, text: TEXT, until: server.now() + 100_000 },
      server.now(),
    )!;
    const seen: string[] = [];
    for (let i = 0; i < 8; i += 1) {
      const step = await stepReply(joining.c, 'alpha', state, server.now());
      state = step.state;
      if (step.done) {
        seen.push(`done:${step.reason}`);
        break;
      }
      seen.push(step.outcome);
      server.control.advanceTime(step.waitMs);
    }
    // sends at 0, 30, 60, 90 s, and the step after the end stops
    expect(seen).toEqual(['sent', 'sent', 'sent', 'sent', 'done:expired']);
    expect(state.sends).toBe(4);
    const got = await inviter.c.collect();
    // the relay holds a message 30 s: the inviter sees what is still waiting, and it is a reply
    const msgs = got.ok ? got.value.messages : [];
    for (const m of msgs) expect(readInviteReply('alpha', m.content)).toBe(TEXT);
  });

  it('a waiting step sends nothing; acknowledging stops it', async () => {
    const { server, mk } = await pair();
    const inviter = await mk();
    const joining = await mk();
    const t0 = server.now();
    let state = startReply('alpha', { to: inviter.id, text: TEXT, until: t0 + 100_000 }, t0)!;
    state = (await stepReply(joining.c, 'alpha', state, t0)).state;
    const wait = await stepReply(joining.c, 'alpha', state, t0 + 1_000);
    expect(wait).toMatchObject({ done: false, outcome: 'waited', waitMs: 29_000 });
    expect(wait.state.sends).toBe(1);
    const stop = await stepReply(joining.c, 'alpha', acknowledgeReply(state), t0 + 60_000);
    expect(stop).toMatchObject({ done: true, reason: 'acknowledged' });
  });

  it('a failure of the net waits and the next step tries again; what cannot change is `final`', async () => {
    const { server, mk } = await pair();
    const inviter = await mk();
    let offline = true;
    const joining = await mk((u, i) =>
      offline && String(u).endsWith('/ablegen')
        ? Promise.reject(new TypeError('offline'))
        : server.fetch(u, i),
    );
    let state = startReply(
      'alpha',
      { to: inviter.id, text: TEXT, until: server.now() + 600_000 },
      server.now(),
    )!;
    const first = await stepReply(joining.c, 'alpha', state, server.now());
    expect(first).toMatchObject({ done: false, outcome: 'network', waitMs: 30_000 });
    expect(first.done === false && first.final).toBeUndefined();
    offline = false;
    server.control.advanceTime(30_000);
    state = first.state;
    expect(await stepReply(joining.c, 'alpha', state, server.now())).toMatchObject({
      outcome: 'sent',
    });
    // a client that was told it is blocked can send no more: final
    const blocked = await mk();
    blocked.c.forget();
    const unenrolled = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: server.fetch,
      store: memoryStore(),
      clock: server.now,
    });
    const none = await stepReply(
      unenrolled,
      'alpha',
      startReply(
        'alpha',
        { to: inviter.id, text: TEXT, until: server.now() + 600_000 },
        server.now(),
      )!,
      server.now(),
    );
    expect(none).toMatchObject({ done: false, outcome: 'no-credentials', final: true });
    // a relay that is too busy: the hint is honoured
    const busy = await mk((_u, init) =>
      String(init.body).includes('inhalt')
        ? Promise.resolve(
            new Response(JSON.stringify({ fehler: 'x', art: 'zu-viele-anfragen' }), {
              status: 429,
              headers: { 'Content-Type': 'application/json' },
            }),
          )
        : server.fetch(_u, init),
    );
    const limited = await stepReply(
      busy.c,
      'alpha',
      startReply(
        'alpha',
        { to: inviter.id, text: TEXT, until: server.now() + 600_000 },
        server.now(),
      )!,
      server.now(),
    );
    expect(limited).toMatchObject({ outcome: 'rate-limited' });
    expect(limited.done === false && limited.waitMs).toBeGreaterThanOrEqual(15_000);
  });

  it("a recipient's full mailbox waits like a rate limit: the next copy goes after the interval", async () => {
    const { server, mk } = await pair();
    const inviter = await mk();
    const joining = await mk();
    server.control.setLimits({ mailboxMessages: 1 });
    await joining.c.drop([{ device: inviter.id, content: Uint8Array.of(1) }]);
    const r = await stepReply(
      joining.c,
      'alpha',
      startReply(
        'alpha',
        { to: inviter.id, text: TEXT, until: server.now() + 600_000 },
        server.now(),
      )!,
      server.now(),
    );
    expect(r).toMatchObject({ done: false, outcome: 'recipient-full' });
    expect(r.state.sends).toBe(1);
  });
});

describe('the inviting device: it takes the replies out of what it collected, with limits', () => {
  const reply = (n: number): Uint8Array => encodeInviteReply('alpha', `${TEXT}${n}`) as Uint8Array;

  it('takes replies, leaves every other message in `rest` in order, untouched', () => {
    const other = Uint8Array.of(1, 2, 3);
    const out = takeInviteReplies(
      'alpha',
      [message(DEV, other), message(DEV2, reply(1)), message(DEV, Uint8Array.of(9))],
      NOW,
    );
    expect(out.replies).toEqual([{ from: DEV2, text: `${TEXT}1` }]);
    expect(out.rest.map((m) => [...m.content])).toEqual([[1, 2, 3], [9]]);
    expect(takeInviteReplies('beta', [message(DEV, reply(1))], NOW).replies).toEqual([]);
  });

  it('at most 5 replies from one sender in a window, the same text from the same sender once, at most 20 in a batch', () => {
    let inbox = emptyReplyInbox;
    const out = takeInviteReplies(
      'alpha',
      Array.from({ length: 9 }, (_, i) => message(DEV, reply(i))),
      NOW,
      inbox,
    );
    expect(out.replies).toHaveLength(INVITE_REPLY_LIMITS.perSenderMax);
    inbox = out.inbox;
    expect(
      takeInviteReplies('alpha', [message(DEV, reply(100))], NOW + 1000, inbox).replies,
    ).toEqual([]);
    expect(
      takeInviteReplies(
        'alpha',
        [message(DEV2, reply(0)), message(DEV2, reply(0))],
        NOW + 1000,
        inbox,
      ).replies,
    ).toHaveLength(1);
    // after the window the sender may give again
    expect(
      takeInviteReplies(
        'alpha',
        [message(DEV, reply(100))],
        NOW + INVITE_REPLY_LIMITS.windowMs + 1,
        inbox,
      ).replies,
    ).toHaveLength(1);
    // senders are separate; a batch is capped
    const many = Array.from({ length: 30 }, (_, i) =>
      message(`geraet-${String(i).padStart(32, '0')}`, reply(i)),
    );
    expect(takeInviteReplies('alpha', many, NOW).replies).toHaveLength(
      INVITE_REPLY_LIMITS.perBatchMax,
    );
  });

  it('the inbox is bounded and forgets by time; nothing a hostile sender sends makes it throw', () => {
    let inbox = emptyReplyInbox;
    for (let round = 0; round < 40; round += 1) {
      const batch = Array.from({ length: 20 }, (_, i) =>
        message(`geraet-${String(round * 20 + i).padStart(32, '0')}`, reply(round * 20 + i)),
      );
      inbox = takeInviteReplies('alpha', batch, NOW + round, inbox).inbox;
    }
    expect(inbox.taken.length).toBeLessThanOrEqual(INVITE_REPLY_LIMITS.maxRemembered);
    expect(takeInviteReplies('alpha', [message(DEV, Uint8Array.of(0xff))], NOW).rest).toHaveLength(
      1,
    );
    const later = takeInviteReplies('alpha', [], NOW + INVITE_REPLY_LIMITS.windowMs + 100, inbox);
    expect(later.inbox.taken).toHaveLength(0);
  });
});
