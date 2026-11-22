// The per-day exchange: two devices that meet end with the same envelopes and only what the other
// lacks travels; the messages are read strictly; the session is bounded.
import { describe, expect, it } from 'vitest';
import {
  EMPTY_MAILBOX,
  POST_LIMITS,
  dayChecks,
  maxMessageChars,
  postDone,
  postStart,
  postStep,
  readPostMessage,
  resolvePostLimits,
  writePostMessage,
  type Mailbox,
  type PostMessage,
} from '../../src/index.ts';
import { mutate, randomJson, rng } from '../core/secure-helpers.ts';
import { A, APP, B, TODAY, fake, ids, mailboxOf, meet } from './helpers.ts';

const text = (m: PostMessage): string => writePostMessage(APP, m);
const started = (mailbox: Mailbox, limits?: Partial<typeof POST_LIMITS>) => {
  const r = postStart({ appId: APP, mailbox, today: TODAY, ...(limits ? { limits } : {}) });
  if (!r.ok) throw new Error(r.reason);
  return r;
};

describe('carrying envelopes between two devices (cases of both earlier implementations)', () => {
  it('two devices end with the same envelopes; only what the other lacks travels', () => {
    const shared = fake('2026-11-08');
    const onlyA = fake();
    const onlyB = fake();
    const r = meet(mailboxOf(shared, onlyA), mailboxOf(shared, onlyB));
    expect(r.done).toBe(true);
    expect(ids(r.a)).toEqual(ids(r.b));
    expect(ids(r.a)).toHaveLength(3);
    // to A came B's one, to B came A's one: the shared day did not travel at all
    expect(r.travelled).toMatchObject({ toA: 1, toB: 1, ids: 2 });
    expect(r.sessionA.taken).toBe(1);
  });

  it('equal boxes: nothing but the check values', () => {
    const x = fake();
    const r = meet(mailboxOf(x), mailboxOf(x));
    expect(r.done).toBe(true);
    expect(r.travelled).toMatchObject({ toA: 0, toB: 0, ids: 0 });
  });

  it('an empty box gets everything, in pieces', () => {
    const many = Array.from({ length: 120 }, () => fake());
    const r = meet(mailboxOf(...many), EMPTY_MAILBOX);
    expect(r.done).toBe(true);
    expect(ids(r.b)).toEqual(ids(r.a));
    expect(r.travelled.toB).toBe(120);
    expect(r.travelled.messages).toBeGreaterThan(10);
  });

  it('two devices compare day by day and each gets what it lacked (day 1 shared, one each)', () => {
    const [u1, u2, u3] = [fake(), fake(), fake('2026-11-09')];
    const r = meet(mailboxOf(u1, u2), mailboxOf(u2, u3));
    expect(r.done).toBe(true);
    expect(ids(r.a)).toEqual([u1.id, u2.id, u3.id].sort());
    expect(ids(r.b)).toEqual(ids(r.a));
    expect(r.travelled).toMatchObject({ toA: 1, toB: 1 });
  });

  it("a session counts what it refused over the other device's quota of the day", () => {
    const many = Array.from({ length: POST_LIMITS.maxPerSupplier + 3 }, () => fake());
    const r = meet(mailboxOf(...many), EMPTY_MAILBOX);
    expect(r.done).toBe(true);
    expect(r.b.items).toHaveLength(POST_LIMITS.maxPerSupplier);
    expect(r.sessionB).toMatchObject({ taken: POST_LIMITS.maxPerSupplier, rejected: 3 });
  });

  it('what is too old is dropped when the exchange starts, and is not announced', () => {
    const old = fake('2026-09-01');
    const fresh = fake();
    const s = started(mailboxOf(old, fresh));
    expect(s.mailbox.items.map((e) => e.id)).toEqual([fresh.id]);
    expect(Object.keys(JSON.parse(s.send[0] as string).days)).toEqual([TODAY]);
    expect(postStart({ appId: APP, mailbox: EMPTY_MAILBOX, today: 'nope' })).toEqual({
      ok: false,
      reason: 'bad-day',
    });
  });

  it('big envelopes travel alone and still obey the piece size for the others', () => {
    const limits = { pieceChars: 3000 };
    const many = Array.from({ length: 12 }, () => fake(TODAY, 600));
    const r = meet(mailboxOf(...many), EMPTY_MAILBOX, { limits });
    expect(r.done).toBe(true);
    expect(r.b.items).toHaveLength(12);
    const messages = started(mailboxOf(...many), limits);
    expect(messages.send).toHaveLength(1);
    for (const m of many)
      expect(m.text.length).toBeLessThan(maxMessageChars(resolvePostLimits(limits)));
  });

  it('every message the sender writes is within what a reader takes', () => {
    const limits = { pieceChars: 2500 };
    const lim = resolvePostLimits(limits);
    const box = mailboxOf(...Array.from({ length: 30 }, () => fake(TODAY, 300)));
    const peer = started(EMPTY_MAILBOX, limits);
    let session = started(box, limits).session;
    const days = postStep({
      appId: APP,
      session,
      mailbox: box,
      message: peer.send[0] as string,
      today: TODAY,
      from: B,
      limits,
    });
    if (!days.ok) throw new Error(days.reason);
    session = days.session;
    const last = postStep({
      appId: APP,
      session,
      mailbox: box,
      message: text({ t: 'ids', ids: [], last: true }),
      today: TODAY,
      from: B,
      limits,
    });
    if (!last.ok) throw new Error(last.reason);
    expect(last.send.length).toBeGreaterThan(5);
    for (const m of [...days.send, ...last.send]) {
      expect(m.length).toBeLessThanOrEqual(maxMessageChars(lim));
      expect(readPostMessage(APP, m, limits)).toBeDefined();
    }
  });
});

describe('the messages are read strictly', () => {
  const x = fake();
  const days = { t: 'days', days: dayChecks(APP, mailboxOf(x)) } as const;
  const idsMsg = { t: 'ids', ids: [x.id], last: true } as const;
  const envMsg = { t: 'envelopes', envelopes: [x], last: false } as const;

  it('round trips each kind and gives fresh copies', () => {
    for (const m of [days, idsMsg, envMsg]) {
      const read = readPostMessage(APP, text(m));
      expect(read).toEqual(m);
      expect(readPostMessage(APP, text(m))).not.toBe(read);
    }
    const a = readPostMessage(APP, text(idsMsg)) as Extract<PostMessage, { t: 'ids' }>;
    const b = readPostMessage(APP, text(idsMsg)) as Extract<PostMessage, { t: 'ids' }>;
    (a.ids as string[]).push('x');
    expect(b.ids).toEqual([x.id]);
    expect(
      Object.getPrototypeOf((readPostMessage(APP, text(days)) as typeof days).days),
    ).toBeNull();
  });

  it('refuses a second spelling, unknown members, another app and rubbish', () => {
    const good = text(idsMsg);
    const bad = [
      good.replace('"last":true', '"last" :true'),
      ` ${good}`,
      good.replace('{"m"', '{"x":1,"m"'),
      good.replace('"t":"ids"', '"t":"idz"'),
      good.replace('demo-post', 'other-post'),
      good.replace('"last":true', '"last":1'),
      good.replace('"ids":[', '"ids":["__proto__",'),
      good.replace('"ids":[', '"ids":[null,'),
      good.replace(x.id, `${x.id}=`),
      good.replace(x.id, x.id.slice(1)),
      good.replace('"last":true}', '"last":true,"last":true}'),
      '',
      '{}',
      'null',
      '[]',
      '{"m":"demo-post:2","t":"ids"}',
    ];
    for (const b of bad) expect(readPostMessage(APP, b)).toBeUndefined();
    expect(readPostMessage('other', good)).toBeUndefined();
    expect(readPostMessage(APP, 5)).toBeUndefined();
    expect(readPostMessage(APP, undefined)).toBeUndefined();
  });

  it('days: calendar days only, in order, with 22-character check values, at most 64', () => {
    const check = 'A'.repeat(22);
    expect(
      readPostMessage(
        APP,
        `{"m":"demo-post:2","t":"days","days":{"2026-11-09":"${check}","2026-11-10":"${check}"}}`,
      ),
    ).toBeDefined();
    for (const days of [
      `{"2026-11-10":"${check}","2026-11-09":"${check}"}`, // not in order
      `{"2026-02-30":"${check}"}`,
      `{"__proto__":"${check}"}`,
      `{"2026-11-10":"short"}`,
      `{"2026-11-10":"${check}","2026-11-10":"${check}"}`,
      `{"2026-11-10":7}`,
      '[]',
    ]) {
      expect(readPostMessage(APP, `{"m":"demo-post:2","t":"days","days":${days}}`)).toBeUndefined();
    }
    const many = (n: number): string =>
      `{"m":"demo-post:2","t":"days","days":{${Array.from({ length: n }, (_, i) => `"${new Date(Date.UTC(2026, 0, 1 + i)).toISOString().slice(0, 10)}":"${check}"`).join(',')}}}`;
    expect(readPostMessage(APP, many(64))).toBeDefined();
    expect(readPostMessage(APP, many(65))).toBeUndefined();
  });

  it('ids and envelopes: at most 400 in a message, every envelope strictly read', () => {
    const one = fake().id;
    const lots = (n: number): string =>
      text({ t: 'ids', ids: Array.from({ length: n }, () => one), last: false });
    expect(readPostMessage(APP, lots(400))).toBeDefined();
    expect(readPostMessage(APP, lots(401))).toBeUndefined();
    const broken = text(envMsg).replace('"iv":"AAAAAAAAAAAAAAAA"', '"iv":"AAAAAAAAAAAAAAAB"');
    expect(readPostMessage(APP, broken)).toBeUndefined();
    expect(readPostMessage(APP, text({ t: 'envelopes', envelopes: [], last: true }))).toBeDefined();
    const other = fake(TODAY, 0, 'other');
    expect(
      readPostMessage(APP, text({ t: 'envelopes', envelopes: [other], last: true })),
    ).toBeUndefined();
  });

  it('a text over the cap is refused before it is parsed', () => {
    const lim = resolvePostLimits();
    const long = ' '.repeat(maxMessageChars(lim) + 1);
    expect(readPostMessage(APP, long)).toBeUndefined();
    const small = resolvePostLimits({ pieceChars: 100, maxEnvelopeBytes: 100 });
    expect(maxMessageChars(small)).toBe(612);
  });

  it('fuzzing: 3500 inputs never throw and give a message only for what the writer writes', () => {
    const base = [text(days), text(idsMsg), text(envMsg)];
    const next = rng(2026);
    let read = 0;
    for (let i = 0; i < 3500; i += 1) {
      const pick = next();
      const source = base[Math.floor(next() * base.length)] as string;
      const input: unknown =
        pick < 0.6
          ? mutate(next, source)
          : pick < 0.8
            ? JSON.stringify(randomJson(next))
            : source.slice(0, Math.floor(next() * source.length));
      let message: PostMessage | undefined;
      expect(() => {
        message = readPostMessage(APP, input);
      }).not.toThrow();
      if (message) {
        read += 1;
        expect(writePostMessage(APP, message)).toBe(input);
      }
    }
    expect(read).toBeLessThan(3500);
    for (const b of base) expect(readPostMessage(APP, b)).toBeDefined();
  });
});

describe('the session is a state machine: out of order, over a limit, or rubbish is a refusal', () => {
  const step = (
    session: ReturnType<typeof started>['session'],
    mailbox: Mailbox,
    message: string,
    limits?: Partial<typeof POST_LIMITS>,
  ) =>
    postStep({
      appId: APP,
      session,
      mailbox,
      message,
      today: TODAY,
      from: B,
      ...(limits ? { limits } : {}),
    });
  const daysOf = (m: Mailbox): string => text({ t: 'days', days: dayChecks(APP, m) });
  const ready = (limits?: Partial<typeof POST_LIMITS>) => {
    const mailbox = mailboxOf(fake(), fake());
    const s = started(mailbox, limits);
    const r = step(s.session, s.mailbox, daysOf(EMPTY_MAILBOX), limits);
    if (!r.ok) throw new Error(r.reason);
    return { mailbox: r.mailbox, session: r.session };
  };

  it('messages out of order are refused: days twice, ids first, envelopes before the last ids, anything after the end', () => {
    const s = started(mailboxOf(fake()));
    const noDays = step(s.session, s.mailbox, text({ t: 'ids', ids: [], last: true }));
    expect(noDays).toEqual({ ok: false, reason: 'unexpected' });
    expect(step(s.session, s.mailbox, text({ t: 'envelopes', envelopes: [], last: true }))).toEqual(
      { ok: false, reason: 'unexpected' },
    );
    const afterDays = ready();
    expect(step(afterDays.session, afterDays.mailbox, daysOf(EMPTY_MAILBOX))).toEqual({
      ok: false,
      reason: 'unexpected',
    });
    expect(
      step(
        afterDays.session,
        afterDays.mailbox,
        text({ t: 'envelopes', envelopes: [], last: true }),
      ),
    ).toEqual({ ok: false, reason: 'unexpected' });
    const open = step(
      afterDays.session,
      afterDays.mailbox,
      text({ t: 'ids', ids: [], last: true }),
    );
    expect(open.ok).toBe(true);
    if (!open.ok) return;
    expect(step(open.session, open.mailbox, text({ t: 'ids', ids: [], last: true }))).toEqual({
      ok: false,
      reason: 'unexpected',
    });
    const end = step(
      open.session,
      open.mailbox,
      text({ t: 'envelopes', envelopes: [], last: true }),
    );
    expect(end.ok && postDone(end.session)).toBe(true);
    if (!end.ok) return;
    expect(
      step(end.session, end.mailbox, text({ t: 'envelopes', envelopes: [], last: true })),
    ).toEqual({ ok: false, reason: 'unexpected' });
  });

  it('unreadable messages and a bad sender are refusals that change nothing', () => {
    const s = started(mailboxOf(fake()));
    expect(step(s.session, s.mailbox, 'garbage')).toEqual({ ok: false, reason: 'bad-message' });
    expect(
      step(s.session, s.mailbox, text({ t: 'ids', ids: [], last: true }).replace('demo', 'other')),
    ).toEqual({ ok: false, reason: 'bad-message' });
    expect(
      postStep({
        appId: APP,
        session: s.session,
        mailbox: s.mailbox,
        message: daysOf(EMPTY_MAILBOX),
        today: TODAY,
        from: 'a|b',
      }),
    ).toEqual({ ok: false, reason: 'bad-supplier' });
    expect(
      postStep({
        appId: APP,
        session: s.session,
        mailbox: s.mailbox,
        message: text({ t: 'envelopes', envelopes: [], last: true }),
        today: 'nope',
        from: B,
      }),
    ).toMatchObject({ ok: false });
    // after the refusals the real message is still taken
    expect(step(s.session, s.mailbox, daysOf(EMPTY_MAILBOX)).ok).toBe(true);
  });

  it('the other side may announce at most maxTheirIds ids, in however many messages', () => {
    const limits = { maxTheirIds: 600 };
    let { session, mailbox } = ready(limits);
    const ids400 = (): string[] => Array.from({ length: 400 }, () => fake().id);
    const first = step(session, mailbox, text({ t: 'ids', ids: ids400(), last: false }), limits);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    ({ session, mailbox } = first);
    const exactly = step(
      session,
      mailbox,
      text({ t: 'ids', ids: ids400().slice(0, 200), last: false }),
      limits,
    );
    expect(exactly.ok).toBe(true);
    if (!exactly.ok) return;
    const one = step(
      exactly.session,
      exactly.mailbox,
      text({ t: 'ids', ids: [fake().id], last: false }),
      limits,
    );
    expect(one).toEqual({ ok: false, reason: 'too-many-ids' });
  });

  it('a hostile neighbour that sends thousands of one-id messages costs a linear amount', () => {
    const { session: start, mailbox } = ready();
    let session = start;
    const t0 = performance.now();
    for (let i = 0; i < 3000; i += 1) {
      const r = step(session, mailbox, text({ t: 'ids', ids: [fake().id], last: false }));
      if (!r.ok) throw new Error(r.reason);
      session = r.session;
    }
    expect(session.theirCount).toBe(3000);
    expect(performance.now() - t0).toBeLessThan(5000);
    const batch = (): string =>
      text({ t: 'ids', ids: Array.from({ length: 400 }, () => fake().id), last: false });
    for (let i = 0; i < 2; i += 1) {
      const more = step(session, mailbox, batch());
      if (!more.ok) throw new Error(more.reason);
      session = more.session;
    }
    expect(session.theirCount).toBe(3800);
    expect(step(session, mailbox, batch())).toEqual({ ok: false, reason: 'too-many-ids' });
  });

  it('the envelopes taken in one session are bounded by maxEnvelopes, offered ones included', () => {
    const limits = { maxEnvelopes: 10, maxPerMessage: 400 };
    const { session, mailbox } = (() => {
      const s = started(EMPTY_MAILBOX, limits);
      const r = step(s.session, s.mailbox, daysOf(EMPTY_MAILBOX), limits);
      if (!r.ok) throw new Error(r.reason);
      const o = step(r.session, r.mailbox, text({ t: 'ids', ids: [], last: true }), limits);
      if (!o.ok) throw new Error(o.reason);
      return o;
    })();
    const batch = (n: number): string =>
      text({ t: 'envelopes', envelopes: Array.from({ length: n }, () => fake()), last: false });
    const six = step(session, mailbox, batch(6), limits);
    expect(six.ok && six.session.offered).toBe(6);
    if (!six.ok) return;
    expect(step(six.session, six.mailbox, batch(5), limits)).toEqual({
      ok: false,
      reason: 'too-many-envelopes',
    });
    expect(step(six.session, six.mailbox, batch(4), limits).ok).toBe(true);
  });

  it('a message of envelopes for another day is simply not carried (too old), the rest is taken', () => {
    const { session, mailbox } = (() => {
      const s = started(EMPTY_MAILBOX);
      const r = step(s.session, s.mailbox, daysOf(EMPTY_MAILBOX));
      if (!r.ok) throw new Error(r.reason);
      const o = step(r.session, r.mailbox, text({ t: 'ids', ids: [], last: true }));
      if (!o.ok) throw new Error(o.reason);
      return o;
    })();
    const good = fake();
    const old = fake('2026-01-01');
    const r = step(session, mailbox, text({ t: 'envelopes', envelopes: [old, good], last: true }));
    expect(r.ok && r.added.map((e) => e.id)).toEqual([good.id]);
    expect(r.ok && r.session.taken).toBe(1);
  });
});

describe('two apps never read each other', () => {
  it('messages of one app are not messages of another', () => {
    const s = started(mailboxOf(fake()));
    const msg = s.send[0] as string;
    expect(readPostMessage('demo', msg)).toBeDefined();
    expect(readPostMessage('other', msg)).toBeUndefined();
    const r = postStep({
      appId: 'other',
      session: s.session,
      mailbox: s.mailbox,
      message: msg,
      today: TODAY,
      from: A,
    });
    expect(r).toEqual({ ok: false, reason: 'bad-message' });
  });
});
