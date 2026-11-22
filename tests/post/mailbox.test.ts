// The mailbox: envelopes carried for others. Cases of both earlier implementations (their union),
// every limit at its boundary, receipts, hostile ids, linear growth and two apps side by side.
import { describe, expect, it } from 'vitest';
import {
  EMPTY_MAILBOX,
  POST_LIMITS,
  addEnvelopes,
  announcedStand,
  applyReceipts,
  dayChecks,
  deliveredToday,
  keepNewest,
  mailboxCheck,
  pruneMailbox,
  readMailbox,
  readReceipts,
  resolvePostLimits,
  STORE_ATTEMPTS,
  storeMailbox,
  type Envelope,
  type Mailbox,
  type PostLimits,
} from '../../src/index.ts';
import { mutate, randomJson, rng } from '../core/secure-helpers.ts';
import { A, APP, B, TODAY, fake, mailboxOf, plain } from './helpers.ts';

const add = (
  m: Mailbox,
  incoming: readonly Envelope[],
  options: {
    from?: string;
    today?: string;
    limits?: Partial<PostLimits>;
  } = {},
) => {
  const r = addEnvelopes(APP, m, incoming, options.today ?? TODAY, {
    ...(options.from !== undefined ? { from: options.from } : {}),
    ...(options.limits ? { limits: options.limits } : {}),
  });
  if (!r.ok) throw new Error(r.reason);
  return r;
};

describe('taking envelopes in (cases of both earlier implementations)', () => {
  it('drops envelopes after 30 days and from a clock far ahead; keeps the newest', () => {
    const old = fake('2026-10-11');
    const edge = fake('2026-10-12');
    const future = fake('2026-11-20');
    const k = add(EMPTY_MAILBOX, [old, edge, future]).mailbox;
    expect(k.items.map((e) => e.id)).toEqual([edge.id]);
    // a day later the envelope of 2026-10-12 goes too
    expect(pruneMailbox(APP, k, '2026-11-11')?.items).toHaveLength(0);
    const older = add(EMPTY_MAILBOX, [fake('2026-11-01')]).mailbox;
    const full = add(
      older,
      Array.from({ length: POST_LIMITS.maxEnvelopes }, () => fake()),
    );
    expect(full.mailbox.items).toHaveLength(POST_LIMITS.maxEnvelopes);
    expect(full.mailbox.items.every((e) => e.day === TODAY)).toBe(true);
  });

  it('an envelope already there is not taken twice', () => {
    const x = fake();
    const one = add(EMPTY_MAILBOX, [x, x]);
    expect(one.added).toHaveLength(1);
    expect(add(one.mailbox, [x]).added).toHaveLength(0);
  });

  it('nothing new, nothing gone: the very same mailbox (watching it would wake itself for ever)', () => {
    const k = add(EMPTY_MAILBOX, [fake(), fake('2026-11-01')]).mailbox;
    expect(add(k, []).mailbox).toBe(k);
    expect(add(k, [k.items[0] as Envelope]).mailbox).toBe(k);
    expect(pruneMailbox(APP, k, TODAY)).toBe(k);
    // one became too old: a new mailbox
    expect(pruneMailbox(APP, k, '2026-12-01')).not.toBe(k);
  });

  it('one other device brings at most 400 a day, the newest days first; the rest is counted', () => {
    const old = fake('2026-11-01');
    const many = Array.from({ length: POST_LIMITS.maxPerSupplier + 5 }, () => fake());
    const first = add(EMPTY_MAILBOX, [old, ...many], { from: A });
    expect(first.added).toHaveLength(400);
    expect(first.rejected).toBe(6);
    expect(first.mailbox.items.some((e) => e.id === old.id)).toBe(false);
    // the quota of the day is used up for A: nothing more from A today ...
    const again = add(first.mailbox, [fake()], { from: A });
    expect(again).toMatchObject({ added: [], rejected: 1 });
    expect(again.mailbox).toBe(first.mailbox);
    // ... but from B, sealed here (no quota), and from A the next day
    expect(add(first.mailbox, [fake()], { from: B }).added).toHaveLength(1);
    expect(add(first.mailbox, [fake()]).added).toHaveLength(1);
    expect(
      add(first.mailbox, [fake('2026-11-11')], { from: A, today: '2026-11-11' }).added,
    ).toHaveLength(1);
  });

  it('what is there already or too old does not count against the quota', () => {
    const there = fake();
    const k = add(EMPTY_MAILBOX, [there], { from: A }).mailbox;
    const r = add(k, [there, fake('2026-09-01')], { from: A });
    expect(r).toMatchObject({ added: [], rejected: 0 });
    expect(deliveredToday(r.mailbox, TODAY)).toEqual({ [A]: 1 });
  });

  it('check values: per day and for all; a new envelope changes them; the stand is 32 hex digits', () => {
    const k = mailboxOf(fake('2026-11-09'), fake());
    expect(Object.keys(dayChecks(APP, k))).toEqual(['2026-11-09', TODAY]);
    for (const check of Object.values(dayChecks(APP, k)))
      expect(check).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(mailboxCheck(APP, k)).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const more = add(k, [fake()]).mailbox;
    expect(mailboxCheck(APP, more)).not.toBe(mailboxCheck(APP, k));
    expect(dayChecks(APP, more)['2026-11-09']).toBe(dayChecks(APP, k)['2026-11-09']);
    expect(dayChecks(APP, more)[TODAY]).not.toBe(dayChecks(APP, k)[TODAY]);
    const fingerprint = '0123456789abcdef0123456789abcdef';
    expect(announcedStand(APP, fingerprint, EMPTY_MAILBOX)).toBe(fingerprint);
    const one = add(EMPTY_MAILBOX, [fake()]).mailbox;
    const two = add(one, [fake()]).mailbox;
    expect(announcedStand(APP, fingerprint, one)).toMatch(/^[0-9a-f]{32}$/);
    expect(announcedStand(APP, fingerprint, one)).not.toBe(fingerprint);
    expect(announcedStand(APP, fingerprint, two)).not.toBe(announcedStand(APP, fingerprint, one));
  });

  it('check values do not depend on the order of the envelopes', () => {
    const x = [fake(), fake(), fake('2026-11-09')];
    expect(dayChecks(APP, mailboxOf(...x))).toEqual(dayChecks(APP, mailboxOf(...[...x].reverse())));
    expect(mailboxCheck(APP, mailboxOf(...x))).toBe(
      mailboxCheck(APP, mailboxOf(...[...x].reverse())),
    );
  });
});

describe('the mailbox stays small (size limit)', () => {
  it('big envelopes: only the newest days that fit into maxChars are kept (the oldest go first)', () => {
    const limits = { maxChars: 2_000_000 };
    const neu = Array.from({ length: 300 }, (_, n) =>
      fake(`2026-10-${String(12 + (n % 20)).padStart(2, '0')}`, 7000),
    );
    const r = add(EMPTY_MAILBOX, neu, { limits });
    const sum = r.mailbox.items.reduce((s, e) => s + e.text.length, 0);
    expect(sum).toBeLessThanOrEqual(limits.maxChars);
    expect(r.mailbox.items.length).toBeGreaterThan(150);
    expect(r.mailbox.items.length).toBeLessThan(300);
    const kept = new Set(r.mailbox.items.map((e) => e.id));
    const oldestKept = r.mailbox.items.map((e) => e.day).sort()[0] as string;
    expect(neu.filter((e) => !kept.has(e.id)).every((e) => e.day <= oldestKept)).toBe(true);
    // those that did not stay are not reported as new either
    expect(r.added.every((e) => kept.has(e.id))).toBe(true);
    expect(POST_LIMITS.maxChars).toBe(8_000_000);
  });

  it('small envelopes are untouched by the size limit, the count limit still holds', () => {
    const neu = Array.from({ length: POST_LIMITS.maxEnvelopes + 50 }, (_, n) =>
      fake(`2026-11-0${1 + (n % 9)}`),
    );
    // more than maxEnvelopes in one call is refused outright: it is the bound per message
    expect(addEnvelopes(APP, EMPTY_MAILBOX, neu, TODAY)).toEqual({ ok: false, reason: 'too-many' });
    const two = add(add(EMPTY_MAILBOX, neu.slice(0, 1500)).mailbox, neu.slice(1500, 2050));
    expect(two.mailbox.items).toHaveLength(POST_LIMITS.maxEnvelopes);
    expect(add(EMPTY_MAILBOX, neu.slice(0, 40)).mailbox.items).toHaveLength(40);
  });

  it('a mailbox that is already too big shrinks with the next call', () => {
    const limits = { maxChars: 2_000_000 };
    const big = mailboxOf(
      ...Array.from({ length: 300 }, (_, n) => fake(`2026-10-${12 + (n % 20)}`, 7000)),
    );
    const r = add(big, [fake(TODAY, 100)], { limits });
    expect(r.mailbox.items.reduce((s, e) => s + e.text.length, 0)).toBeLessThanOrEqual(2_000_000);
    expect(r.mailbox.items.some((e) => e.id === (r.added[0] as Envelope).id)).toBe(true);
  });

  it('keepNewest keeps the newest days in their old order', () => {
    const [a, b, c, d] = [
      fake('2026-11-05'),
      fake('2026-11-01'),
      fake('2026-11-09'),
      fake('2026-11-03'),
    ];
    const k = {
      ...mailboxOf(a, b, c, d),
      delivered: { day: TODAY, per: Object.create(null) as Record<string, number> },
    };
    const r = keepNewest(k, 2);
    expect(r.items.map((e) => e.id)).toEqual([a.id, c.id]);
    expect(r.delivered).toBe(k.delivered);
    expect(keepNewest(k, 9)).toBe(k);
    expect(keepNewest(k, 0).items).toEqual([]);
    expect(keepNewest(k, Number.NaN).items).toEqual([]);
  });
});

describe('writing the mailbox never refuses a file (the quota of a store)', () => {
  const box = (n: number): Mailbox =>
    mailboxOf(...Array.from({ length: n }, (_, i) => fake(`2026-11-0${1 + (i % 9)}`)));
  const quota = () =>
    Object.assign(new Error('exceeded the quota'), { name: 'QuotaExceededError' });

  it('it fits: written as it is, nothing dropped', async () => {
    const written: Mailbox[] = [];
    expect(await storeMailbox((m) => void written.push(m), box(30))).toMatchObject({
      ok: true,
      kept: 30,
      dropped: 0,
    });
    expect(written).toHaveLength(1);
    expect(written[0]?.items).toHaveLength(30);
  });

  it('it does not fit: halved until it does, the newest days stay, the number dropped is told', async () => {
    const written: Mailbox[] = [];
    const all = box(60);
    const dropped = await storeMailbox((m) => {
      if (m.items.length > 10) throw quota();
      written.push(m);
    }, all);
    expect(written).toHaveLength(1);
    const kept = written[0] as Mailbox;
    expect(kept.items.length).toBeLessThanOrEqual(10);
    expect(dropped).toMatchObject({ ok: true, kept: kept.items.length });
    expect(dropped.dropped).toBe(60 - kept.items.length);
    expect(dropped.ok && dropped.mailbox).toBe(kept);
    const stay = new Set(kept.items.map((e) => e.id));
    const oldestKept = kept.items.map((e) => e.day).sort()[0] as string;
    expect(all.items.filter((e) => !stay.has(e.id)).every((e) => e.day <= oldestKept)).toBe(true);
  });

  it('nothing fits at all: it does not throw and says nothing was written (not "all kept")', async () => {
    const tries: number[] = [];
    const result = await storeMailbox(async (m) => {
      tries.push(m.items.length);
      throw quota();
    }, box(40));
    expect(result).toEqual({ ok: false, kept: 0, dropped: 40 });
    expect(tries[0]).toBe(40);
    // 40 20 10 5 2 1, then the empty mailbox is tried once and the loop ends
    expect(tries).toEqual([40, 20, 10, 5, 2, 1, 0]);
    expect(tries.length).toBeLessThanOrEqual(STORE_ATTEMPTS);
  });

  it('a full mailbox of 2000 is tried 8 times, 2000 down to 15, not down to nothing', async () => {
    const result = await storeMailbox(
      () => {
        throw quota();
      },
      mailboxOf(...Array.from({ length: 2000 }, () => fake())),
    );
    expect(result).toEqual({ ok: false, kept: 0, dropped: 2000 });
    const sizes: number[] = [];
    await storeMailbox(
      (m) => {
        sizes.push(m.items.length);
        throw quota();
      },
      mailboxOf(...Array.from({ length: 2000 }, () => fake())),
    );
    expect(sizes).toEqual([2000, 1000, 500, 250, 125, 62, 31, 15]);
  });

  it('an empty mailbox that cannot be written is a failure too, with nothing dropped', async () => {
    expect(await storeMailbox(() => Promise.reject(quota()), box(0))).toEqual({
      ok: false,
      kept: 0,
      dropped: 0,
    });
    expect(await storeMailbox(() => undefined, box(0))).toMatchObject({ ok: true, kept: 0 });
  });

  it('it fits only when halved to nothing but one: the last attempt that works is reported', async () => {
    const result = await storeMailbox((m) => {
      if (m.items.length > 15) throw quota();
    }, box(2000));
    expect(result).toMatchObject({ ok: true, kept: 15, dropped: 1985 });
  });
});

describe('every limit at its boundary', () => {
  it('postDays: the day 29 days back is carried, 30 days back is not; two days ahead yes, three no', () => {
    const edge = [fake('2026-10-12'), fake('2026-10-11'), fake('2026-11-12'), fake('2026-11-13')];
    const k = add(EMPTY_MAILBOX, edge).mailbox;
    expect(k.items.map((e) => e.day).sort()).toEqual(['2026-10-12', '2026-11-12']);
    const short = add(EMPTY_MAILBOX, edge, { limits: { postDays: 10 } }).mailbox;
    expect(short.items.map((e) => e.day)).toEqual(['2026-11-12']);
  });

  it('maxEnvelopes: exactly the limit stays, one more pushes the oldest out', () => {
    const limits = { maxEnvelopes: 5 };
    const five = Array.from({ length: 5 }, (_, i) => fake(`2026-11-0${i + 1}`));
    const r = add(EMPTY_MAILBOX, five, { limits });
    expect(r.mailbox.items).toHaveLength(5);
    const six = add(r.mailbox, [fake('2026-11-08')], { limits });
    expect(six.mailbox.items).toHaveLength(5);
    expect(six.mailbox.items.some((e) => e.id === five[0]?.id)).toBe(false);
    expect(addEnvelopes(APP, EMPTY_MAILBOX, [...five, fake()], TODAY, { limits })).toEqual({
      ok: false,
      reason: 'too-many',
    });
  });

  it('maxChars: exactly the sum stays, one character less drops the first that does not fit', () => {
    const three = [fake('2026-11-01'), fake('2026-11-02'), fake('2026-11-03')];
    const sum = three.reduce((s, e) => s + e.text.length, 0);
    expect(add(EMPTY_MAILBOX, three, { limits: { maxChars: sum } }).mailbox.items).toHaveLength(3);
    const less = add(EMPTY_MAILBOX, three, { limits: { maxChars: sum - 1 } }).mailbox;
    expect(less.items.map((e) => e.day)).toEqual(['2026-11-02', '2026-11-03']);
  });

  it('maxPerSupplier: 400 pass, the 401st is refused (and a limit of 0 refuses all)', () => {
    const four = Array.from({ length: 401 }, () => fake());
    expect(add(EMPTY_MAILBOX, four.slice(0, 400), { from: A }).rejected).toBe(0);
    expect(add(EMPTY_MAILBOX, four, { from: A }).rejected).toBe(1);
    expect(
      add(EMPTY_MAILBOX, four.slice(0, 3), { from: A, limits: { maxPerSupplier: 0 } }).rejected,
    ).toBe(3);
  });

  it('maxSuppliers: a further device delivers nothing that day, a known one still may', () => {
    const limits = { maxSuppliers: 3 };
    let k = EMPTY_MAILBOX;
    for (const from of ['d1', 'd2', 'd3']) k = add(k, [fake()], { from, limits }).mailbox;
    const fourth = add(k, [fake()], { from: 'd4', limits });
    expect(fourth).toMatchObject({ added: [], rejected: 1 });
    expect(add(k, [fake()], { from: 'd2', limits }).added).toHaveLength(1);
    // the next day the table starts over
    expect(
      add(k, [fake('2026-11-11')], { from: 'd4', limits, today: '2026-11-11' }).added,
    ).toHaveLength(1);
  });

  it('maxAcknowledged and the receipt limits', () => {
    const limits = { maxAcknowledged: 3, maxReceipts: 2, maxReceiptIds: 2 };
    const yes = () => true;
    const many = Array.from({ length: 5 }, (_, i) => fake(`2026-11-0${i + 1}`));
    const r = applyReceipts(
      APP,
      EMPTY_MAILBOX,
      [
        { by: 'o', ids: many.slice(0, 2).map((e) => e.id) },
        { by: 'o', ids: many.slice(2, 4).map((e) => e.id) },
      ],
      yes,
      TODAY,
      limits,
    );
    expect(r.ok && r.mailbox.acknowledged).toHaveLength(3);
    // the newest three days are remembered
    expect(r.ok && r.mailbox.acknowledged?.map((a) => a.day).sort()).toEqual([TODAY, TODAY, TODAY]);
    const over = applyReceipts(
      APP,
      EMPTY_MAILBOX,
      [
        { by: 'o', ids: [] },
        { by: 'o', ids: [] },
        { by: 'o', ids: [] },
      ],
      yes,
      TODAY,
      limits,
    );
    expect(over).toEqual({ ok: false, reason: 'too-many' });
    const wide = applyReceipts(
      APP,
      EMPTY_MAILBOX,
      [{ by: 'o', ids: many.slice(0, 3).map((e) => e.id) }],
      yes,
      TODAY,
      limits,
    );
    expect(wide).toMatchObject({ ok: true, refused: 1 });
    expect(
      readReceipts([{ by: 'o', ids: many.slice(0, 2).map((e) => e.id) }], limits),
    ).toBeDefined();
    expect(
      readReceipts([{ by: 'o', ids: many.slice(0, 3).map((e) => e.id) }], limits),
    ).toBeUndefined();
  });

  it('limits can be overridden in part; anything that is not a safe integer keeps the default', () => {
    expect(resolvePostLimits({ postDays: 5 }).postDays).toBe(5);
    expect(resolvePostLimits({ postDays: 5 }).maxEnvelopes).toBe(2000);
    for (const bad of [-1, 1.5, Number.NaN, Infinity, '9' as unknown as number]) {
      expect(resolvePostLimits({ maxEnvelopes: bad }).maxEnvelopes).toBe(2000);
    }
    expect(resolvePostLimits({ maxFans: 20 }).maxFans).toBe(16);
    expect(resolvePostLimits(undefined)).toEqual(POST_LIMITS);
  });
});

describe('refusals change nothing, and the result is a value', () => {
  it('a bad day, a bad supplier, a non-list: codes, the mailbox as it was', () => {
    const k = add(EMPTY_MAILBOX, [fake()]).mailbox;
    expect(addEnvelopes(APP, k, [], 'today')).toEqual({ ok: false, reason: 'bad-day' });
    expect(addEnvelopes(APP, k, [], '2026-02-30')).toEqual({ ok: false, reason: 'bad-day' });
    expect(addEnvelopes(APP, k, [], TODAY, { from: 'a|b' })).toEqual({
      ok: false,
      reason: 'bad-supplier',
    });
    expect(addEnvelopes(APP, k, 'x' as unknown as Envelope[], TODAY)).toEqual({
      ok: false,
      reason: 'bad-input',
    });
    expect(pruneMailbox(APP, k, 'nope')).toBeUndefined();
    expect(k.items).toHaveLength(1);
  });

  it("junk, another app's envelopes and look-alikes with a wrong id or day are counted, never stored", () => {
    const real = fake();
    const other = fake(TODAY, 0, 'other');
    const tampered = {
      ...plain(real),
      text: real.text.replace('"day":"2026-11-10"', '"day":"2026-11-09"'),
    };
    const wrongId = { ...plain(fake()), id: real.id.replace(/^./, 'Z') };
    const wrongDay = { ...plain(fake()), day: '2026-11-09' };
    const junk = [
      null,
      7,
      'x',
      {},
      { id: '__proto__', day: TODAY, text: '' },
      [],
      { id: real.id },
    ] as unknown as Envelope[];
    const r = add(EMPTY_MAILBOX, [other, plain(other), tampered, wrongId, wrongDay, ...junk]);
    expect(r.mailbox.items).toEqual([]);
    expect(r.invalid).toBe(5 + junk.length);
    expect(r.added).toEqual([]);
    // a hand-made look-alike of a good envelope is read again and taken
    const ok = add(EMPTY_MAILBOX, [plain(real)]);
    expect(ok.added).toHaveLength(1);
    expect(ok.added[0]).toEqual(real);
  });

  it('the stored envelopes cannot be changed from outside', () => {
    const k = add(EMPTY_MAILBOX, [fake()]).mailbox;
    expect(() => (k.items as Envelope[]).push(fake())).toThrow();
    expect(() => ((k.items[0] as { text: string }).text = 'x')).toThrow();
  });
});

describe('receipts: an app-supplied predicate decides who may acknowledge', () => {
  const office = (by: string) => by === 'office';

  it('a receipt of an allowed device drops what it covers; the rest stays', () => {
    const [x, y, z] = [fake(), fake('2026-11-09'), fake()];
    const k = add(EMPTY_MAILBOX, [x, y, z]).mailbox;
    const r = applyReceipts(APP, k, [{ by: 'office', ids: [x.id, y.id] }], office, TODAY);
    expect(r).toMatchObject({ ok: true, dropped: 2, refused: 0 });
    expect(r.ok && r.mailbox.items.map((e) => e.id)).toEqual([z.id]);
    // the covered ids are remembered: a neighbour cannot hand them back
    const back = add(r.ok ? r.mailbox : k, [x, y], { from: A });
    expect(back.added).toEqual([]);
    expect(back.rejected).toBe(0);
  });

  it('a receipt of a device that may not acknowledge, or a malformed one, is ignored and counted', () => {
    const x = fake();
    const k = add(EMPTY_MAILBOX, [x]).mailbox;
    const r = applyReceipts(
      APP,
      k,
      [
        { by: 'stranger', ids: [x.id] },
        { by: 'office', ids: ['not-an-id'] },
        null as never,
        { by: 'a|b', ids: [x.id] },
        { by: 'office' } as never,
      ],
      office,
      TODAY,
    );
    expect(r).toMatchObject({ ok: true, dropped: 0, refused: 4 });
    expect(r.ok && r.mailbox).toBe(k);
  });

  it('the predicate is asked once per device; a predicate that throws, or says "maybe", means no', () => {
    const x = fake();
    const k = add(EMPTY_MAILBOX, [x]).mailbox;
    const asked: string[] = [];
    applyReceipts(
      APP,
      k,
      [
        { by: 'o', ids: [] },
        { by: 'o', ids: [] },
        { by: 'p', ids: [] },
      ],
      (by) => (asked.push(by), true),
      TODAY,
    );
    expect(asked).toEqual(['o', 'p']);
    const boom = applyReceipts(
      APP,
      k,
      [{ by: 'o', ids: [x.id] }],
      () => {
        throw new Error('boom');
      },
      TODAY,
    );
    expect(boom).toMatchObject({ ok: true, dropped: 0, refused: 1 });
    const maybe = applyReceipts(APP, k, [{ by: 'o', ids: [x.id] }], (() => 1) as never, TODAY);
    expect(maybe).toMatchObject({ ok: true, dropped: 0, refused: 1 });
    expect(applyReceipts(APP, k, [], 'nope' as never, TODAY)).toEqual({
      ok: false,
      reason: 'bad-input',
    });
    expect(applyReceipts(APP, k, [], office, 'nope')).toEqual({ ok: false, reason: 'bad-day' });
  });

  it('nothing to drop and nothing to remember: the very same mailbox; ids of unknown envelopes are remembered', () => {
    const k = add(EMPTY_MAILBOX, [fake()]).mailbox;
    expect(applyReceipts(APP, k, [], office, TODAY)).toMatchObject({ ok: true, mailbox: k });
    const unknown = fake();
    const r = applyReceipts(APP, k, [{ by: 'office', ids: [unknown.id] }], office, TODAY);
    expect(r.ok && r.mailbox.items).toBe(k.items);
    expect(r.ok && r.mailbox.acknowledged).toEqual([{ id: unknown.id, day: TODAY }]);
    expect(add(r.ok ? r.mailbox : k, [unknown], { from: A }).added).toEqual([]);
    // the same receipt again changes nothing
    const again = applyReceipts(
      APP,
      r.ok ? r.mailbox : k,
      [{ by: 'office', ids: [unknown.id] }],
      office,
      TODAY,
    );
    expect(again.ok && again.mailbox).toBe(r.ok ? r.mailbox : k);
  });

  it('a remembered id is forgotten with its day: after the envelope would have expired anyway', () => {
    const x = fake('2026-11-01');
    const k = add(EMPTY_MAILBOX, [x]).mailbox;
    const r = applyReceipts(APP, k, [{ by: 'office', ids: [x.id] }], office, TODAY);
    const mb = r.ok ? r.mailbox : k;
    expect(mb.acknowledged).toEqual([{ id: x.id, day: '2026-11-01' }]);
    expect(pruneMailbox(APP, mb, '2026-11-30')?.acknowledged).toHaveLength(1);
    expect(pruneMailbox(APP, mb, '2026-12-01')?.acknowledged).toBeUndefined();
  });

  it('receipts are read strictly: fresh copies, nothing unknown', () => {
    const id = fake().id;
    const good = [{ by: 'office', ids: [id] }];
    const read = readReceipts(good);
    expect(read).toEqual(good);
    expect(read?.[0]).not.toBe(good[0]);
    expect(read?.[0]?.ids).not.toBe(good[0]?.ids);
    for (const bad of [
      'x',
      [{ by: 'office', ids: [id], extra: 1 }],
      [{ by: 'office' }],
      [{ by: '', ids: [] }],
      [{ by: 'office', ids: ['__proto__'] }],
      [{ by: 'office', ids: [`${id}=`] }],
      JSON.parse('[{"by":"o","ids":[],"__proto__":1}]'),
    ]) {
      expect(readReceipts(bad)).toBeUndefined();
    }
  });
});

describe('hostile ids are keys like any other', () => {
  const names = ['__proto__', 'toString', 'constructor', 'hasOwnProperty', 'valueOf', 'prototype'];

  it('devices with such names are counted separately and survive a round trip through JSON', () => {
    let k: Mailbox = EMPTY_MAILBOX;
    for (const [i, from] of names.entries()) {
      k = add(
        k,
        Array.from({ length: i + 1 }, () => fake()),
        { from },
      ).mailbox;
    }
    const today = deliveredToday(k, TODAY);
    expect(Object.getPrototypeOf(today)).toBeNull();
    expect(Object.keys(today).sort()).toEqual([...names].sort());
    expect(names.map((n) => today[n])).toEqual([1, 2, 3, 4, 5, 6]);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
    const text = JSON.stringify(k);
    expect(text).toContain('"__proto__"');
    const back = readMailbox(APP, JSON.parse(text));
    expect(back).toBeDefined();
    expect(deliveredToday(back as Mailbox, TODAY)).toEqual(today);
    expect(Object.getPrototypeOf(back?.delivered?.per)).toBeNull();
    // the quota counts on after the round trip
    const more = add(back as Mailbox, [fake()], { from: '__proto__' }).mailbox;
    expect(deliveredToday(more, TODAY)['__proto__']).toBe(2);
    expect(deliveredToday(more, TODAY)['toString']).toBe(2);
  });

  it('a device that is called __proto__ can acknowledge, and cannot reach the prototype', () => {
    const x = fake();
    const k = add(EMPTY_MAILBOX, [x]).mailbox;
    const r = applyReceipts(
      APP,
      k,
      [{ by: '__proto__', ids: [x.id] }],
      (by) => by === '__proto__',
      TODAY,
    );
    expect(r).toMatchObject({ ok: true, dropped: 1 });
    const no = applyReceipts(
      APP,
      k,
      [{ by: 'toString', ids: [x.id] }],
      (by) => by === '__proto__',
      TODAY,
    );
    expect(no).toMatchObject({ ok: true, dropped: 0, refused: 1 });
  });

  it('an envelope that claims such an id is not an envelope', () => {
    const r = add(EMPTY_MAILBOX, [
      { id: '__proto__', day: TODAY, text: '{}' },
      { id: 'toString', day: TODAY, text: '{}' },
    ]);
    expect(r.invalid).toBe(2);
    expect(r.mailbox.items).toEqual([]);
  });
});

describe('linear in the size of the mailbox', () => {
  const timed = (work: () => unknown, runs = 2): number => {
    let best = Infinity;
    for (let run = 0; run < runs; run += 1) {
      const t = performance.now();
      work();
      best = Math.min(best, performance.now() - t);
    }
    return best;
  };

  it('taking 2000 and 8000 envelopes (known and hand-made), check values and pruning grow about fourfold', () => {
    const sizes = [2000, 8000] as const;
    const all = Array.from({ length: 8000 }, (_, i) => fake(`2026-11-0${1 + (i % 9)}`));
    const made = sizes.map((n) => all.slice(0, n));
    const limits = { maxEnvelopes: 8000, maxChars: 1_000_000_000, maxPerSupplier: 8000 };
    // warm up
    add(EMPTY_MAILBOX, made[0] as Envelope[], { from: A, limits });
    const rows: Record<string, [number, number]> = {};
    const measure = (
      name: string,
      prepare: (n: number, list: Envelope[]) => () => unknown,
      runs = 2,
    ): void => {
      const [small, large] = sizes.map((n, i) => timed(prepare(n, made[i] as Envelope[]), runs));
      rows[name] = [small as number, large as number];
    };
    measure('add known', (_n, list) => () => add(EMPTY_MAILBOX, list, { from: A, limits }));
    measure(
      'add look-alikes',
      (_n, list) => {
        const flat = list.map(plain);
        return () => add(EMPTY_MAILBOX, flat, { from: A, limits });
      },
      1,
    );
    measure('trim', (_n, list) => {
      const box = mailboxOf(...list);
      return () => add(box, [], { limits: { ...limits, maxEnvelopes: 1000 } });
    });
    measure('checks', (_n, list) => {
      const box = mailboxOf(...list);
      return () => [dayChecks(APP, box), mailboxCheck(APP, box)];
    });
    measure('prune', (_n, list) => {
      const box = mailboxOf(...list);
      return () => pruneMailbox(APP, box, TODAY, limits);
    });
    for (const [name, [small, large]] of Object.entries(rows)) {
      // 4x the work: about 4x the time. Quadratic would be 16x; the bound leaves room for noise.
      expect(
        large / Math.max(small, 0.05),
        `${name}: ${small.toFixed(1)} ms -> ${large.toFixed(1)} ms`,
      ).toBeLessThan(9);
    }
  });
});

describe('two apps never read each other', () => {
  it('stored mailboxes, envelopes and receipts of one app are nothing to another', () => {
    const k = add(EMPTY_MAILBOX, [fake(), fake('2026-11-09')]).mailbox;
    expect(readMailbox('demo', JSON.parse(JSON.stringify(k)))).toBeDefined();
    expect(readMailbox('other', JSON.parse(JSON.stringify(k)))).toBeUndefined();
    const foreign = addEnvelopes('other', EMPTY_MAILBOX, k.items, TODAY);
    expect(foreign).toMatchObject({ ok: true, added: [], invalid: 2 });
    expect(dayChecks('other', k)).not.toEqual(dayChecks('demo', k));
    expect(mailboxCheck('other', k)).not.toBe(mailboxCheck('demo', k));
    expect(announcedStand('other', 'fp', k)).not.toBe(announcedStand('demo', 'fp', k));
  });
});

describe('stored state is read strictly (seeded fuzzing, 3500 inputs)', () => {
  it('round trips, and refuses every kind of damage', () => {
    const k = add(
      add(EMPTY_MAILBOX, [fake(), fake('2026-11-09')], { from: A }).mailbox,
      [],
    ).mailbox;
    const r = applyReceipts(APP, k, [{ by: 'office', ids: [fake().id] }], () => true, TODAY);
    const full = r.ok ? r.mailbox : k;
    const back = readMailbox(APP, JSON.parse(JSON.stringify(full)));
    expect(back).toEqual(full);
    expect(back).not.toBe(full);
    expect(back?.items[0]).not.toBe(full.items[0]);
    const base = JSON.parse(JSON.stringify(full)) as {
      items: { id: string; day: string; text: string }[];
    };
    const variants: unknown[] = [
      null,
      [],
      {},
      { ...base, extra: 1 },
      { items: 'x' },
      { items: [{ ...base.items[0], extra: 1 }] },
      { items: [{ ...base.items[0], day: '2026-11-09' }] },
      { items: [{ ...base.items[0], id: base.items[1]?.id }] },
      { items: [base.items[0], base.items[0]] },
      { ...base, delivered: { day: 'x', per: {} } },
      { ...base, delivered: { day: TODAY, per: { a: -1 } } },
      { ...base, delivered: { day: TODAY, per: { a: 1.5 } } },
      { ...base, delivered: { day: TODAY, per: { 'a|b': 1 } } },
      { ...base, delivered: { day: TODAY, per: { a: 401 } } },
      { ...base, acknowledged: [{ id: 'x', day: TODAY }] },
      { ...base, acknowledged: [{ id: base.items[0]?.id, day: TODAY, x: 1 }] },
      JSON.parse('{"items":[],"__proto__":{"x":1}}'),
    ];
    for (const v of variants) expect(readMailbox(APP, v)).toBeUndefined();
    expect(readMailbox(APP, { items: [] })).toEqual({ items: [] });
    expect(readMailbox(APP, base, { maxEnvelopes: 1 })).toBeUndefined();
    expect(readMailbox(APP, base, { maxChars: 10 })).toBeUndefined();
  });

  it('never throws on random input; whatever it takes, it takes in a form it writes again', () => {
    const k = add(EMPTY_MAILBOX, [fake(), fake('2026-11-09')], { from: A }).mailbox;
    const text = JSON.stringify(k);
    const next = rng(31337);
    let taken = 0;
    for (let i = 0; i < 3500; i += 1) {
      const pick = next();
      let input: unknown;
      if (pick < 0.4) input = safeParse(mutate(next, text));
      else if (pick < 0.7) input = randomJson(next);
      else input = { ...JSON.parse(text), ...(randomJson(next) as object) };
      let read: Mailbox | undefined;
      expect(() => {
        read = readMailbox(APP, input);
      }).not.toThrow();
      if (read) {
        taken += 1;
        expect(readMailbox(APP, JSON.parse(JSON.stringify(read)))).toEqual(read);
      }
    }
    expect(taken).toBeLessThan(3500);
  });

  it('receipts: never throws on random input', () => {
    const id = fake().id;
    const text = JSON.stringify([{ by: 'office', ids: [id] }]);
    const next = rng(99);
    for (let i = 0; i < 3500; i += 1) {
      const input = next() < 0.5 ? safeParse(mutate(next, text)) : randomJson(next);
      let read: unknown;
      expect(() => {
        read = readReceipts(input);
      }).not.toThrow();
      if (read) expect(readReceipts(JSON.parse(JSON.stringify(read)))).toEqual(read);
    }
  });
});

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
