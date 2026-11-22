import { randomBytes } from 'node:crypto';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import {
  ENVELOPE_LIMITS,
  FAN_GROUP,
  base64url,
  buildEnvelope,
  envelopeId,
  isKnownEnvelope,
  openEnvelope,
  readEnvelope,
  resolveEnvelopeLimits,
  sealEnvelope,
  shuffled,
  signText,
  type Envelope,
} from '../../src/core/index.ts';
import {
  refInner,
  refOpen,
  refSeal,
  refSigned,
  refText,
  type EnvelopeParts,
} from './envelope-reference.ts';
import {
  APP,
  DAY,
  bytes,
  member,
  open,
  reader,
  seal,
  seededRandom,
  show,
  type Member,
  type Reader,
} from './envelope-helpers.ts';
import { mutate, randomJson, rng } from './secure-helpers.ts';

let A: Member;
let B1: Member;
let B2: Member;
let C: Member;
beforeAll(async () => {
  [A, B1, B2, C] = await Promise.all([
    member('device-aaaa'),
    member('device-bbb1'),
    member('device-bbb2'),
    member('device-cccc'),
  ]);
});

const authors = (...ms: Member[]): Record<string, string> =>
  Object.fromEntries(ms.map((m) => [m.device, m.sig]));

const partsOf = (e: Envelope): EnvelopeParts => {
  const { day, eph, iv, kc, ct, k } = JSON.parse(e.text) as EnvelopeParts;
  return { day, eph, iv, kc, ct, k };
};

describe('sealing and opening (cases of both earlier implementations)', () => {
  it('every reader opens it, the author is known only inside; others cannot open it', async () => {
    const e = await seal(A, [B1.dh, B2.dh], { body: 'Can you take Thursday?' });
    expect(JSON.parse(e.text).k).toHaveLength(FAN_GROUP);
    for (const secret of [A.device, 'Thursday', A.sig, 'chan-1']) {
      expect(e.text).not.toContain(secret);
    }
    for (const r of [B1, B2]) {
      const got = await open(r, e, authors(A));
      expect(got).toMatchObject({ ok: true, from: A.device, channel: 'chan-1', day: DAY });
      expect(got.ok && show(got.body)).toBe('Can you take Thursday?');
      expect(got.ok && got.id).toBe(e.id);
    }
    expect(await open(C, e, authors(A))).toEqual({ ok: false, reason: 'not-for-me' });
    // the author's own device was not among the readers
    expect(await open(A, e, authors(A))).toEqual({ ok: false, reason: 'not-for-me' });
  });

  it('the author is checked against the key the lookup gives, and only a trusted author passes', async () => {
    const e = await seal(A, [B1.dh]);
    expect(await open(B1, e, authors(C))).toEqual({ ok: false, reason: 'unknown-author' });
    expect(await open(B1, e, { [A.device]: C.sig })).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
    expect(await open(B1, e, {})).toEqual({ ok: false, reason: 'unknown-author' });
  });

  it('the lookup is asked once, with the author found inside, and never for a stranger', async () => {
    const e = await seal(A, [B1.dh]);
    const asked: string[] = [];
    const lookup = (from: string): string => {
      asked.push(from);
      return A.sig;
    };
    const go = (m: Member) =>
      openEnvelope({
        appId: APP,
        own: { agreement: m.keys.agreement },
        envelope: e,
        authorKey: lookup,
      });
    expect((await go(B1)).ok).toBe(true);
    expect(asked).toEqual([A.device]);
    asked.length = 0;
    expect((await go(C)).ok).toBe(false);
    expect(asked).toEqual([]);
  });

  it('a lookup that throws, or gives rubbish or a point off the curve, is an unknown author', async () => {
    const e = await seal(A, [B1.dh]);
    const offCurve = base64url(Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 4 : 1)));
    for (const key of [
      () => {
        throw new Error('boom');
      },
      () => 'not a point',
      () => offCurve,
      () => undefined,
      () => 42 as unknown as string,
    ]) {
      const r = await openEnvelope({
        appId: APP,
        own: { agreement: B1.keys.agreement },
        envelope: e,
        authorKey: key,
      });
      expect(r).toEqual({ ok: false, reason: 'unknown-author' });
    }
  });

  it('a changed envelope does not open (content, day, key) and is not read (id)', async () => {
    const e = await seal(A, [B1.dh]);
    const p = partsOf(e);
    const flip = (s: string, at = 5): string =>
      s.slice(0, at) + (s[at] === 'A' ? 'B' : 'A') + s.slice(at + 1);
    const remake = (changed: Partial<EnvelopeParts>): string =>
      buildEnvelope(APP, { ...p, ...changed }).text;
    for (const changed of [{ ct: flip(p.ct) }, { day: '2026-11-11' }, { iv: flip(p.iv, 3) }]) {
      expect((await open(B1, remake(changed), authors(A))).ok).toBe(false);
    }
    const copy = JSON.parse(e.text) as Record<string, unknown>;
    expect(readEnvelope(APP, JSON.stringify({ ...copy, id: flip(e.id) }))).toBeUndefined();
    expect(readEnvelope(APP, JSON.stringify({ ...copy, ct: flip(p.ct) }))).toBeUndefined();
    expect(readEnvelope(APP, JSON.stringify({ ...copy, k: [...p.k].reverse() }))).toBeUndefined();
    expect(readEnvelope(APP, e.text)).toEqual(e);
  });

  it('is read strictly as it travels; refusals are codes and nothing throws', async () => {
    const e = await seal(A, [B1.dh]);
    const copy = JSON.parse(e.text) as { k: string[] } & Record<string, unknown>;
    expect(readEnvelope(APP, JSON.stringify({ ...copy, k: copy.k.slice(1) }))).toBeUndefined();
    expect(readEnvelope(APP, JSON.stringify({ ...copy, day: 'yesterday' }))).toBeUndefined();
    expect(readEnvelope(APP, JSON.stringify({ ...copy, extra: 1 }))).toBeUndefined();
    expect(readEnvelope(APP, ` ${e.text}`)).toBeUndefined();
    expect(readEnvelope(APP, e.text.replace('"id":', '"id" :'))).toBeUndefined();
    expect(readEnvelope(APP, 7)).toBeUndefined();
    expect(readEnvelope(APP, undefined)).toBeUndefined();
    expect(await open(B1, 'garbage', authors(A))).toEqual({ ok: false, reason: 'not-an-envelope' });
  });

  it('too much for one envelope, no recipient, too many recipients are refused with codes', async () => {
    const seal1 = (over: Record<string, unknown>) =>
      sealEnvelope({
        appId: APP,
        author: { device: A.device, signing: A.keys.signing.privateKey },
        recipients: [B1.dh],
        channel: 'c',
        day: DAY,
        body: bytes('x'),
        random: seededRandom(5),
        ...over,
      } as Parameters<typeof sealEnvelope>[0]);
    expect(await seal1({ body: new Uint8Array(20_000) })).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect(await seal1({ recipients: [] })).toEqual({ ok: false, reason: 'no-recipients' });
    expect(await seal1({ recipients: 'nope' })).toEqual({ ok: false, reason: 'no-recipients' });
    expect(await seal1({ recipients: ['x'] })).toEqual({ ok: false, reason: 'bad-recipient' });
    expect(await seal1({ recipients: [B1.dh, 3] })).toEqual({ ok: false, reason: 'bad-recipient' });
    const offCurve = base64url(Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 4 : 7)));
    expect(await seal1({ recipients: [offCurve] })).toEqual({ ok: false, reason: 'bad-recipient' });
    expect(await seal1({ channel: 'a|b' })).toEqual({ ok: false, reason: 'bad-channel' });
    expect(await seal1({ channel: '' })).toEqual({ ok: false, reason: 'bad-channel' });
    expect(await seal1({ day: '2026-02-30' })).toEqual({ ok: false, reason: 'bad-day' });
    expect(await seal1({ body: 'text' })).toEqual({ ok: false, reason: 'bad-input' });
    expect(await seal1({ author: { device: 'a|b', signing: A.keys.signing.privateKey } })).toEqual({
      ok: false,
      reason: 'bad-author',
    });
    expect(await seal1({ author: { device: A.device, signing: null } })).toEqual({
      ok: false,
      reason: 'bad-author',
    });
    expect(await seal1({ author: { device: A.device, signing: {} } })).toEqual({
      ok: false,
      reason: 'bad-author',
    });
    expect(await seal1({ random: () => new Uint8Array(3) })).toEqual({
      ok: false,
      reason: 'bad-random',
    });
    expect(
      await seal1({
        random: () => {
          throw new Error('no entropy');
        },
      }),
    ).toEqual({ ok: false, reason: 'bad-random' });
    expect(await seal1({ random: 'x' })).toEqual({ ok: false, reason: 'bad-random' });
    await expect(seal1({ appId: 'Bad-App' })).rejects.toThrow('invalid appId');
  });

  it('a refusal leaves the inputs as they were', async () => {
    const recipients = [B1.dh, B2.dh];
    const body = bytes('keep me');
    const before = [...recipients];
    await sealEnvelope({
      appId: APP,
      author: { device: A.device, signing: A.keys.signing.privateKey },
      recipients,
      channel: 'bad|channel',
      day: DAY,
      body,
      random: seededRandom(1),
    });
    expect(recipients).toEqual(before);
    expect(show(body)).toBe('keep me');
  });

  it('a recipient listed twice is one reader; the body is copied in and out', async () => {
    const body = bytes('copy');
    const e = await seal(A, [B1.dh, B1.dh], { body });
    body[0] = 0;
    const got = await open(B1, e, authors(A));
    expect(got.ok && show(got.body)).toBe('copy');
    if (got.ok) got.body[0] = 0;
    const again = await open(B1, e, authors(A));
    expect(again.ok && show(again.body)).toBe('copy');
  });

  it('names and channels may be any readable text, but a separator is refused', async () => {
    const odd = await member('gerät-ü-1');
    const e = await seal(odd, [B1.dh], { channel: 'kanal/ä-1', body: '' });
    expect(await open(B1, e, authors(odd))).toMatchObject({
      ok: true,
      from: 'gerät-ü-1',
      channel: 'kanal/ä-1',
    });
  });
});

describe('what the envelope hides', () => {
  it('hides the number of readers up to the next multiple of 8, also in its size', async () => {
    const readers = await Promise.all(Array.from({ length: 17 }, () => reader()));
    const sizes: number[] = [];
    for (const n of [1, 2, 7, 8]) {
      const e = await seal(
        A,
        readers.slice(0, n).map((r) => r.dh),
      );
      expect(JSON.parse(e.text).k).toHaveLength(8);
      sizes.push(e.text.length);
    }
    expect(new Set(sizes).size).toBe(1);
    const nine = await seal(
      A,
      readers.slice(0, 9).map((r) => r.dh),
    );
    const seventeen = await seal(
      A,
      readers.map((r) => r.dh),
    );
    expect(JSON.parse(nine.text).k).toHaveLength(16);
    expect(JSON.parse(seventeen.text).k).toHaveLength(24);
    for (const [r, env] of [
      [readers[0], nine],
      [readers[8], nine],
      [readers[16], seventeen],
    ] as [Reader, Envelope][]) {
      const got = await open({ pair: r.pair }, env, authors(A));
      expect(got.ok).toBe(true);
    }
  });

  it('the slots look alike: all are 64 canonical characters, real or padding', async () => {
    const e = await seal(A, [B1.dh]);
    for (const slot of JSON.parse(e.text).k as string[])
      expect(slot).toMatch(/^[A-Za-z0-9_-]{64}$/);
  });

  it('shuffles the slots: the place of the one real slot is uniform (seeded, 240 envelopes)', async () => {
    const r = await reader();
    const random = seededRandom(20261122);
    const hits = new Array<number>(8).fill(0);
    for (let i = 0; i < 240; i += 1) {
      const e = await seal(A, [r.dh], { random });
      const opened = refOpen(APP, e.text, r.jwk);
      hits[opened?.slotIndex ?? -1] = (hits[opened?.slotIndex ?? -1] ?? 0) + 1;
    }
    const expected = 240 / 8;
    const chi = hits.reduce((sum, n) => sum + (n - expected) ** 2 / expected, 0);
    // chi-square, 7 degrees of freedom: 24.3 is the 0.1 % point
    expect(chi).toBeLessThan(24.3);
    expect(hits.every((n) => n > 0)).toBe(true);
  });

  it('shuffled is a permutation and moves things for different bytes (unit)', () => {
    const list = [0, 1, 2, 3, 4, 5, 6, 7];
    const out = shuffled(list, seededRandom(3)(32));
    expect([...out].sort()).toEqual(list);
    expect(out).not.toEqual(list);
    expect(list).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(shuffled(list, seededRandom(4)(32))).not.toEqual(out);
    expect(shuffled(list, new Uint8Array(32))).toEqual([1, 2, 3, 4, 5, 6, 7, 0]);
  });

  it('shows a carrier nothing but the id, the day, the size and fresh-looking keys', async () => {
    const e = await seal(A, [B1.dh, B2.dh], { body: 'secret body', channel: 'secret-channel' });
    const second = await seal(A, [B1.dh, B2.dh], {
      body: 'secret body',
      channel: 'secret-channel',
    });
    const p = partsOf(e);
    const q = partsOf(second);
    // same author, readers, channel and body: nothing repeats that could link them
    expect(p.eph).not.toBe(q.eph);
    expect(p.iv).not.toBe(q.iv);
    expect(p.ct).not.toBe(q.ct);
    expect(p.k.filter((s) => q.k.includes(s))).toEqual([]);
    for (const text of [A.device, B1.device, B1.dh, B2.dh, A.sig, 'secret']) {
      expect(e.text).not.toContain(text);
    }
  });
});

describe('only the listed readers open it, at a bounded cost', () => {
  function calls(): { counts: () => Record<string, number>; restore: () => void } {
    const names = ['deriveBits', 'deriveKey', 'decrypt', 'verify', 'importKey'] as const;
    const spies = names.map((name) => vi.spyOn(crypto.subtle, name));
    return {
      counts: () => Object.fromEntries(names.map((n, i) => [n, spies[i]?.mock.calls.length ?? 0])),
      restore: () => spies.forEach((s) => s.mockRestore()),
    };
  }

  it('a stranger costs one ECDH, one key derivation and at most one decryption per slot', async () => {
    const readers = await Promise.all(Array.from({ length: 64 }, () => reader()));
    const e = await seal(
      A,
      readers.map((r) => r.dh),
    );
    expect(JSON.parse(e.text).k).toHaveLength(64);
    const spy = calls();
    try {
      expect(await open(C, e, authors(A))).toEqual({ ok: false, reason: 'not-for-me' });
      const c = spy.counts();
      expect(c.deriveBits).toBe(1);
      expect(c.deriveKey).toBe(1);
      expect(c.decrypt).toBe(64);
      expect(c.verify).toBe(0);
      expect(c.importKey).toBe(2); // the ephemeral point, the HKDF material
    } finally {
      spy.restore();
    }
  });

  it('a reader costs the same plus one content decryption and one signature check', async () => {
    const e = await seal(A, [B1.dh]);
    const spy = calls();
    try {
      expect((await open(B1, e, authors(A))).ok).toBe(true);
      const c = spy.counts();
      expect(c.deriveBits).toBe(1);
      expect(c.deriveKey).toBe(1);
      expect(c.decrypt).toBeLessThanOrEqual(8 + 1);
      expect(c.verify).toBe(1);
    } finally {
      spy.restore();
    }
  });

  it('a sealer that wraps the key for one reader in every slot costs one content decryption only', async () => {
    const r = await reader();
    const eph = await reader();
    const made = refSeal({
      appId: APP,
      day: DAY,
      ephPriv: eph.jwk,
      readers: Array.from({ length: 8 }, () => r.dh),
      contentKey: randomBytes(32),
      iv: randomBytes(12),
      padding: [],
      inner: refInner(A.device, 'c', 'A'.repeat(86), ''),
    });
    const spy = calls();
    try {
      await open({ pair: r.pair }, made.text, authors(A));
      // the first slot that opens decides: one slot trial and one content decryption
      expect(spy.counts().decrypt).toBe(2);
    } finally {
      spy.restore();
    }
  });

  it('the fan limit is a limit: 64 readers fit, 65 do not; it is rounded to a multiple of 8', async () => {
    const readers = await Promise.all(Array.from({ length: 66 }, () => reader()));
    const dhs = readers.map((r) => r.dh);
    expect(JSON.parse((await seal(A, dhs.slice(0, 64), { body: '' })).text).k).toHaveLength(64);
    await expect(seal(A, dhs.slice(0, 65))).rejects.toThrow('too-many-recipients');
    expect(resolveEnvelopeLimits({ maxFans: 20 }).maxFans).toBe(16);
    expect(resolveEnvelopeLimits({ maxFans: 3 }).maxFans).toBe(8);
    expect(resolveEnvelopeLimits({ maxFans: -1 }).maxFans).toBe(64);
    await expect(seal(A, dhs.slice(0, 17), { limits: { maxFans: 16 } })).rejects.toThrow(
      'too-many-recipients',
    );
    const small = await seal(A, dhs.slice(0, 16), { limits: { maxFans: 16 }, body: '' });
    // a reader with the default limit takes it, one with a smaller limit refuses it
    expect(readEnvelope(APP, small.text)).toBeDefined();
    expect(readEnvelope(APP, small.text, { maxFans: 8 })).toBeUndefined();
  });

  it('the size limit is exact: the largest envelope is read, one character more is not', async () => {
    const e = await seal(A, [B1.dh], { body: new Uint8Array(500) });
    const n = e.text.length;
    expect(readEnvelope(APP, e.text, { maxEnvelopeBytes: n })).toBeDefined();
    expect(readEnvelope(APP, e.text, { maxEnvelopeBytes: n - 1 })).toBeUndefined();
    // sealing: the biggest body that fits the default limit is accepted, a bigger one is refused
    let low = 0;
    let high = 9000;
    while (high - low > 1) {
      const mid = Math.floor((low + high) / 2);
      const r = await sealEnvelope({
        appId: APP,
        author: { device: A.device, signing: A.keys.signing.privateKey },
        recipients: [B1.dh],
        channel: 'chan-1',
        day: DAY,
        body: new Uint8Array(mid),
        random: seededRandom(mid),
      });
      if (r.ok) {
        expect(r.envelope.text.length).toBeLessThanOrEqual(ENVELOPE_LIMITS.maxEnvelopeBytes);
        low = mid;
      } else {
        expect(r.reason).toBe('too-large');
        high = mid;
      }
    }
    expect(low).toBeGreaterThan(5000);
    expect(low).toBeLessThan(8250);
  });
});

describe('the author signs app, sender, channel, day and content (a carrier cannot relabel)', () => {
  // A hostile READER (it holds the content key) builds envelopes with any inside it likes, using
  // the independent reference. It can copy the author's signature, but not make a new one.
  async function forged(
    options: {
      signed?: { appId?: string; from?: string; channel?: string; day?: string; body?: string };
      inner?: { from?: string; channel?: string; body?: string; sig?: string };
      day?: string;
      appId?: string;
      innerText?: string;
    } = {},
  ): Promise<{ r: Reader; text: string }> {
    const r = await reader();
    const eph = await reader();
    const signed = {
      appId: APP,
      from: A.device,
      channel: 'chan-1',
      day: DAY,
      body: base64url(bytes('truth')),
      ...options.signed,
    };
    const sig = await signText(
      A.keys.signing.privateKey,
      refSigned(signed.appId, signed.from, signed.channel, signed.day, signed.body),
    );
    const inner = {
      from: A.device,
      channel: 'chan-1',
      body: base64url(bytes('truth')),
      sig,
      ...options.inner,
    };
    const made = refSeal({
      appId: options.appId ?? APP,
      day: options.day ?? DAY,
      ephPriv: eph.jwk,
      readers: [r.dh],
      contentKey: randomBytes(32),
      iv: randomBytes(12),
      padding: Array.from({ length: 7 }, () => randomBytes(48)),
      inner: options.innerText ?? refInner(inner.from, inner.channel, inner.sig, inner.body),
    });
    return { r, text: made.text };
  }
  const reason = async (f: { r: Reader; text: string }, table = authors(A, B1)) => {
    const got = await open({ pair: f.r.pair }, f.text, table);
    return got.ok ? 'accepted' : got.reason;
  };

  it('control: an honest inside built by the reference opens (the documented texts are enough)', async () => {
    const f = await forged();
    const got = await open({ pair: f.r.pair }, f.text, authors(A));
    expect(got.ok && show(got.body)).toBe('truth');
  });

  it('a relabelled author, channel, content or day is never accepted', async () => {
    expect(await reason(await forged({ inner: { from: B1.device } }))).toBe('bad-signature');
    expect(await reason(await forged({ inner: { channel: 'chan-2' } }))).toBe('bad-signature');
    expect(await reason(await forged({ inner: { body: base64url(bytes('lie')) } }))).toBe(
      'bad-signature',
    );
    expect(await reason(await forged({ day: '2026-11-11' }))).toBe('bad-signature');
    // the author is unknown to the receiver: the claim itself is refused
    expect(await reason(await forged({ inner: { from: 'device-nobody' } }))).toBe('unknown-author');
  });

  it('the signature binds the app', async () => {
    // signed for another app, sealed as ours
    expect(await reason(await forged({ signed: { appId: 'other' } }))).toBe('bad-signature');
    // sealed for another app, offered to ours: not an envelope of ours at all
    expect(await reason(await forged({ appId: 'other', signed: { appId: 'other' } }))).toBe(
      'not-an-envelope',
    );
  });

  it('fields are length-prefixed: the same characters split differently do not verify', async () => {
    // signed as from "device-aaaa" + channel "x", presented as from "device-aaa" + channel "ax"
    const f = await forged({
      signed: { from: 'device-aaaa', channel: 'x' },
      inner: { from: 'device-aaa', channel: 'ax' },
    });
    // the same key is registered under both ids: only the length prefixes tell the texts apart
    expect(await reason(f, { 'device-aaa': A.sig, 'device-aaaa': A.sig })).toBe('bad-signature');
  });

  it('a malformed inside is "damaged", never accepted', async () => {
    const sig = 'A'.repeat(86);
    const body = base64url(bytes('x'));
    const bad = [
      `{"from":"a","channel":"c","sig":"${sig}","body":"${body}","x":1}`,
      `{"channel":"c","from":"a","sig":"${sig}","body":"${body}"}`,
      ` {"from":"a","channel":"c","sig":"${sig}","body":"${body}"}`,
      `{"from":"a","channel":"c","sig":"${sig}","body":"${body}=="}`,
      `{"from":"a","channel":"c","sig":"short","body":"${body}"}`,
      `{"from":"a|b","channel":"c","sig":"${sig}","body":"${body}"}`,
      `{"from":"a","from":"b","channel":"c","sig":"${sig}","body":"${body}"}`,
      `{"__proto__":{},"channel":"c","sig":"${sig}","body":"${body}"}`,
      '[]',
      'null',
      '﻿{}',
    ];
    for (const innerText of bad) {
      expect(await reason(await forged({ innerText }))).toBe('damaged');
    }
  });

  it('a high-s twin of a good signature is refused', async () => {
    const f = await forged();
    const got = await open({ pair: f.r.pair }, f.text, authors(A));
    expect(got.ok).toBe(true);
    const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const signed = refSigned(APP, A.device, 'chan-1', DAY, base64url(bytes('truth')));
    const sig = Buffer.from(await signText(A.keys.signing.privateKey, signed), 'base64url');
    const s = BigInt(`0x${sig.subarray(32).toString('hex')}`);
    const twin = Buffer.concat([
      sig.subarray(0, 32),
      Buffer.from((order - s).toString(16).padStart(64, '0'), 'hex'),
    ]);
    const g = await forged({ inner: { sig: base64url(twin) } });
    expect(await reason(g, authors(A))).toBe('bad-signature');
  });
});

describe('tamper sweeps', () => {
  it('flipping any single character of the wire text is never read', async () => {
    const e = await seal(A, [B1.dh]);
    let tried = 0;
    for (let i = 0; i < e.text.length; i += 1) {
      const original = e.text[i] as string;
      const changed = e.text.slice(0, i) + (original === 'x' ? 'y' : 'x') + e.text.slice(i + 1);
      expect(readEnvelope(APP, changed)).toBeUndefined();
      tried += 1;
    }
    expect(tried).toBe(e.text.length);
  });

  it('with the id recomputed, no change to day, ephemeral key, nonce or content is ever accepted', async () => {
    const e = await seal(A, [B1.dh], { body: 'one reader, eight slots' });
    const p = partsOf(e);
    let tried = 0;
    let refused = 0;
    for (const name of ['day', 'eph', 'iv', 'kc', 'ct'] as const) {
      const value = p[name];
      for (let i = 0; i < value.length; i += 1) {
        const ch = value[i] as string;
        const swap = name === 'day' ? (ch === '1' ? '2' : '1') : ch === 'A' ? 'B' : 'A';
        const changed = value.slice(0, i) + swap + value.slice(i + 1);
        tried += 1;
        // a changed text may not even be a valid envelope any more
        const text = (() => {
          try {
            return buildEnvelope(APP, { ...p, [name]: changed }).text;
          } catch {
            return undefined;
          }
        })();
        if (text === undefined) {
          refused += 1;
          continue;
        }
        const got = await open(B1, text, authors(A));
        if (!got.ok) refused += 1;
        else expect(show(got.body)).toBe('one reader, eight slots');
      }
    }
    // every change either does not make an envelope or does not open
    expect(refused).toBe(tried);
  });

  it('changes to a slot never change what is accepted (they only lose the reader)', async () => {
    const e = await seal(A, [B1.dh], { body: 'same' });
    const p = partsOf(e);
    let lost = 0;
    for (let slot = 0; slot < p.k.length; slot += 1) {
      const k = [...p.k];
      const old = k[slot] as string;
      k[slot] = (old[0] === 'A' ? 'B' : 'A') + old.slice(1);
      const got = await open(B1, buildEnvelope(APP, { ...p, k }).text, authors(A));
      if (got.ok) expect(show(got.body)).toBe('same');
      else {
        expect(got.reason).toBe('not-for-me');
        lost += 1;
      }
    }
    expect(lost).toBe(1);
  });
});

/** The text with its sixth character replaced by a different one (a fixed 'B' is sometimes the same). */
function changeChar(text: string): string {
  return `${text.slice(0, 5)}${text[5] === 'B' ? 'C' : 'B'}${text.slice(6)}`;
}

describe('ids', () => {
  it('are stable, depend on every member and on the app, and do not collide in a sample', async () => {
    const e = await seal(A, [B1.dh]);
    const p = partsOf(e);
    expect(envelopeId(APP, p)).toBe(e.id);
    expect(envelopeId('other', p)).not.toBe(e.id);
    const variants: EnvelopeParts[] = [
      { ...p, day: '2026-11-11' },
      { ...p, eph: changeChar(p.eph) },
      { ...p, iv: changeChar(p.iv) },
      { ...p, kc: changeChar(p.kc) },
      { ...p, ct: changeChar(p.ct) },
      { ...p, k: p.k.slice(1) },
      { ...p, k: [...p.k].reverse() },
    ];
    for (const v of variants) expect(envelopeId(APP, v)).not.toBe(e.id);
    const ids = new Set<string>();
    for (let n = 0; n < 2000; n += 1) {
      const parts: EnvelopeParts = {
        ...p,
        ct: base64url(
          new Uint8Array([n >> 8, n & 255, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        ),
      };
      ids.add(envelopeId(APP, parts));
    }
    expect(ids.size).toBe(2000);
    // an id is the reference's id too (written from the document)
    expect(refText(APP, e.id, p)).toBe(e.text);
  });

  it('length prefixes: members cannot be shifted into each other', () => {
    const base: EnvelopeParts = {
      day: DAY,
      eph: `B${'A'.repeat(86)}`,
      iv: 'A'.repeat(16),
      kc: 'A'.repeat(43),
      ct: 'A'.repeat(40),
      k: Array.from({ length: 8 }, () => 'A'.repeat(64)),
    };
    const shifted: EnvelopeParts = { ...base, iv: `${base.iv}A`, ct: base.ct.slice(1) };
    expect(envelopeId(APP, shifted)).not.toBe(envelopeId(APP, base));
  });
});

describe('two apps never read each other', () => {
  it('an envelope of one app is not an envelope of another, and does not open there', async () => {
    const e = await seal(A, [B1.dh]);
    expect(readEnvelope('other', e.text)).toBeUndefined();
    expect(isKnownEnvelope(e, APP)).toBe(true);
    expect(isKnownEnvelope(e, 'other')).toBe(false);
    expect(isKnownEnvelope({ ...e }, APP)).toBe(false);
    expect(await open(B1, e.text, authors(A), { appId: 'other' })).toEqual({
      ok: false,
      reason: 'not-an-envelope',
    });
    const other = await seal(A, [B1.dh], { appId: 'other' });
    expect(readEnvelope(APP, other.text)).toBeUndefined();
    expect((await open(B1, other, authors(A), { appId: 'other' })).ok).toBe(true);
  });
});

describe('strict reader fuzzing (seeded, 3500 inputs)', () => {
  it('never throws, reads only what it writes, and gives fresh copies', async () => {
    const e = await seal(A, [B1.dh, B2.dh]);
    const next = rng(777);
    let accepted = 0;
    for (let i = 0; i < 3500; i += 1) {
      const pick = next();
      const input: unknown =
        pick < 0.5
          ? mutate(next, e.text)
          : pick < 0.7
            ? JSON.stringify(randomJson(next))
            : pick < 0.8
              ? randomJson(next)
              : pick < 0.9
                ? e.text.slice(0, Math.floor(next() * e.text.length))
                : mutate(next, JSON.stringify({ ...JSON.parse(e.text), k: JSON.parse(e.text).k }));
      let read: Envelope | undefined;
      expect(() => {
        read = readEnvelope(APP, input);
      }).not.toThrow();
      if (read) {
        accepted += 1;
        // what is read is exactly what was given, once more readable
        expect(read.text).toBe(input);
        expect(readEnvelope(APP, read.text)).toEqual(read);
        expect(readEnvelope(APP, read.text)).not.toBe(read);
      }
    }
    // the unchanged text is among the inputs now and then: the reader is not refusing everything
    expect(readEnvelope(APP, e.text)).toBeDefined();
    expect(accepted).toBeLessThan(3500);
  });

  it('opening mutated envelopes never throws and never changes what is accepted', async () => {
    const e = await seal(A, [B1.dh], { body: 'fixed' });
    const next = rng(4242);
    for (let i = 0; i < 300; i += 1) {
      const text = mutate(next, e.text);
      const got = await open(B1, text, authors(A));
      if (got.ok) expect(show(got.body)).toBe('fixed');
    }
  });
});
