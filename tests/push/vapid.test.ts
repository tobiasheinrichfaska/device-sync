// VAPID (RFC 8292): the RFC's example token, tokens built here verified by node:crypto, and the checker's
// refusals (audience, expiry, 24 h rule, spelling, signature, key).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  buildVapid,
  checkVapid,
  generateVapidKeys,
  isRingVapid,
  isSubject,
  splitVapidHeader,
  vapidAudience,
} from '../../src/push/index.ts';
import { b64, refVerifyJwt, unb64 } from './reference.ts';

const V = (
  JSON.parse(readFileSync(new URL('../vectors/push.json', import.meta.url), 'utf8')) as {
    rfc8292: Record<string, string | number>;
  }
).rfc8292;
const s = (k: string): string => V[k] as string;

const NOW = 1_453_500_000;
const ENDPOINT = 'https://push.example.net/p/abc';
const textOf = (seg: string): string => unb64(seg).toString('utf8');

describe('the RFC 8292 example token', () => {
  it('is built from the documented JSON texts and verifies with the published key (independently)', () => {
    const [h, c] = s('jwt').split('.') as [string, string];
    expect(textOf(h)).toBe(s('jwtHeader'));
    expect(textOf(c)).toBe(s('jwtClaims'));
    expect(b64(Buffer.from(s('jwtHeader')))).toBe(h);
    expect(b64(Buffer.from(s('jwtClaims')))).toBe(c);
    expect(refVerifyJwt(s('jwt'), s('publicKey'))).toBe(true);
  });

  it('checkVapid accepts it when it is written in the one spelling, with the RFC time', async () => {
    const header = `vapid t=${s('jwt')}, k=${s('publicKey')}`;
    const ok = await checkVapid({ header, endpoint: s('endpoint'), nowS: 1_453_523_768 - 3600 });
    expect(ok).toEqual({
      ok: true,
      value: {
        publicKey: s('publicKey'),
        expiresS: 1_453_523_768,
        subject: 'mailto:push@example.com',
      },
    });
  });

  it('is refused for a token one second after exp, and for another audience', async () => {
    const header = `vapid t=${s('jwt')}, k=${s('publicKey')}`;
    const late = await checkVapid({ header, endpoint: s('endpoint'), nowS: 1_453_523_769 });
    expect(late).toEqual({ ok: false, reason: 'expired' });
    const edge = await checkVapid({ header, endpoint: s('endpoint'), nowS: 1_453_523_768 });
    expect(edge.ok).toBe(true);
    const other = await checkVapid({ header, endpoint: 'https://other.example.net/x', nowS: 1 });
    expect(other).toEqual({ ok: false, reason: 'audience' });
  });
});

describe('buildVapid', () => {
  it('builds a token a second implementation verifies, in exactly the relay form', async () => {
    const keys = await generateVapidKeys();
    const r = await buildVapid({
      endpoint: ENDPOINT,
      ...keys,
      nowS: NOW,
      subject: 'mailto:ops@example.org',
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(isRingVapid(r.value.header)).toBe(true);
    const parts = splitVapidHeader(r.value.header)!;
    expect(parts.key).toBe(keys.publicKey);
    expect(refVerifyJwt(`${parts.header}.${parts.claims}.${parts.signature}`, keys.publicKey)).toBe(
      true,
    );
    expect(textOf(parts.header)).toBe('{"typ":"JWT","alg":"ES256"}');
    expect(textOf(parts.claims)).toBe(
      `{"aud":"https://push.example.net","exp":${NOW + 43_200},"sub":"mailto:ops@example.org"}`,
    );
    expect(unb64(parts.signature)).toHaveLength(64);
    expect(r.value).toMatchObject({ audience: 'https://push.example.net', expiresS: NOW + 43_200 });
  });

  it('the claims have no sub when none was given; exp is exactly now + lifetime', async () => {
    const keys = await generateVapidKeys();
    const r = await buildVapid({ endpoint: ENDPOINT, ...keys, nowS: NOW, lifetimeS: 60 });
    const parts = splitVapidHeader(r.ok ? r.value.header : '')!;
    expect(textOf(parts.claims)).toBe(`{"aud":"https://push.example.net","exp":${NOW + 60}}`);
  });

  it('the 24 hour rule: 86400 is the last lifetime, 86401 and 0 are refused', async () => {
    const keys = await generateVapidKeys();
    const at = async (lifetimeS: number) =>
      buildVapid({ endpoint: ENDPOINT, ...keys, nowS: NOW, lifetimeS });
    expect((await at(86_400)).ok).toBe(true);
    expect(await at(86_401)).toEqual({ ok: false, reason: 'lifetime' });
    expect(await at(0)).toEqual({ ok: false, reason: 'lifetime' });
    expect(await at(1.5)).toEqual({ ok: false, reason: 'lifetime' });
    expect(await at(NaN)).toEqual({ ok: false, reason: 'lifetime' });
  });

  it('refuses bad inputs with codes', async () => {
    const keys = await generateVapidKeys();
    const other = await generateVapidKeys();
    const mk = (over: Record<string, unknown>) =>
      buildVapid({ endpoint: ENDPOINT, ...keys, nowS: NOW, ...over } as never);
    expect(await mk({ endpoint: 'http://push.example.net/x' })).toEqual({
      ok: false,
      reason: 'audience',
    });
    expect(await mk({ endpoint: 5 })).toEqual({ ok: false, reason: 'audience' });
    expect(await mk({ nowS: -1 })).toEqual({ ok: false, reason: 'time' });
    expect(await mk({ nowS: 1.5 })).toEqual({ ok: false, reason: 'time' });
    expect(await mk({ subject: 'ops@example.org' })).toEqual({ ok: false, reason: 'subject' });
    expect(await mk({ subject: 'mailto:a b@c' })).toEqual({ ok: false, reason: 'subject' });
    expect(await mk({ publicKey: 'AAAA' })).toEqual({ ok: false, reason: 'vapid-key' });
    expect(await mk({ privateKey: {} })).toEqual({ ok: false, reason: 'vapid-key' });
    expect(await mk({ publicKey: other.publicKey })).toEqual({ ok: false, reason: 'key-mismatch' });
  });

  it('a private key that cannot sign is a code, not an exception', async () => {
    const keys = await generateVapidKeys();
    const dh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
      'deriveBits',
    ]);
    const r = await buildVapid({
      endpoint: ENDPOINT,
      ...keys,
      privateKey: dh.privateKey,
      nowS: NOW,
    });
    expect(r).toEqual({ ok: false, reason: 'crypto' });
  });
});

describe('checkVapid refusals', () => {
  const build = async (over: Record<string, unknown> = {}) => {
    const keys = await generateVapidKeys();
    const r = await buildVapid({
      endpoint: ENDPOINT,
      ...keys,
      nowS: NOW,
      subject: 'https://app.example/contact',
      ...over,
    } as never);
    if (!r.ok) throw new Error(r.reason);
    return { header: r.value.header, keys };
  };
  const check = (header: string, over: Record<string, unknown> = {}) =>
    checkVapid({ header, endpoint: ENDPOINT, nowS: NOW, ...over });

  it('accepts what buildVapid wrote and reports key, expiry and contact', async () => {
    const { header, keys } = await build();
    expect(await check(header)).toEqual({
      ok: true,
      value: {
        publicKey: keys.publicKey,
        expiresS: NOW + 43_200,
        subject: 'https://app.example/contact',
      },
    });
  });

  it('expiry and the 24 hour rule from the checker side', async () => {
    const { header } = await build({ lifetimeS: 100 });
    expect((await check(header, { nowS: NOW + 100 })).ok).toBe(true);
    expect(await check(header, { nowS: NOW + 101 })).toEqual({ ok: false, reason: 'expired' });
    const far = await build({ lifetimeS: 86_400 });
    expect((await check(far.header, { nowS: NOW })).ok).toBe(true);
    expect(await check(far.header, { nowS: NOW - 1 })).toEqual({ ok: false, reason: 'lifetime' });
  });

  it('the audience is the origin of the endpoint, not the path', async () => {
    const { header } = await build();
    expect((await check(header, { endpoint: 'https://push.example.net/other/path' })).ok).toBe(
      true,
    );
    expect(await check(header, { endpoint: 'https://push.example.net:8443/x' })).toEqual({
      ok: false,
      reason: 'audience',
    });
    expect(await check(header, { endpoint: 'https://evil.example.net/x' })).toEqual({
      ok: false,
      reason: 'audience',
    });
    expect(await check(header, { endpoint: 'nonsense' })).toEqual({
      ok: false,
      reason: 'audience',
    });
  });

  it('a changed signature, claims or key is refused', async () => {
    const { header } = await build();
    const p = splitVapidHeader(header)!;
    const flip = (seg: string, at: number): string => {
      const raw = unb64(seg);
      raw[at] = (raw[at] as number) ^ 1;
      return b64(raw);
    };
    for (let at = 0; at < 64; at += 8) {
      const h = `vapid t=${p.header}.${p.claims}.${flip(p.signature, at)}, k=${p.key}`;
      expect(await check(h)).toEqual({ ok: false, reason: 'signature' });
    }
    const other = await generateVapidKeys();
    expect(
      await check(`vapid t=${p.header}.${p.claims}.${p.signature}, k=${other.publicKey}`),
    ).toEqual({ ok: false, reason: 'signature' });
    const claims = b64(Buffer.from(`{"aud":"https://push.example.net","exp":${NOW + 99}}`));
    expect(await check(`vapid t=${p.header}.${claims}.${p.signature}, k=${p.key}`)).toEqual({
      ok: false,
      reason: 'signature',
    });
  });

  it('a key that is not a curve point is refused', async () => {
    const { header } = await build();
    const p = splitVapidHeader(header)!;
    const raw = unb64(p.key);
    raw[64] = (raw[64] as number) ^ 1;
    expect(await check(`vapid t=${p.header}.${p.claims}.${p.signature}, k=${b64(raw)}`)).toEqual({
      ok: false,
      reason: 'key',
    });
  });

  it('one spelling only: other spacing, order, header member, claims, extra claims, bad sub', async () => {
    const keys = await generateVapidKeys();
    const sign = async (headerText: string, claimsText: string) => {
      const input = `${b64(Buffer.from(headerText))}.${b64(Buffer.from(claimsText))}`;
      const sig = new Uint8Array(
        await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          keys.privateKey,
          Buffer.from(input),
        ),
      );
      return `vapid t=${input}.${b64(sig)}, k=${keys.publicKey}`;
    };
    const aud = 'https://push.example.net';
    const goodH = '{"typ":"JWT","alg":"ES256"}';
    const goodC = `{"aud":"${aud}","exp":${NOW + 10}}`;
    expect((await check(await sign(goodH, goodC))).ok).toBe(true);
    const bad: [string, string, string][] = [
      ['{"alg":"ES256","typ":"JWT"}', goodC, 'token'],
      ['{"typ":"JWT","alg":"none"}', goodC, 'token'],
      [goodH, `{"exp":${NOW + 10},"aud":"${aud}"}`, 'claims'],
      [goodH, `{"aud":"${aud}","exp":${NOW + 10},"extra":1}`, 'claims'],
      [goodH, `{"aud":"${aud}","exp":${NOW + 10},"sub":"x"}`, 'claims'],
      [goodH, `{"aud":"${aud}","exp":"${NOW + 10}"}`, 'claims'],
      [goodH, `{"aud":"${aud}","exp":${NOW + 10}.5}`, 'claims'],
      [goodH, `{"aud":"${aud}", "exp":${NOW + 10}}`, 'claims'],
      [goodH, `{"aud":"${aud}","aud":"${aud}","exp":${NOW + 10}}`, 'claims'],
      [goodH, `{"aud":"${aud}","exp":${NOW + 10},"__proto__":{}}`, 'claims'],
      [goodH, `[1]`, 'claims'],
      [goodH, `not json`, 'claims'],
    ];
    for (const [h, c, reason] of bad)
      expect(await check(await sign(h, c)), c).toEqual({ ok: false, reason });
    const good = await sign(goodH, goodC);
    for (const h of [
      good.replace(', k=', ',k='),
      good.replace('vapid t=', 'vapid  t='),
      good.replace('vapid t=', 'VAPID t='),
      good + ' ',
      good.replace(/t=([^,]+), k=(.*)$/, 'k=$2, t=$1'),
      '',
    ])
      expect(await check(h)).toEqual({ ok: false, reason: 'header' });
    expect(await check(5 as never)).toEqual({ ok: false, reason: 'header' });
  });

  it('1000 seeded mutations of a valid header never throw and never pass', async () => {
    const { header } = await build();
    let seed = 7;
    const rnd = () => (seed = (seed * 1_103_515_245 + 12_345) & 0x7fffffff) / 0x7fffffff;
    const alphabet = 'AB-_09=,. ';
    for (let i = 0; i < 1000; i += 1) {
      const at = Math.floor(rnd() * header.length);
      const ch = alphabet[Math.floor(rnd() * alphabet.length)] as string;
      const mutated = header.slice(0, at) + ch + header.slice(at + 1);
      if (mutated === header) continue;
      expect((await check(mutated)).ok, mutated).toBe(false);
    }
  });
});

describe('helpers', () => {
  it('vapidAudience: origin only, lower case, default port dropped, no logins or odd forms', () => {
    expect(vapidAudience('https://Push.Example.NET/a/b?c=d')).toBe('https://push.example.net');
    expect(vapidAudience('https://push.example.net:443/x')).toBe('https://push.example.net');
    expect(vapidAudience('https://push.example.net:8443/x')).toBe('https://push.example.net:8443');
    for (const bad of [
      'http://push.example.net/x',
      'https://user@push.example.net/x',
      'https://push.example.net:0/x',
      'https://push.example.net:65536/x',
      'https://push.example.net:080/x',
      'https://push..example.net/x',
      'https://push.example.net/ x',
      'https:///x',
      '',
      undefined,
      12,
      `https://x.example/${'a'.repeat(2100)}`,
    ])
      expect(vapidAudience(bad), String(bad)).toBeUndefined();
  });

  it('isSubject: mailto or https, printable ASCII, at most 200', () => {
    expect(isSubject('mailto:ops@example.org')).toBe(true);
    expect(isSubject('https://example.org/contact')).toBe(true);
    expect(isSubject(`https://e.org/${'a'.repeat(186)}`)).toBe(true);
    expect(isSubject(`https://e.org/${'a'.repeat(187)}`)).toBe(false);
    for (const bad of [
      'http://example.org',
      'mailto:',
      'mailto:a@',
      'mailto:a b@c.d',
      'mailto:ü@c.d',
      '',
      5,
      null,
    ])
      expect(isSubject(bad), String(bad)).toBe(false);
  });
});
