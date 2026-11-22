// Regression tests of the shared parts of the session and file layers and of the point check.
import { describe, expect, it } from 'vitest';
import {
  base64url,
  checkCode,
  fromBase64url,
  generateDeviceKeys,
  isPoint,
  openSession,
  publicKeys,
} from '../../src/core/index.ts';
import {
  compareUtf8,
  hasMembers,
  isDeviceText,
  overrideNumbers,
  readBytes,
} from '../../src/core/secure.ts';
import { jwkToPoint, nonce, refOpen, refSeal, refSession } from './reference.ts';
import { APP, extractablePair, pairFromJwk, show, text } from './secure-helpers.ts';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

describe('isPoint reads one spelling per point', () => {
  it('a point whose last character carries stray padding bits is not a point', async () => {
    const keys = await generateDeviceKeys();
    const { dh } = await publicKeys(keys);
    expect(isPoint(dh)).toBe(true);
    const twin = dh.slice(0, -1) + ALPHABET[ALPHABET.indexOf(dh.at(-1) as string) ^ 1];
    expect(twin).not.toBe(dh);
    expect(fromBase64url(twin)).toEqual(fromBase64url(dh)); // same 65 bytes, another text
    expect(isPoint(twin)).toBe(false);
  });

  it('so one key cannot have two check codes', async () => {
    const keys = await generateDeviceKeys();
    const pub = await publicKeys(keys);
    const twin = pub.dh.slice(0, -1) + ALPHABET[ALPHABET.indexOf(pub.dh.at(-1) as string) ^ 1];
    await expect(checkCode(APP, 'device-x', { sig: pub.sig, dh: twin })).rejects.toThrow(TypeError);
  });
});

describe('device ids of the encrypted layers', () => {
  it('accepted and refused ids', () => {
    for (const ok of [
      'a',
      'device-' + '0'.repeat(32),
      'Ünï',
      '日本',
      'a b',
      'x'.repeat(200),
      '\u{1F600}',
    ]) {
      expect(isDeviceText(ok), ok).toBe(true);
    }
    for (const bad of [
      '',
      'a|b',
      'a\u0000',
      'a\u001F',
      'a\u007F',
      'a\u0085',
      'a​',
      'a‮',
      '﻿a',
      String.fromCharCode(0xdc00),
      'x'.repeat(201),
      5,
      null,
      undefined,
      {},
    ]) {
      expect(isDeviceText(bad), String(bad)).toBe(false);
    }
  });
});

describe('byte order of device ids', () => {
  it('compares UTF-8 bytes: not UTF-16 units, not the locale', () => {
    const bmp = 'x～'; // UTF-8 EF BD 9E, UTF-16 FF5E
    const astral = 'x\u{1F600}'; // UTF-8 F0 9F 98 80, UTF-16 D83D DE00
    expect(bmp < astral).toBe(false); // UTF-16 order puts the emoji first
    expect(compareUtf8(bmp, astral)).toBe(-1); // UTF-8 order puts the full-width tilde first
    expect(compareUtf8(astral, bmp)).toBe(1);
    expect(compareUtf8('a', 'a')).toBe(0);
    expect(compareUtf8('a', 'ab')).toBe(-1);
    expect(compareUtf8('B', 'a')).toBe(-1); // upper case before lower case, whatever the locale
    expect('B'.localeCompare('a')).toBe(1);
  });

  it('two devices whose ids sort differently in UTF-16 and UTF-8 agree, and agree with the documented order', async () => {
    const lo = 'dev-～'; // smaller by UTF-8 bytes, larger by UTF-16 units
    const hi = 'dev-\u{1F600}';
    const [sl, sh, el, eh] = [
      await extractablePair(),
      await extractablePair(),
      await extractablePair(),
      await extractablePair(),
    ];
    const side = (device: string, s: typeof sl, e: typeof sl) => ({
      device,
      staticPriv: s.jwk,
      staticDh: jwkToPoint(s.jwk),
      ephPriv: e.jwk,
      ephPoint: jwkToPoint(e.jwk),
    });
    const L = side(lo, sl, el);
    const H = side(hi, sh, eh);
    const open = async (me: typeof L, you: typeof L, s: typeof sl, e: typeof sl) => {
      const r = await openSession({
        appId: APP,
        own: { device: me.device, agreement: await pairFromJwk(s.jwk) },
        peer: { device: you.device, dh: you.staticDh },
        ephemeral: await pairFromJwk(e.jwk),
        ownHello: { device: me.device, eph: me.ephPoint },
        peerHello: { device: you.device, eph: you.ephPoint },
      });
      if (!r.ok) throw new Error(r.reason);
      return r.session;
    };
    const a = await open(L, H, sl, el);
    const b = await open(H, L, sh, eh);
    const sealed = await a.seal(text('order'));
    if (!sealed.ok) throw new Error('seal');
    const opened = await b.open(sealed.text);
    expect(opened.ok && show(opened.plaintext)).toBe('order');
    // and the independent derivation (which orders by UTF-8 bytes) opens the library's message
    const ref = refSession(APP, L, H, {});
    const m = sealed.text.match(/"ct":"([^"]+)"/)?.[1] as string;
    const aad = `demo-msg:2|${Buffer.byteLength(lo)}:${lo}|${Buffer.byteLength(hi)}:${hi}|0`;
    const plain = refOpen(ref.keyOf(lo), nonce(0), aad, Buffer.from(m, 'base64url'));
    expect(plain && show(plain)).toBe('order');
    expect(refSeal(APP, ref.keyOf(hi), hi, lo, 0, text('x')).text).toContain('"n":0');
  });
});

describe('readBytes, hasMembers, overrideNumbers', () => {
  it('canonical base64url of a bounded length only', () => {
    const raw = Uint8Array.from([1, 2, 3, 4, 5]);
    const t = base64url(raw);
    expect(readBytes(t, 5, 5)).toEqual(raw);
    expect(readBytes(t, 6, 9)).toBeUndefined();
    expect(readBytes(t, 0, 4)).toBeUndefined();
    expect(readBytes(`${t}=`, 0, 9)).toBeUndefined();
    expect(
      readBytes(t.slice(0, -1) + ALPHABET[ALPHABET.indexOf(t.at(-1) as string) ^ 1], 0, 9),
    ).toBeUndefined();
    expect(readBytes('A'.repeat(10_000_000), 0, 10)).toBeUndefined();
    expect(readBytes(undefined, 0, 9)).toBeUndefined();
    expect(readBytes('', 0, 9)).toEqual(new Uint8Array(0));
    expect(readBytes('', 1, 9)).toBeUndefined();
    expect(readBytes('a+b/', 0, 9)).toBeUndefined();
  });

  it('members in exactly this order; a prototype key is just an unknown key', () => {
    expect(hasMembers({ a: 1, b: 2 }, ['a', 'b'])).toBe(true);
    expect(hasMembers({ b: 2, a: 1 }, ['a', 'b'])).toBe(false);
    expect(hasMembers({ a: 1 }, ['a', 'b'])).toBe(false);
    expect(hasMembers({ a: 1, b: 2, c: 3 }, ['a', 'b'])).toBe(false);
    expect(
      hasMembers(JSON.parse('{"a":1,"__proto__":{}}') as Record<string, unknown>, ['a', 'b']),
    ).toBe(false);
  });

  it('overrideNumbers keeps own, finite, non-negative integers only', () => {
    const d = { x: 1, y: 2 };
    expect(overrideNumbers(d, { x: 5 })).toEqual({ x: 5, y: 2 });
    expect(overrideNumbers(d, { x: -1, y: NaN })).toEqual(d);
    expect(overrideNumbers(d, { x: Infinity })).toEqual(d);
    expect(overrideNumbers(d, { x: 2 ** 60 })).toEqual(d);
    expect(overrideNumbers(d, Object.create({ x: 9 }) as object)).toEqual(d);
    expect(overrideNumbers(d, 'x' as never)).toEqual(d);
    expect(overrideNumbers(d, undefined)).toEqual(d);
    expect(d).toEqual({ x: 1, y: 2 });
  });
});
