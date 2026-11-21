import { describe, expect, it } from 'vitest';
import { base64url, fromBase64url, sha256Text } from '../../src/core/encoding.ts';

describe('base64url', () => {
  it('round-trips all 256 byte values and random lengths', () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(fromBase64url(base64url(all))).toEqual(all);
    for (let n = 0; n < 70; n++) {
      const bytes = crypto.getRandomValues(new Uint8Array(n));
      const text = base64url(bytes);
      expect(text).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(fromBase64url(text)).toEqual(bytes);
    }
  });

  it('uses the url alphabet without padding', () => {
    expect(base64url(Uint8Array.of(0xfb, 0xff, 0xfe))).toBe('-__-');
    expect(base64url(Uint8Array.of(1))).toBe('AQ');
    expect(base64url(new Uint8Array(0))).toBe('');
  });

  it('is strict: refuses + / = spaces and every other character', () => {
    for (const bad of ['+A', 'A/', 'AQ==', 'AQ ', ' AQ', 'A Q', 'A\nQ', 'ä', '=', 'AQ=']) {
      expect(() => fromBase64url(bad)).toThrow();
    }
  });

  it('refuses a length that cannot be base64 (one left-over character)', () => {
    expect(() => fromBase64url('A')).toThrow();
    expect(() => fromBase64url('AAAAA')).toThrow();
  });

  it('empty is valid and gives no bytes', () => {
    expect(fromBase64url('')).toEqual(new Uint8Array(0));
  });
});

describe('sha256Text', () => {
  const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  it('matches the fixed vectors', () => {
    expect(hex(sha256Text('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(hex(sha256Text(''))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });
  it('hashes the UTF-8 encoding', async () => {
    const expected = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode('ü😀')),
    );
    expect(sha256Text('ü😀')).toEqual(expected);
  });
});
