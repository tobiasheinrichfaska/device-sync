import { describe, expect, it } from 'vitest';
import { base64url } from '../../src/core/encoding.ts';
import {
  checkCode,
  generateDeviceKeys,
  importPublicKey,
  isPoint,
  publicKeys,
} from '../../src/core/keys.ts';

const A = `device-${'a'.repeat(16)}`;
const B = `device-${'b'.repeat(16)}`;

describe('device keys', () => {
  it('two pairs; secret halves cannot be read out; public halves are 87-char P-256 points', async () => {
    const keys = await generateDeviceKeys();
    const pub = await publicKeys(keys);
    expect(pub.sig).toHaveLength(87);
    expect(pub.dh).toHaveLength(87);
    expect(isPoint(pub.sig) && isPoint(pub.dh)).toBe(true);
    expect(pub.sig).not.toBe(pub.dh);
    await expect(crypto.subtle.exportKey('pkcs8', keys.signing.privateKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey('pkcs8', keys.agreement.privateKey)).rejects.toThrow();
    expect(await importPublicKey(pub.dh, 'dh')).toBeDefined();
    expect(await importPublicKey(pub.sig, 'sig')).toBeDefined();
  });

  it('a point off the curve or of the wrong length is refused', async () => {
    const off = new Uint8Array(65);
    off[0] = 4;
    off[1] = 1;
    expect(isPoint(base64url(off))).toBe(true);
    expect(await importPublicKey(base64url(off), 'dh')).toBeUndefined();
    expect(await importPublicKey(base64url(off), 'sig')).toBeUndefined();
    expect(isPoint(base64url(new Uint8Array(33)))).toBe(false);
    expect(isPoint('not a point')).toBe(false);
  });

  it('isPoint rejects wrong first byte, non-base64url text and non-strings', async () => {
    const pub = await publicKeys(await generateDeviceKeys());
    const bytes = Uint8Array.from(atob(pub.sig.replace(/-/g, '+').replace(/_/g, '/') + '='), (c) =>
      c.charCodeAt(0),
    );
    bytes[0] = 2;
    expect(isPoint(base64url(bytes))).toBe(false);
    expect(isPoint(pub.sig.slice(0, 86) + '+')).toBe(false);
    expect(isPoint(pub.sig + 'A')).toBe(false);
    expect(isPoint(undefined)).toBe(false);
    expect(isPoint(42)).toBe(false);
  });

  it('the exported point is the real key: sign with the private half, verify with the import', async () => {
    const keys = await generateDeviceKeys();
    const pub = await publicKeys(keys);
    const data = new TextEncoder().encode('hello');
    const algo = { name: 'ECDSA', hash: 'SHA-256' };
    const sig = await crypto.subtle.sign(algo, keys.signing.privateKey, data);
    const imported = await importPublicKey(pub.sig, 'sig');
    expect(imported).toBeDefined();
    expect(await crypto.subtle.verify(algo, imported!, sig, data)).toBe(true);
    expect(
      await crypto.subtle.verify(algo, imported!, sig, new TextEncoder().encode('hellO')),
    ).toBe(false);
    const other = await importPublicKey((await publicKeys(await generateDeviceKeys())).sig, 'sig');
    expect(await crypto.subtle.verify(algo, other!, sig, data)).toBe(false);
  });
});

describe('checkCode', () => {
  it('five groups of four digits, the same for the same input', async () => {
    const pub = await publicKeys(await generateDeviceKeys());
    const code = await checkCode('demo', A, pub);
    expect(code).toMatch(/^\d{4}( \d{4}){4}$/);
    expect(await checkCode('demo', A, pub)).toBe(code);
    expect(await checkCode('demo', B, pub)).not.toBe(code);
  });

  it('appId, device id, sig and dh each change the code', async () => {
    const one = await publicKeys(await generateDeviceKeys());
    const two = await publicKeys(await generateDeviceKeys());
    const base = await checkCode('demo', A, one);
    expect(await checkCode('other', A, one)).not.toBe(base);
    expect(await checkCode('demo', B, one)).not.toBe(base);
    expect(await checkCode('demo', A, { sig: two.sig, dh: one.dh })).not.toBe(base);
    expect(await checkCode('demo', A, { sig: one.sig, dh: two.dh })).not.toBe(base);
  });

  it('matches a fixed vector (pins the derivation)', async () => {
    const code = await checkCode('demo', 'device-0', { sig: 'S', dh: 'D' });
    const hash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode('demo-device:2|device-0|S|D')),
    );
    const groups = [0, 2, 4, 6, 8].map((i) =>
      String((((hash[i] ?? 0) << 8) | (hash[i + 1] ?? 0)) % 10000).padStart(4, '0'),
    );
    expect(code).toBe(groups.join(' '));
  });

  it('refuses an invalid appId', async () => {
    await expect(checkCode('Bad', A, { sig: 'S', dh: 'D' })).rejects.toThrow(/invalid appId/);
  });
});
