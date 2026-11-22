// Device keys that can leave the key store: for an identity inside an encrypted store of the app.
import { describe, expect, it } from 'vitest';
import {
  exportDeviceKeys,
  generateDeviceKeys,
  generateExportableDeviceKeys,
  importDeviceKeys,
  publicKeys,
  signText,
  verifyText,
  importPublicKey,
} from '../../src/core/index.ts';
import { prng } from '../log/helpers.ts';

describe('export and import of device keys', () => {
  it('the keys come back as the same identity, usable, and no longer extractable', async () => {
    const keys = await generateExportableDeviceKeys();
    const exported = await exportDeviceKeys(keys);
    if (!exported.ok) throw new Error(exported.reason);
    const back = await importDeviceKeys(exported.text, { expect: await publicKeys(keys) });
    if (!back.ok) throw new Error(back.reason);
    expect(back.public).toEqual(await publicKeys(keys));
    // signs as the original, verifies with the original's public key
    const sig = await signText(back.keys.signing.privateKey, 'hello');
    const pub = await importPublicKey(back.public.sig, 'sig');
    expect(await verifyText(pub as CryptoKey, 'hello', sig)).toBe(true);
    // agrees with a peer exactly as the original does
    const peer = await generateDeviceKeys();
    const bits = (own: CryptoKey, other: CryptoKey) =>
      crypto.subtle.deriveBits({ name: 'ECDH', public: other }, own, 256);
    expect(
      new Uint8Array(await bits(back.keys.agreement.privateKey, peer.agreement.publicKey)),
    ).toEqual(new Uint8Array(await bits(keys.agreement.privateKey, peer.agreement.publicKey)));
    // the imported private keys cannot be exported again
    await expect(crypto.subtle.exportKey('jwk', back.keys.signing.privateKey)).rejects.toThrow();
    await expect(exportDeviceKeys(back.keys)).resolves.toEqual({
      ok: false,
      reason: 'not-extractable',
    });
    // and ordinary device keys are never extractable
    await expect(exportDeviceKeys(await generateDeviceKeys())).resolves.toEqual({
      ok: false,
      reason: 'not-extractable',
    });
  });

  it('the text is exactly the documented shape', async () => {
    const exported = await exportDeviceKeys(await generateExportableDeviceKeys());
    if (!exported.ok) throw new Error(exported.reason);
    const o = JSON.parse(exported.text) as Record<string, Record<string, string>>;
    expect(Object.keys(o)).toEqual(['v', 'sig', 'dh']);
    expect(Object.keys(o.sig as object)).toEqual(['kty', 'crv', 'x', 'y', 'd']);
    expect(Object.keys(o.dh as object)).toEqual(['kty', 'crv', 'x', 'y', 'd']);
  });

  it('refuses the wrong keys, a mixed pair and every other spelling', async () => {
    const a = await exportDeviceKeys(await generateExportableDeviceKeys());
    const b = await exportDeviceKeys(await generateExportableDeviceKeys());
    if (!a.ok || !b.ok) throw new Error('export');
    const ja = JSON.parse(a.text) as {
      v: number;
      sig: Record<string, string>;
      dh: Record<string, string>;
    };
    const jb = JSON.parse(b.text) as typeof ja;
    // the other identity expected
    const imported = await importDeviceKeys(b.text);
    if (!imported.ok) throw new Error(imported.reason);
    const otherPublic = imported.public;
    expect(await importDeviceKeys(a.text, { expect: otherPublic })).toEqual({
      ok: false,
      reason: 'wrong-keys',
    });
    // the private half of one identity under the public half of another
    const mixed = JSON.stringify({ ...ja, sig: { ...ja.sig, d: jb.sig.d } });
    const m1 = await importDeviceKeys(mixed);
    expect(m1.ok === false && ['inconsistent', 'bad-key'].includes(m1.reason)).toBe(true);
    const mixedDh = JSON.stringify({ ...ja, dh: { ...ja.dh, d: jb.dh.d } });
    const m2 = await importDeviceKeys(mixedDh);
    expect(m2.ok === false && ['inconsistent', 'bad-key'].includes(m2.reason)).toBe(true);
    const bad: unknown[] = [
      null,
      5,
      '',
      '[]',
      '{}',
      a.text.replace('"v":1', '"v":2'),
      a.text.replace('"v":1,', '"v":1,"v":1,'),
      JSON.stringify({ ...ja, extra: 1 }),
      JSON.stringify({ ...ja, sig: { ...ja.sig, key_ops: ['sign'] } }),
      JSON.stringify({ ...ja, sig: { ...ja.sig, crv: 'P-384' } }),
      JSON.stringify({ ...ja, sig: { ...ja.sig, kty: 'RSA' } }),
      JSON.stringify({ ...ja, sig: { ...ja.sig, x: ja.sig.x?.slice(1) } }),
      JSON.stringify({ ...ja, sig: { ...ja.sig, d: `${ja.sig.d?.slice(0, 42)}=` } }),
      JSON.stringify({ ...ja, sig: { ...ja.sig, d: 5 } }),
      JSON.stringify({ sig: ja.sig, v: 1, dh: ja.dh }),
      'x'.repeat(4001),
    ];
    for (const text of bad) {
      const out = await importDeviceKeys(text);
      expect(out.ok, String(text).slice(0, 60)).toBe(false);
    }
    // a point not on the curve
    const off = JSON.stringify({ ...ja, sig: { ...ja.sig, y: ja.sig.x } });
    expect((await importDeviceKeys(off)).ok).toBe(false);
  });

  it('never throws on 300 seeded damages of a real export', async () => {
    const exported = await exportDeviceKeys(await generateExportableDeviceKeys());
    if (!exported.ok) throw new Error(exported.reason);
    const r = prng(5);
    for (let i = 0; i < 300; i += 1) {
      const at = Math.floor(r() * exported.text.length);
      const text =
        exported.text.slice(0, at) +
        String.fromCharCode(33 + Math.floor(r() * 90)) +
        exported.text.slice(at + 1);
      const out = await importDeviceKeys(text);
      if (out.ok) expect(JSON.stringify(Object.keys(out))).toContain('keys');
    }
  });
});
