import { describe, expect, it } from 'vitest';
import { base64url, fromBase64url } from '../../src/core/encoding.ts';
import { generateDeviceKeys } from '../../src/core/keys.ts';
import { signText, verifyText } from '../../src/core/signature.ts';

const pair = async () => (await generateDeviceKeys()).signing;

describe('signText / verifyText', () => {
  it('a signature is 86 base64url characters (64 bytes) and verifies with the matching key', async () => {
    const keys = await pair();
    const sig = await signText(keys.privateKey, 'hello');
    expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(fromBase64url(sig)).toHaveLength(64);
    expect(await verifyText(keys.publicKey, 'hello', sig)).toBe(true);
  });

  it('another text, another key or one changed byte: false', async () => {
    const a = await pair();
    const b = await pair();
    const sig = await signText(a.privateKey, 'hello');
    expect(await verifyText(a.publicKey, 'hellO', sig)).toBe(false);
    expect(await verifyText(a.publicKey, 'hello ', sig)).toBe(false);
    expect(await verifyText(b.publicKey, 'hello', sig)).toBe(false);
    const bytes = fromBase64url(sig);
    for (const i of [0, 31, 32, 63]) {
      const flipped = Uint8Array.from(bytes);
      flipped[i] = (flipped[i] ?? 0) ^ 1;
      expect(await verifyText(a.publicKey, 'hello', base64url(flipped))).toBe(false);
    }
  });

  it('the text is signed as UTF-8, not as UTF-16 units', async () => {
    const keys = await pair();
    const sig = await signText(keys.privateKey, 'ä€😀');
    expect(await verifyText(keys.publicKey, 'ä€😀', sig)).toBe(true);
    expect(await verifyText(keys.publicKey, 'a€😀', sig)).toBe(false);
  });

  it('garbage, wrong length, padding and non-base64url are false and never throw', async () => {
    const keys = await pair();
    const sig = await signText(keys.privateKey, 'x');
    const bytes = fromBase64url(sig);
    const garbage: unknown[] = [
      '',
      'abc',
      'a'.repeat(86),
      '!'.repeat(86),
      `${sig}=`,
      `${sig}==`,
      ` ${sig}`,
      `${sig}\n`,
      `+${sig.slice(1)}`,
      sig.slice(0, -1),
      `${sig}A`,
      base64url(bytes.slice(0, 63)),
      base64url(bytes.slice(0, 32)),
      base64url(Uint8Array.from([...bytes, 0])),
      base64url(new Uint8Array(64)),
      'é'.repeat(86),
      undefined,
      null,
      42,
      {},
    ];
    for (const g of garbage) {
      await expect(verifyText(keys.publicKey, 'x', g as string)).resolves.toBe(false);
    }
  });

  it('a second spelling of the same 64 bytes (spare bits of the last character) is false', async () => {
    const keys = await pair();
    const sig = await signText(keys.privateKey, 'x');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(sig.slice(-1));
    const variant = sig.slice(0, -1) + alphabet[last ^ 1];
    expect(variant).not.toBe(sig);
    expect(await verifyText(keys.publicKey, 'x', sig)).toBe(true);
    expect(await verifyText(keys.publicKey, 'x', variant)).toBe(false);
  });
});
