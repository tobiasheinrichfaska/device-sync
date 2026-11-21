// Regression tests of the second half of the security review (signatures and check codes).
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  base64url,
  checkCode,
  fromBase64url,
  generateDeviceKeys,
  publicKeys,
  signText,
  verifyText,
  type PublicKeys,
} from '../../src/core/index.ts';

/** Order of the P-256 group. */
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const sOf = (signature: string): bigint =>
  BigInt(`0x${Buffer.from(fromBase64url(signature).slice(32)).toString('hex')}`);

function highSTwin(signature: string): string {
  const bytes = fromBase64url(signature);
  const s = sOf(signature);
  const twin = (N - s).toString(16).padStart(64, '0');
  const out = new Uint8Array(64);
  out.set(bytes.slice(0, 32), 0);
  out.set(Uint8Array.from(Buffer.from(twin, 'hex')), 32);
  return base64url(out);
}

describe('N1: signatures are low-s, so one signature has one spelling', () => {
  it('300 fresh signatures are all low-s and all verify', async () => {
    const { signing } = await generateDeviceKeys();
    for (let i = 0; i < 300; i += 1) {
      const text = `text ${i}`;
      const sig = await signText(signing.privateKey, text);
      expect(sOf(sig) <= N / 2n, `signature ${i}`).toBe(true);
      expect(await verifyText(signing.publicKey, text, sig)).toBe(true);
    }
  });

  it('the high-s twin of a valid signature is refused (r, n - s)', async () => {
    const { signing } = await generateDeviceKeys();
    for (let i = 0; i < 20; i += 1) {
      const sig = await signText(signing.privateKey, `m${i}`);
      const twin = highSTwin(sig);
      expect(sOf(twin) > N / 2n).toBe(true);
      expect(twin).not.toBe(sig);
      expect(await verifyText(signing.publicKey, `m${i}`, twin)).toBe(false);
    }
  });

  it('the platform itself still accepts the twin: the rule is ours (so the test has teeth)', async () => {
    const { signing } = await generateDeviceKeys();
    const sig = await signText(signing.privateKey, 'teeth');
    const twin = fromBase64url(highSTwin(sig));
    const ecdsa = { name: 'ECDSA', hash: 'SHA-256' } as const;
    expect(
      await crypto.subtle.verify(
        ecdsa,
        signing.publicKey,
        new Uint8Array(twin),
        new TextEncoder().encode('teeth'),
      ),
    ).toBe(true);
  });
});

describe('N2: the check code hashes unambiguous text and checks its input', () => {
  const keys = async (): Promise<PublicKeys> => publicKeys(await generateDeviceKeys());

  it('is the documented text: marker, then length-prefixed device id, signing key and agreement key', async () => {
    const k = await keys();
    const text = `demo-device:2|5:dev-1|87:${k.sig}|87:${k.dh}`;
    const hash = createHash('sha256').update(text).digest();
    const groups = [0, 2, 4, 6, 8].map((i) =>
      String((((hash[i] as number) << 8) | (hash[i + 1] as number)) % 10000).padStart(4, '0'),
    );
    expect(await checkCode('demo', 'dev-1', k)).toBe(groups.join(' '));
  });

  it('a device id with the separator or a control character is a programming error', async () => {
    const k = await keys();
    for (const bad of ['a|b', 'a\nb', 'a\u0000b', 'a\u007fb', '']) {
      await expect(checkCode('demo', bad, k), JSON.stringify(bad)).rejects.toThrow(TypeError);
    }
    await expect(checkCode('demo', 5 as never, k)).rejects.toThrow(TypeError);
  });

  it('keys that are not points are a programming error (the old separator collision is closed)', async () => {
    const k = await keys();
    // the proven collision: ('a', sig 'b|c') and ('a|b', sig 'c') hashed to the same code
    await expect(checkCode('demo', 'a', { sig: 'b|c', dh: k.dh })).rejects.toThrow(TypeError);
    await expect(checkCode('demo', 'a|b', { sig: 'c', dh: k.dh })).rejects.toThrow(TypeError);
    await expect(checkCode('demo', 'a', { sig: k.sig, dh: 'short' })).rejects.toThrow(TypeError);
    await expect(checkCode('demo', 'a', { sig: k.sig, dh: undefined as never })).rejects.toThrow(
      TypeError,
    );
  });

  it('still five groups of four digits', async () => {
    expect(await checkCode('demo', 'dev-1', await keys())).toMatch(/^\d{4}( \d{4}){4}$/);
  });
});
