import { base64url, fromBase64url } from './encoding.ts';

const ECDSA = { name: 'ECDSA', hash: 'SHA-256' } as const;
const utf8 = new TextEncoder();
/** ECDSA P-256 in the P1363 format (r and s, 32 bytes each) that WebCrypto uses. */
const SIGNATURE_BYTES = 64;
/** Order n of the P-256 group; (r, s) and (r, n - s) both verify, so only the low-s form is ours. */
const ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_ORDER = ORDER / 2n;

const bigintOf = (bytes: Uint8Array): bigint =>
  bytes.reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);

function bytesOf(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let rest = value;
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

/**
 * Signs the UTF-8 bytes of a text (ECDSA P-256 / SHA-256, P1363); the signature travels as base64url.
 * The signature is normalised to low-s (s <= n/2), so a signature has one valid form.
 */
export async function signText(privateKey: CryptoKey, text: string): Promise<string> {
  const signature = new Uint8Array(await crypto.subtle.sign(ECDSA, privateKey, utf8.encode(text)));
  const s = bigintOf(signature.slice(32));
  if (s > HALF_ORDER) signature.set(bytesOf(ORDER - s), 32);
  return base64url(signature);
}

/**
 * True only for a valid signature over exactly this text. Strict: a signature that is not
 * canonical base64url, not 64 bytes or has a high s (the malleable twin) is simply false; this
 * never throws.
 */
export async function verifyText(
  publicKey: CryptoKey,
  text: string,
  signature: string,
): Promise<boolean> {
  try {
    if (typeof signature !== 'string') return false;
    const bytes = fromBase64url(signature);
    // Re-encoding must give the same text, so one signature has exactly one spelling.
    if (bytes.length !== SIGNATURE_BYTES || base64url(bytes) !== signature) return false;
    if (bigintOf(bytes.slice(32)) > HALF_ORDER) return false;
    return await crypto.subtle.verify(ECDSA, publicKey, new Uint8Array(bytes), utf8.encode(text));
  } catch {
    return false;
  }
}
