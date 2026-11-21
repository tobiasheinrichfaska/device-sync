import { base64url, fromBase64url } from './encoding.ts';

const ECDSA = { name: 'ECDSA', hash: 'SHA-256' } as const;
const utf8 = new TextEncoder();
/** ECDSA P-256 in the P1363 format (r and s, 32 bytes each) that WebCrypto uses. */
const SIGNATURE_BYTES = 64;

/** Signs the UTF-8 bytes of a text (ECDSA P-256 / SHA-256, P1363); the signature travels as base64url. */
export async function signText(privateKey: CryptoKey, text: string): Promise<string> {
  const signature = await crypto.subtle.sign(ECDSA, privateKey, utf8.encode(text));
  return base64url(new Uint8Array(signature));
}

/**
 * True only for a valid signature over exactly this text. Strict: a signature that is not
 * canonical base64url or not 64 bytes is simply false; this never throws.
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
    return await crypto.subtle.verify(ECDSA, publicKey, new Uint8Array(bytes), utf8.encode(text));
  } catch {
    return false;
  }
}
