// Shared building blocks of the session and the encrypted file. Internal: not exported from the
// package. Everything here is strict (one spelling, bounded) and never throws on foreign input.
import { base64url, fromBase64url } from './encoding.ts';
import { importPublicKey } from './keys.ts';

const utf8 = new TextEncoder();

/** The longest device id (UTF-16 units) the encrypted layers accept. */
export const MAX_DEVICE_ID = 200;
/** A device id has no control character, no format character, no lone surrogate and no `|`. */
const FORBIDDEN_IN_ID = /[\p{Cc}\p{Cf}\p{Cs}|]/u;

/** A device id as the encrypted layers read it (the trust layer has its own, stricter predicate). */
export function isDeviceText(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= MAX_DEVICE_ID &&
    !FORBIDDEN_IN_ID.test(value)
  );
}

/** `<UTF-8 byte length>:<text>`: a field of a hashed or authenticated text cannot shift into another. */
export const field = (text: string): string => `${utf8.encode(text).length}:${text}`;

/** Byte-wise order of the UTF-8 forms (not locale order, not UTF-16 order): same in every language. */
export function compareUtf8(a: string, b: string): number {
  const x = utf8.encode(a);
  const y = utf8.encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i += 1) {
    const d = (x[i] as number) - (y[i] as number);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return x.length === y.length ? 0 : x.length < y.length ? -1 : 1;
}

/**
 * The bytes of canonical unpadded base64url text (it re-encodes to itself, so a value has one
 * spelling) with a length in [min, max]; undefined for anything else. Never throws.
 */
export function readBytes(text: unknown, min: number, max: number): Uint8Array | undefined {
  if (typeof text !== 'string' || text.length > Math.ceil((max * 4) / 3) + 2) return undefined;
  try {
    const bytes = fromBase64url(text);
    if (bytes.length < min || bytes.length > max || base64url(bytes) !== text) return undefined;
    return bytes;
  } catch {
    return undefined;
  }
}

/** A plain data object (from JSON.parse): no array, no class instance. */
export function isPlain(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

/** Exactly these members, in this order (own members only: `__proto__` is just an unknown key). */
export function hasMembers(value: Record<string, unknown>, names: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === names.length && keys.every((k, i) => k === names[i]);
}

/** JSON.parse that answers undefined instead of throwing (also for a depth bomb). */
export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** UTF-8 text of bytes, or undefined when they are not valid UTF-8. */
export function decodeUtf8(bytes: Uint8Array): string | undefined {
  try {
    // ignoreBOM: a leading byte order mark stays in the text (and is refused), not silently dropped
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

/** Defaults with a partial override of own, finite, non-negative integer members on top. */
export function overrideNumbers<T extends object>(
  defaults: T,
  override: Partial<T> | undefined,
): T {
  if (!override || typeof override !== 'object') return defaults;
  const out: Record<string, number> = { ...(defaults as Record<string, number>) };
  for (const key of Object.keys(out)) {
    if (!Object.hasOwn(override, key)) continue;
    const value = (override as Record<string, unknown>)[key];
    if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) out[key] = value;
  }
  return out as T;
}

/** The public point of an agreement pair, or undefined when it cannot be exported. */
export async function ownPoint(agreement: CryptoKeyPair): Promise<string | undefined> {
  try {
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', agreement.publicKey));
    return raw.length === 65 ? base64url(raw) : undefined;
  } catch {
    return undefined;
  }
}

/** A public key checked on the curve, or undefined. */
export const importPoint = (point: string): Promise<CryptoKey | undefined> =>
  importPublicKey(point, 'dh');

/** The 32-byte ECDH secret. */
export async function ecdh(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256),
  );
}

export const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

export const sha256 = async (text: string): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(text)));

/** AES-256-GCM key from HKDF-SHA-256 (salt and info are texts); not extractable. */
export async function aesKey(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', new Uint8Array(ikm), 'HKDF', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(salt), info: utf8.encode(info) },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Length of the AES-GCM tag (the default of WebCrypto, written down here on purpose). */
export const TAG_BYTES = 16;

/** Wire size of base64url for `bytes` bytes. */
export const base64urlLength = (bytes: number): number => Math.ceil((bytes * 4) / 3);
