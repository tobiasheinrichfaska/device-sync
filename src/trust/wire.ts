import { base64url, fromBase64url, isPoint } from '../core/index.ts';
import type { Introduction, Validators } from './types.ts';

/** A plain data object (from JSON): no array, no class instance. */
export function isPlain(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

/** A device's introduction from its parts, strictly read; the two keys must differ. */
export function parseIntroduction(raw: unknown, valid: Validators): Introduction | undefined {
  if (!isPlain(raw)) return undefined;
  const { device, name, sig, dh } = raw;
  return typeof device === 'string' &&
    valid.deviceId(device) &&
    typeof name === 'string' &&
    valid.name(name) &&
    isPoint(sig) &&
    isPoint(dh) &&
    sig !== dh
    ? { device, name, sig, dh }
    : undefined;
}

/** Text of exactly `bytes` bytes in canonical (re-encodes to itself) unpadded base64url. */
export function isBase64urlBytes(text: unknown, bytes: number): text is string {
  if (typeof text !== 'string') return false;
  try {
    const raw = fromBase64url(text);
    return raw.length === bytes && base64url(raw) === text;
  } catch {
    return false;
  }
}

/** One-time code: 16 bytes, 22 characters. */
export const isCode = (v: unknown): v is string => isBase64urlBytes(v, 16);
/** HMAC-SHA-256 proof: 32 bytes, 43 characters. */
export const isProof = (v: unknown): v is string => isBase64urlBytes(v, 32);
/** ECDSA P-256 signature: 64 bytes, 86 characters. */
export const isSignature = (v: unknown): v is string => isBase64urlBytes(v, 64);

/** A non-negative integer a double holds exactly. */
export const isCount = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

/** Strict UTF-8 JSON of a text; undefined for anything else. */
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
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}
