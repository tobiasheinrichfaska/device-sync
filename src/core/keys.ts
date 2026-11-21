import { base64url, fromBase64url } from './encoding.ts';
import { FORMAT_VERSION, marker } from './markers.ts';

const SIGNING = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const AGREEMENT = { name: 'ECDH', namedCurve: 'P-256' } as const;

export interface DeviceKeys {
  readonly signing: CryptoKeyPair;
  readonly agreement: CryptoKeyPair;
}

/** Public halves as uncompressed P-256 points (65 bytes), base64url (87 characters). */
export interface PublicKeys {
  readonly sig: string;
  readonly dh: string;
}

/** A signing pair (ECDSA P-256) and an agreement pair (ECDH P-256); private halves are not extractable. */
export async function generateDeviceKeys(): Promise<DeviceKeys> {
  const signing = await crypto.subtle.generateKey(SIGNING, false, ['sign', 'verify']);
  const agreement = await crypto.subtle.generateKey(AGREEMENT, false, ['deriveBits']);
  return { signing, agreement };
}

export async function publicKeys(keys: DeviceKeys): Promise<PublicKeys> {
  const raw = async (key: CryptoKey) =>
    base64url(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
  return { sig: await raw(keys.signing.publicKey), dh: await raw(keys.agreement.publicKey) };
}

/** A P-256 point as it travels: 65 bytes, uncompressed (first byte 4), 87 base64url characters. */
export function isPoint(text: unknown): text is string {
  if (typeof text !== 'string' || text.length !== 87) return false;
  try {
    const bytes = fromBase64url(text);
    return bytes.length === 65 && bytes[0] === 4;
  } catch {
    return false;
  }
}

/** Imports a public key; undefined when the point is malformed or not on the curve. */
export async function importPublicKey(
  point: string,
  kind: 'sig' | 'dh',
): Promise<CryptoKey | undefined> {
  if (!isPoint(point)) return undefined;
  try {
    return await crypto.subtle.importKey(
      'raw',
      new Uint8Array(fromBase64url(point)),
      kind === 'sig' ? SIGNING : AGREEMENT,
      true,
      kind === 'sig' ? ['verify'] : [],
    );
  } catch {
    return undefined;
  }
}

const unsafeChar = (ch: string): boolean => {
  const code = ch.codePointAt(0) ?? 0;
  return code < 32 || code === 127 || ch === '|';
};

/**
 * Groups of four digits from a hash over app, device id and both public keys; compared aloud.
 * The hashed text is `<marker>|<n>:<deviceId>|<n>:<sig>|<n>:<dh>` where each `<n>` is the UTF-8
 * byte length of the field after it, so no field can be shifted into another. The five groups carry
 * about 66 bits (5 x log2(10000)): enough to catch a mistake, not a lasting protection against an
 * attacker who can grind keys; the trust layer decides how much more a meeting needs.
 * `groups` (default 5, allowed 5 to 10, else TypeError) sets the length: each group adds about 13.3
 * bits (10 groups: about 133 bits). Use at least 8 groups (about 106 bits) where the code is what
 * protects against a modified invitation link; a longer code is read aloud more slowly.
 * A device id with `|` or a control character, or a key that is not a point, is a programming error
 * (TypeError).
 */
export async function checkCode(
  appId: string,
  deviceId: string,
  keys: PublicKeys,
  groups = 5,
): Promise<string> {
  if (!Number.isInteger(groups) || groups < 5 || groups > 10) {
    throw new TypeError('checkCode: groups must be an integer from 5 to 10');
  }
  if (typeof deviceId !== 'string' || deviceId.length === 0 || [...deviceId].some(unsafeChar)) {
    throw new TypeError('checkCode: the device id is empty or has a control character or "|"');
  }
  if (!isPoint(keys?.sig) || !isPoint(keys?.dh)) {
    throw new TypeError('checkCode: both public keys must be uncompressed P-256 points');
  }
  const utf8 = new TextEncoder();
  const field = (text: string): string => `${utf8.encode(text).length}:${text}`;
  const data = utf8.encode(
    `${marker(appId, 'device', FORMAT_VERSION)}|${field(deviceId)}|${field(keys.sig)}|${field(keys.dh)}`,
  );
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  const parts: string[] = [];
  for (let i = 0; i < groups * 2; i += 2) {
    const n = (((hash[i] ?? 0) << 8) | (hash[i + 1] ?? 0)) % 10000;
    parts.push(String(n).padStart(4, '0'));
  }
  return parts.join(' ');
}
