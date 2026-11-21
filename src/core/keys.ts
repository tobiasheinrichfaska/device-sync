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

/** Five groups of four digits from a hash over app, device id and both public keys; compared aloud. */
export async function checkCode(
  appId: string,
  deviceId: string,
  keys: PublicKeys,
): Promise<string> {
  const data = new TextEncoder().encode(
    `${marker(appId, 'device', FORMAT_VERSION)}|${deviceId}|${keys.sig}|${keys.dh}`,
  );
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  const groups: string[] = [];
  for (let i = 0; i < 10; i += 2) {
    const n = (((hash[i] ?? 0) << 8) | (hash[i + 1] ?? 0)) % 10000;
    groups.push(String(n).padStart(4, '0'));
  }
  return groups.join(' ');
}
