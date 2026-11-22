// The derivations of the group layer (HKDF-SHA-256 from the group key; AES-256-GCM per message).
import { FORMAT_VERSION, marker } from '../core/markers.ts';
import { base64url } from '../core/encoding.ts';
import { aesKey, field, sha256 } from '../core/secure.ts';

const utf8 = new TextEncoder();

/** Bytes of the group key itself (random, never derived from anything else). */
export const KEY_BYTES = 32;
/** Bytes of the key id (128 bits, 22 characters). */
export const KID_BYTES = 16;
/** Bytes of the per-message salt (the message key is fresh per message). */
export const SALT_BYTES = 16;

const group = (appId: string): string => marker(appId, 'group', FORMAT_VERSION);

/** `<appId>-group:2|<n>:<set>`, hashed: the HKDF salt of the key id. */
const setSalt = (appId: string, set: string): Promise<Uint8Array> =>
  sha256(`${group(appId)}|${field(set)}`);

/** The key id: 128 bits HKDF-expanded from the key, bound to app, data set and epoch. */
export async function deriveKeyId(
  appId: string,
  set: string,
  epoch: number,
  key: Uint8Array,
): Promise<string> {
  const material = await crypto.subtle.importKey('raw', new Uint8Array(key), 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(await setSalt(appId, set)),
      info: utf8.encode(`${group(appId)}|kid|${epoch}`),
    },
    material,
    KID_BYTES * 8,
  );
  return base64url(new Uint8Array(bits));
}

/** The text that is the HKDF info of a message key and the start of the AAD. */
export const dataInfo = (appId: string, set: string, epoch: number, kid: string): string =>
  `${marker(appId, 'gdata', FORMAT_VERSION)}|${field(set)}|${epoch}|${kid}`;

/** The authenticated data of a message: the info text and the app's context. */
export const dataAad = (info: string, context: string): Uint8Array<ArrayBuffer> =>
  utf8.encode(`${info}|${field(context)}`);

/** The message key: HKDF(group key, fresh salt, info). One key opens one message. */
export const messageKey = (key: Uint8Array, salt: Uint8Array, info: string): Promise<CryptoKey> =>
  aesKey(key, salt, info);

/** The GCM nonce: constant, because the key is fresh per message. */
export const ZERO_IV = new Uint8Array(12);
