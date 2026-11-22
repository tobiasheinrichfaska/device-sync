// Web Push message encryption: RFC 8291 on top of the aes128gcm content coding of RFC 8188, exactly one
// record. Pure apart from WebCrypto; the salt is a parameter. Never throws on bad input.
import { base64url } from '../core/encoding.ts';
import { isPoint } from '../core/keys.ts';
import { concat, ecdh, importPoint, ownPoint, readBytes } from '../core/secure.ts';
import { fail, pass, PUSH_LIMITS, type PushResult } from './limits.ts';

const utf8 = new TextEncoder();
const KEY_INFO = utf8.encode('WebPush: info\0');
const CEK_INFO = utf8.encode('Content-Encoding: aes128gcm\0');
const NONCE_INFO = utf8.encode('Content-Encoding: nonce\0');
const { saltBytes, authBytes, pointBytes, headerBytes, recordOverhead } = PUSH_LIMITS;

async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  bits: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(ikm), 'HKDF', false, [
    'deriveBits',
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(salt), info: new Uint8Array(info) },
      key,
      bits,
    ),
  );
}

/** CEK and nonce of RFC 8291 section 3.3 / 3.4 from the shared secret, both public points, auth secret and salt. */
async function deriveKeys(
  secret: Uint8Array,
  receiverPoint: Uint8Array,
  senderPoint: Uint8Array,
  auth: Uint8Array,
  salt: Uint8Array,
): Promise<{ readonly cek: CryptoKey; readonly nonce: Uint8Array }> {
  const ikm = await hkdf(secret, auth, concat(KEY_INFO, receiverPoint, senderPoint), 256);
  const cek = await hkdf(ikm, salt, CEK_INFO, 128);
  const nonce = await hkdf(ikm, salt, NONCE_INFO, 96);
  return {
    cek: await crypto.subtle.importKey('raw', new Uint8Array(cek), 'AES-GCM', false, [
      'encrypt',
      'decrypt',
    ]),
    nonce,
  };
}

export interface PushEncryptParams {
  /** What the receiver gets (may be empty). */
  readonly plaintext: Uint8Array;
  /** The receiver's `p256dh` key: an uncompressed P-256 point, 87 base64url characters. */
  readonly receiverPublic: string;
  /** The subscription's `auth` secret: 16 bytes, 22 base64url characters. */
  readonly authSecret: string;
  /** 16 fresh random bytes (one salt per message; a reused salt with the same keys reuses key and nonce). */
  readonly salt: Uint8Array;
  /** Zero octets added after the delimiter to hide the length (default 0). */
  readonly padding?: number;
  /** The `rs` field, 18 to 4096 (default 4096): plaintext + padding + 17 must fit in it. */
  readonly recordSize?: number;
  /** The sender's ephemeral agreement pair; drawn from WebCrypto when absent (tests pass a fixed one). */
  readonly ephemeral?: CryptoKeyPair;
}

export type PushEncryptRefusal =
  | 'plaintext'
  | 'receiver-key'
  | 'auth-secret'
  | 'salt'
  | 'padding'
  | 'record-size'
  | 'too-long'
  | 'crypto';

const isCount = (v: unknown, max: number): v is number =>
  typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;

/** Encrypts one Web Push message (header + one record). */
export async function encryptPushMessage(
  p: PushEncryptParams,
): Promise<PushResult<Uint8Array, PushEncryptRefusal>> {
  try {
    if (!(p.plaintext instanceof Uint8Array)) return fail('plaintext');
    const padding = p.padding ?? 0;
    const recordSize = p.recordSize ?? PUSH_LIMITS.recordSizeMax;
    if (!isCount(padding, PUSH_LIMITS.recordSizeMax)) return fail('padding');
    if (!isCount(recordSize, PUSH_LIMITS.recordSizeMax) || recordSize < PUSH_LIMITS.recordSizeMin)
      return fail('record-size');
    if (!(p.salt instanceof Uint8Array) || p.salt.length !== saltBytes) return fail('salt');
    const auth = readBytes(p.authSecret, authBytes, authBytes);
    if (!auth) return fail('auth-secret');
    if (!isPoint(p.receiverPublic)) return fail('receiver-key');
    const receiverKey = await importPoint(p.receiverPublic);
    if (!receiverKey) return fail('receiver-key');
    const recordLength = p.plaintext.length + 1 + padding + 16;
    if (recordLength > recordSize) return fail('too-long');

    const ephemeral =
      p.ephemeral ??
      (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
        'deriveBits',
      ]));
    const senderText = await ownPoint(ephemeral);
    if (!senderText) return fail('crypto');
    const senderPoint = readBytes(senderText, pointBytes, pointBytes) as Uint8Array;
    const receiverPoint = readBytes(p.receiverPublic, pointBytes, pointBytes) as Uint8Array;
    const secret = await ecdh(ephemeral.privateKey, receiverKey);
    const { cek, nonce } = await deriveKeys(secret, receiverPoint, senderPoint, auth, p.salt);

    const record = new Uint8Array(recordLength - 16);
    record.set(p.plaintext, 0);
    record[p.plaintext.length] = 2; // delimiter of the last (here: only) record; the padding stays zero
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(nonce) }, cek, record),
    );
    const header = new Uint8Array(headerBytes);
    header.set(p.salt, 0);
    new DataView(header.buffer).setUint32(saltBytes, recordSize);
    header[saltBytes + 4] = pointBytes;
    header.set(senderPoint, saltBytes + 5);
    return pass(concat(header, sealed));
  } catch {
    return fail('crypto');
  }
}

export interface PushDecryptParams {
  /** The whole body of the push request. */
  readonly body: Uint8Array;
  /** The receiver's agreement private key (the `p256dh` pair). */
  readonly receiverPrivate: CryptoKey;
  /** The receiver's public point, 87 base64url characters. */
  readonly receiverPublic: string;
  /** The subscription's `auth` secret. */
  readonly authSecret: string;
}

export type PushDecryptRefusal =
  | 'body'
  | 'receiver-key'
  | 'auth-secret'
  | 'header'
  | 'record-size'
  | 'key-id'
  | 'multiple-records'
  | 'decrypt'
  | 'delimiter'
  | 'crypto';

export interface PushDecrypted {
  readonly plaintext: Uint8Array;
  /** Number of zero padding octets that followed the delimiter. */
  readonly padding: number;
}

/**
 * Decrypts a Web Push message of exactly one record (for a receiver and for tests). Strict: the key id
 * must be a valid 65-byte point, `rs` 18 to 4096, the record the last one (delimiter 2, only zeros
 * after it) and no byte may follow it. Anything else is a code.
 */
export async function decryptPushMessage(
  p: PushDecryptParams,
): Promise<PushResult<PushDecrypted, PushDecryptRefusal>> {
  try {
    if (!(p.body instanceof Uint8Array)) return fail('body');
    const auth = readBytes(p.authSecret, authBytes, authBytes);
    if (!auth) return fail('auth-secret');
    if (!isPoint(p.receiverPublic)) return fail('receiver-key');
    if (p.body.length < headerBytes + recordOverhead) return fail('header');
    const view = new DataView(p.body.buffer, p.body.byteOffset, p.body.byteLength);
    const recordSize = view.getUint32(saltBytes);
    if (recordSize < PUSH_LIMITS.recordSizeMin || recordSize > PUSH_LIMITS.recordSizeMax)
      return fail('record-size');
    if (p.body[saltBytes + 4] !== pointBytes) return fail('key-id');
    const sealed = p.body.subarray(headerBytes);
    if (sealed.length > recordSize) return fail('multiple-records');
    const senderPoint = p.body.slice(saltBytes + 5, headerBytes);
    const senderKey = await importPoint(base64url(senderPoint));
    if (!senderKey) return fail('key-id');
    const receiverPoint = readBytes(p.receiverPublic, pointBytes, pointBytes) as Uint8Array;
    const secret = await ecdh(p.receiverPrivate, senderKey);
    const { cek, nonce } = await deriveKeys(
      secret,
      receiverPoint,
      senderPoint,
      auth,
      p.body.slice(0, saltBytes),
    );
    let record: Uint8Array;
    try {
      record = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: new Uint8Array(nonce) },
          cek,
          new Uint8Array(sealed),
        ),
      );
    } catch {
      return fail('decrypt');
    }
    let end = record.length;
    while (end > 0 && record[end - 1] === 0) end -= 1;
    if (end === 0 || record[end - 1] !== 2) return fail('delimiter');
    return pass({ plaintext: record.slice(0, end - 1), padding: record.length - end });
  } catch {
    return fail('crypto');
  }
}
