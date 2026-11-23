// An independent implementation of the envelope, written from docs/wire-format.md ("Envelope") with
// node:crypto only (no code of src/). The tests use it to show that the documented texts and
// numbers are enough to make and open the bytes, and to play an attacker who forges the inside.
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  type BinaryLike,
} from 'node:crypto';
import { dh, jwkToPoint, type PrivateJwk } from './reference.ts';

const b64 = (buf: Uint8Array): string => Buffer.from(buf).toString('base64url');
const field = (text: string): string => `${Buffer.byteLength(text)}:${text}`;
const sha = (text: BinaryLike): Buffer => createHash('sha256').update(text).digest();
const ZERO_IV = Buffer.alloc(12);

export const refHeader = (appId: string, day: string, eph: string): string =>
  `${appId}-envelope:3|header|${field(day)}|${field(eph)}`;

export function refKek(appId: string, secret: Buffer, header: string, readerDh: string): Buffer {
  return Buffer.from(
    hkdfSync('sha256', secret, sha(header), `${appId}-envelope:3|slot|${field(readerDh)}`, 32),
  );
}

/** The key commitment: SHA-256 over `<appId>-envelope:3|commit|<header>|` and the raw content key. */
export const refCommit = (appId: string, header: string, contentKey: Buffer): string =>
  b64(
    createHash('sha256')
      .update(`${appId}-envelope:3|commit|${header}|`)
      .update(contentKey)
      .digest(),
  );

export function gcm(key: Buffer, iv: Buffer, aad: string | undefined, data: Buffer): Buffer {
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  if (aad !== undefined) cipher.setAAD(Buffer.from(aad));
  return Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
}

export function ungcm(
  key: Buffer,
  iv: Buffer,
  aad: string | undefined,
  data: Buffer,
): Buffer | undefined {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    if (aad !== undefined) decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(data.subarray(data.length - 16));
    return Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]);
  } catch {
    return undefined;
  }
}

export interface EnvelopeParts {
  day: string;
  eph: string;
  iv: string;
  kc: string;
  ct: string;
  k: string[];
}

export function refId(appId: string, p: EnvelopeParts): string {
  const text = `${appId}-envid:3|${field(p.day)}|${field(p.eph)}|${field(p.iv)}|${field(p.kc)}|${field(p.ct)}|${
    p.k.length
  }|${p.k.map(field).join('|')}`;
  return b64(sha(text).subarray(0, 16));
}

export const refText = (appId: string, id: string, p: EnvelopeParts): string =>
  `{"m":"${appId}-envelope:3","id":"${id}","day":"${p.day}","eph":"${p.eph}","iv":"${p.iv}","kc":"${p.kc}","ct":"${
    p.ct
  }","k":[${p.k.map((s) => `"${s}"`).join(',')}]}`;

/** The text the author signs. */
export const refSigned = (
  appId: string,
  from: string,
  channel: string,
  day: string,
  body: string,
): string => `${appId}-envsig:3|${field(from)}|${field(channel)}|${field(day)}|${field(body)}`;

export const refInner = (from: string, channel: string, sig: string, body: string): string =>
  `{"from":${JSON.stringify(from)},"channel":${JSON.stringify(channel)},"sig":"${sig}","body":"${body}"}`;

export interface RefSealInput {
  appId: string;
  day: string;
  ephPriv: PrivateJwk;
  /** Agreement points of the readers, in the order of their slots before the padding. */
  readers: string[];
  contentKey: Buffer;
  iv: Buffer;
  padding: Buffer[];
  /** The order of the slots (a permutation of 0 .. n-1); default: as they are. */
  order?: number[];
  /** The inside text, as it is encrypted. */
  inner: string;
}

export function refSeal(input: RefSealInput): { text: string; id: string; parts: EnvelopeParts } {
  const { appId, day, ephPriv, readers, contentKey, iv, padding, inner } = input;
  const eph = jwkToPoint(ephPriv);
  const header = refHeader(appId, day, eph);
  const slots = [
    ...readers.map((reader) =>
      b64(gcm(refKek(appId, dh(ephPriv, reader), header, reader), ZERO_IV, undefined, contentKey)),
    ),
    ...padding.map(b64),
  ];
  const order = input.order ?? slots.map((_, i) => i);
  const parts: EnvelopeParts = {
    day,
    eph,
    iv: b64(iv),
    kc: refCommit(appId, header, contentKey),
    ct: b64(gcm(contentKey, iv, header, Buffer.from(inner))),
    k: order.map((i) => slots[i] as string),
  };
  const id = refId(appId, parts);
  return { text: refText(appId, id, parts), id, parts };
}

export interface RefOpened {
  header: string;
  salt: Buffer;
  kek: Buffer;
  slotIndex: number;
  contentKey: Buffer;
  inner: string;
}

/** The inside text of an envelope for the holder of `ownPriv`, or undefined; `slotIndex` = where it sat. */
export function refOpen(appId: string, text: string, ownPriv: PrivateJwk): RefOpened | undefined {
  const raw = JSON.parse(text) as {
    day: string;
    eph: string;
    iv: string;
    kc: string;
    ct: string;
    k: string[];
  };
  const header = refHeader(appId, raw.day, raw.eph);
  const ownDh = jwkToPoint(ownPriv);
  const kek = refKek(appId, dh(ownPriv, raw.eph), header, ownDh);
  for (const [slotIndex, slot] of raw.k.entries()) {
    const contentKey = ungcm(kek, ZERO_IV, undefined, Buffer.from(slot, 'base64url'));
    if (!contentKey || refCommit(appId, header, contentKey) !== raw.kc) continue;
    const inner = ungcm(
      contentKey,
      Buffer.from(raw.iv, 'base64url'),
      header,
      Buffer.from(raw.ct, 'base64url'),
    );
    return (
      inner && { header, salt: sha(header), kek, slotIndex, contentKey, inner: inner.toString() }
    );
  }
  return undefined;
}
