// The texts of the group layer and their strict readers: one spelling (compact JSON, members in this
// order), bounded, canonical base64url. A reader never throws; anything else gives undefined.
import { FORMAT_VERSION, marker } from '../core/markers.ts';
import {
  compareUtf8,
  hasMembers,
  isDeviceText,
  isPlain,
  MAX_DEVICE_ID,
  parseJson,
  readBytes,
  TAG_BYTES,
} from '../core/secure.ts';
import { base64url } from '../core/encoding.ts';
import { KEY_BYTES, KID_BYTES, SALT_BYTES } from './derive.ts';
import {
  MAX_EPOCH,
  maxDataChars,
  maxGrantChars,
  maxStateChars,
  resolveGroupLimits,
  type GroupLimits,
} from './limits.ts';

const q = JSON.stringify;

/** An ECDSA P-256 signature in the P1363 form. */
const SIG_BYTES = 64;

/** A data set name as the group layer reads it (the same predicate as a device id). */
export const isSetText = isDeviceText;

/** The key of one epoch as a device holds it. */
export interface GroupKey {
  readonly epoch: number;
  /** The device that made the key (as the grantor reported it). */
  readonly author: string;
  /** The key id derived from the key (22 characters). */
  readonly kid: string;
  /** The 32 key bytes, base64url. Secret. */
  readonly key: string;
  /** Devices that were given the key (sorted by UTF-8 order, unique; includes the author). */
  readonly audience: readonly string[];
}

/**
 * Version of the signed grant and request texts (the markers `gkey`, `greq` and the two signing
 * texts); the other texts of the layer keep the core format version.
 */
export const GRANT_VERSION = 3;

/** What a grant carries (the payload of the file sealed for one device). */
export interface KeyGrant {
  readonly set: string;
  readonly epoch: number;
  /** The device that made the key (the sender's claim for a forwarded key). */
  readonly author: string;
  /** The device that issued this grant and signed it (the sender of the file). */
  readonly from: string;
  /** The one device this grant is for. */
  readonly to: string;
  /** The key id of `key` (22 characters); the signature covers it, so it covers the key. */
  readonly kid: string;
  readonly key: string;
  readonly audience: readonly string[];
  /** Signature of `from` over `grantSigText` (64 bytes, low-s, base64url). */
  readonly sig: string;
}

const isEpoch = (v: unknown, min = 1): v is number =>
  typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= MAX_EPOCH;

/** Strictly increasing by UTF-8 order, every entry a device id, at most `max` entries. */
function isIdList(v: unknown, max: number): v is string[] {
  if (!Array.isArray(v) || v.length < 1 || v.length > max) return false;
  for (let i = 0; i < v.length; i += 1) {
    if (!isDeviceText(v[i])) return false;
    if (i > 0 && compareUtf8(v[i - 1] as string, v[i] as string) >= 0) return false;
  }
  return true;
}

const ids = (list: readonly string[]): string => `[${list.map((x) => q(x)).join(',')}]`;

// --- grant ------------------------------------------------------------------------------------

const gm = (appId: string, kind: string): string => q(marker(appId, kind, GRANT_VERSION));

/**
 * The text a grant's issuer signs: app (in the marker), data set, epoch, key author, issuer,
 * recipient, key id and audience. The raw key is not in it (the key id is derived from it).
 */
export const grantSigText = (appId: string, g: Omit<KeyGrant, 'key' | 'sig'>): string =>
  `{"m":${gm(appId, 'gkeysig')},"set":${q(g.set)},"epoch":${g.epoch},"author":${q(
    g.author,
  )},"from":${q(g.from)},"to":${q(g.to)},"kid":${q(g.kid)},"audience":${ids(g.audience)}}`;

export function grantText(appId: string, g: KeyGrant): string {
  return `{"m":${gm(appId, 'gkey')},"set":${q(g.set)},"epoch":${g.epoch},"author":${q(
    g.author,
  )},"from":${q(g.from)},"to":${q(g.to)},"kid":${q(g.kid)},"key":${q(g.key)},"audience":${ids(
    g.audience,
  )},"sig":${q(g.sig)}}`;
}

export function parseGrant(
  appId: string,
  text: unknown,
  limits?: Partial<GroupLimits>,
): KeyGrant | undefined {
  const lim = resolveGroupLimits(limits);
  if (typeof text !== 'string' || text.length > maxGrantChars(lim)) return undefined;
  const raw = parseJson(text);
  if (
    !isPlain(raw) ||
    !hasMembers(raw, ['m', 'set', 'epoch', 'author', 'from', 'to', 'kid', 'key', 'audience', 'sig'])
  ) {
    return undefined;
  }
  const { set, epoch, author, from, to, kid, key, audience, sig } = raw;
  if (!isSetText(set) || !isEpoch(epoch) || !isDeviceText(author)) return undefined;
  if (!isDeviceText(from) || !isDeviceText(to) || from === to) return undefined;
  if (readBytes(kid, KID_BYTES, KID_BYTES) === undefined) return undefined;
  if (readBytes(key, KEY_BYTES, KEY_BYTES) === undefined) return undefined;
  if (readBytes(sig, SIG_BYTES, SIG_BYTES) === undefined) return undefined;
  if (!isIdList(audience, lim.maxAudience) || !audience.includes(author)) return undefined;
  const grant: KeyGrant = {
    set,
    epoch,
    author,
    from,
    to,
    kid: kid as string,
    key: key as string,
    audience,
    sig: sig as string,
  };
  return grantText(appId, grant) === text ? grant : undefined;
}

// --- rotation request -------------------------------------------------------------------------

export interface RotationRequest {
  readonly set: string;
  /** The highest epoch the requester holds (0: none). A request below the receiver's epoch is stale. */
  readonly epoch: number;
  /** The requester, who signed the request. */
  readonly from: string;
  /** The one device the request is for. */
  readonly to: string;
  /** Signature of `from` over `requestSigText` (64 bytes, low-s, base64url). */
  readonly sig: string;
}

/** The text a requester signs: app (in the marker), data set, epoch held, requester and recipient. */
export const requestSigText = (appId: string, r: Omit<RotationRequest, 'sig'>): string =>
  `{"m":${gm(appId, 'greqsig')},"set":${q(r.set)},"epoch":${r.epoch},"from":${q(r.from)},"to":${q(
    r.to,
  )}}`;

export const requestText = (appId: string, r: RotationRequest): string =>
  `{"m":${gm(appId, 'greq')},"set":${q(r.set)},"epoch":${r.epoch},"from":${q(r.from)},"to":${q(
    r.to,
  )},"sig":${q(r.sig)}}`;

/** The most characters of a rotation request payload: three ids, the signature and the frame. */
export const MAX_REQUEST_CHARS = 3 * (2 * MAX_DEVICE_ID + 4) + 300;

export function parseRequest(appId: string, text: unknown): RotationRequest | undefined {
  if (typeof text !== 'string' || text.length > MAX_REQUEST_CHARS) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'set', 'epoch', 'from', 'to', 'sig'])) {
    return undefined;
  }
  if (!isSetText(raw.set) || !isEpoch(raw.epoch, 0)) return undefined;
  if (!isDeviceText(raw.from) || !isDeviceText(raw.to) || raw.from === raw.to) return undefined;
  if (readBytes(raw.sig, SIG_BYTES, SIG_BYTES) === undefined) return undefined;
  const request = {
    set: raw.set,
    epoch: raw.epoch,
    from: raw.from,
    to: raw.to,
    sig: raw.sig as string,
  };
  return requestText(appId, request) === text ? request : undefined;
}

// --- stored state -----------------------------------------------------------------------------

/** The state as a plain value: the keys of every retained epoch. */
export interface GroupState {
  readonly dataSet: string;
  /** Epochs below this were pruned and are refused when they come again (0: nothing pruned). */
  readonly floor: number;
  /** Sorted by epoch, then author in UTF-8 order. */
  readonly keys: readonly GroupKey[];
}

export const compareKeys = (a: GroupKey, b: GroupKey): number =>
  a.epoch !== b.epoch ? (a.epoch < b.epoch ? -1 : 1) : compareUtf8(a.author, b.author);

export function stateText(appId: string, s: GroupState): string {
  const keys = s.keys
    .map(
      (k) =>
        `{"epoch":${k.epoch},"author":${q(k.author)},"key":${q(k.key)},"audience":${ids(k.audience)}}`,
    )
    .join(',');
  return `{"m":${q(marker(appId, 'gstate', FORMAT_VERSION))},"set":${q(s.dataSet)},"floor":${s.floor},"keys":[${keys}]}`;
}

/** The state without key ids (they are derived when the state is read); undefined unless exact. */
export function parseStateShape(
  appId: string,
  text: unknown,
  limits?: Partial<GroupLimits>,
): { dataSet: string; floor: number; keys: Omit<GroupKey, 'kid'>[] } | undefined {
  const lim = resolveGroupLimits(limits);
  if (typeof text !== 'string' || text.length > maxStateChars(lim)) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'set', 'floor', 'keys'])) return undefined;
  const { set, floor, keys } = raw;
  if (!isSetText(set) || !isEpoch(floor, 0)) return undefined;
  if (!Array.isArray(keys) || keys.length > lim.maxKeys) return undefined;
  const out: Omit<GroupKey, 'kid'>[] = [];
  const perEpoch = new Map<number, number>();
  for (const k of keys as unknown[]) {
    if (!isPlain(k) || !hasMembers(k, ['epoch', 'author', 'key', 'audience'])) return undefined;
    if (!isEpoch(k.epoch, Math.max(floor, 1)) || !isDeviceText(k.author)) return undefined;
    if (readBytes(k.key, KEY_BYTES, KEY_BYTES) === undefined) return undefined;
    if (!isIdList(k.audience, lim.maxAudience) || !k.audience.includes(k.author)) return undefined;
    const entry = { epoch: k.epoch, author: k.author, key: k.key as string, audience: k.audience };
    const last = out[out.length - 1];
    if (last && compareKeys({ ...last, kid: '' }, { ...entry, kid: '' }) >= 0) return undefined;
    const n = (perEpoch.get(entry.epoch) ?? 0) + 1;
    if (n > lim.maxPerEpoch) return undefined;
    perEpoch.set(entry.epoch, n);
    out.push(entry);
  }
  const shape = { dataSet: set, floor, keys: out };
  const again = stateText(appId, { ...shape, keys: out.map((k) => ({ ...k, kid: '' })) });
  return again === text ? shape : undefined;
}

// --- encrypted data ---------------------------------------------------------------------------

export interface GroupData {
  readonly set: string;
  readonly epoch: number;
  readonly kid: string;
  readonly salt: Uint8Array;
  /** Ciphertext with the 16-byte tag. */
  readonly ct: Uint8Array;
}

export const dataText = (
  appId: string,
  set: string,
  epoch: number,
  kid: string,
  salt: Uint8Array,
  ct: Uint8Array,
): string =>
  `{"m":${q(marker(appId, 'gdata', FORMAT_VERSION))},"set":${q(set)},"epoch":${epoch},"kid":${q(
    kid,
  )},"salt":${q(base64url(salt))},"ct":${q(base64url(ct))}}`;

export function parseData(
  appId: string,
  text: unknown,
  limits?: Partial<GroupLimits>,
): GroupData | undefined {
  const lim = resolveGroupLimits(limits);
  if (typeof text !== 'string' || text.length > maxDataChars(lim)) return undefined;
  if (!text.startsWith(`{"m":${q(marker(appId, 'gdata', FORMAT_VERSION))},"set":`))
    return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'set', 'epoch', 'kid', 'salt', 'ct'])) {
    return undefined;
  }
  const { set, epoch, kid } = raw;
  if (!isSetText(set) || !isEpoch(epoch)) return undefined;
  if (readBytes(kid, KID_BYTES, KID_BYTES) === undefined) return undefined;
  const salt = readBytes(raw.salt, SALT_BYTES, SALT_BYTES);
  const ct = readBytes(raw.ct, TAG_BYTES, lim.maxPlaintextBytes + TAG_BYTES);
  if (!salt || !ct) return undefined;
  return dataText(appId, set, epoch, kid as string, salt, ct) === text
    ? { set, epoch, kid: kid as string, salt, ct }
    : undefined;
}
