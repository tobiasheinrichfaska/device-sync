// The texts of the group layer and their strict readers: one spelling (compact JSON, members in this
// order), bounded, canonical base64url. A reader never throws; anything else gives undefined.
import { FORMAT_VERSION, marker } from '../core/markers.ts';
import {
  compareUtf8,
  hasMembers,
  isDeviceText,
  isPlain,
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

/** What a grant carries (the payload of the file sealed for one device). */
export interface KeyGrant {
  readonly set: string;
  readonly epoch: number;
  readonly author: string;
  readonly key: string;
  readonly audience: readonly string[];
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

export function grantText(appId: string, g: KeyGrant): string {
  return `{"m":${q(marker(appId, 'gkey', FORMAT_VERSION))},"set":${q(g.set)},"epoch":${g.epoch},"author":${q(
    g.author,
  )},"key":${q(g.key)},"audience":${ids(g.audience)}}`;
}

export function parseGrant(
  appId: string,
  text: unknown,
  limits?: Partial<GroupLimits>,
): KeyGrant | undefined {
  const lim = resolveGroupLimits(limits);
  if (typeof text !== 'string' || text.length > maxGrantChars(lim)) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'set', 'epoch', 'author', 'key', 'audience'])) {
    return undefined;
  }
  const { set, epoch, author, key, audience } = raw;
  if (!isSetText(set) || !isEpoch(epoch) || !isDeviceText(author)) return undefined;
  if (readBytes(key, KEY_BYTES, KEY_BYTES) === undefined) return undefined;
  if (!isIdList(audience, lim.maxAudience) || !audience.includes(author)) return undefined;
  const grant: KeyGrant = { set, epoch, author, key: key as string, audience };
  return grantText(appId, grant) === text ? grant : undefined;
}

// --- rotation request -------------------------------------------------------------------------

export interface RotationRequest {
  readonly set: string;
  /** The highest epoch the requester holds (0: none). A request below the receiver's epoch is stale. */
  readonly epoch: number;
}

export const requestText = (appId: string, r: RotationRequest): string =>
  `{"m":${q(marker(appId, 'greq', FORMAT_VERSION))},"set":${q(r.set)},"epoch":${r.epoch}}`;

export function parseRequest(appId: string, text: unknown): RotationRequest | undefined {
  if (typeof text !== 'string' || text.length > 600) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'set', 'epoch'])) return undefined;
  if (!isSetText(raw.set) || !isEpoch(raw.epoch, 0)) return undefined;
  const request = { set: raw.set, epoch: raw.epoch };
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
