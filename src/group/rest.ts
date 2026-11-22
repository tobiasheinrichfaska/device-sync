// The group state at rest: the stored state text (raw keys) encrypted under an AES-256-GCM key the app
// keeps non-extractable (in the browser key store). One text in one spelling; the app, the data set and
// the version are bound as authenticated data. Pure: the IV comes from the injected `random`, every
// check that costs nothing runs before WebCrypto is touched, and nothing here throws on foreign input.
import { marker } from '../core/markers.ts';
import {
  TAG_BYTES,
  decodeUtf8,
  field,
  hasMembers,
  isPlain,
  parseJson,
  readBytes,
} from '../core/secure.ts';
import { base64url } from '../core/encoding.ts';
import { resolveGroupLimits, maxStateChars, type GroupLimits } from './limits.ts';
import { readGroupState, storeGroupState } from './state.ts';
import { isSetText, parseStateShape, type GroupState } from './wire.ts';
import type { RandomBytes } from './grant.ts';

/** Version of the sealed text. */
export const REST_VERSION = 1;
/** Bytes of the IV: 96 bits, drawn fresh from `random` for every sealing. */
export const REST_IV_BYTES = 12;
const KIND = 'grest';
const utf8 = new TextEncoder();
const q = JSON.stringify;

export type SealStateRefusal =
  'bad-input' | 'bad-key' | 'bad-random' | 'too-large' | 'crypto-failure';
export type OpenStateRefusal =
  | 'bad-input'
  | 'bad-key'
  | 'not-sealed'
  | 'truncated'
  | 'unsupported-version'
  | 'wrong-data-set'
  | 'cannot-open'
  | 'bad-state';

export type SealedState =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly reason: SealStateRefusal };
export type OpenedState =
  | { readonly ok: true; readonly state: GroupState }
  | { readonly ok: false; readonly reason: OpenStateRefusal };

export interface SealStateOptions {
  readonly appId: string;
  readonly random: RandomBytes;
  readonly limits?: Partial<GroupLimits>;
}
export interface OpenStateOptions {
  readonly appId: string;
  /** When given, a sealed text of another data set is refused before anything is decrypted. */
  readonly dataSet?: string;
  readonly limits?: Partial<GroupLimits>;
}

/** The most plaintext bytes a state can have under these limits (UTF-8 is at most 3 bytes per unit). */
const maxStateBytes = (lim: GroupLimits): number => 3 * maxStateChars(lim);

/** The most characters of a sealed state under these limits. */
export const maxSealedStateChars = (limits?: Partial<GroupLimits>): number => {
  const lim = resolveGroupLimits(limits);
  return Math.ceil(((maxStateBytes(lim) + TAG_BYTES) * 4) / 3) + 600;
};

/** Duck type of a usable wrap key: a non-extractable AES-256-GCM secret key for encrypt and decrypt. */
export function wrapKeyProblem(key: unknown): boolean {
  if (typeof key !== 'object' || key === null) return true;
  const k = key as {
    type?: unknown;
    extractable?: unknown;
    algorithm?: { name?: unknown; length?: unknown };
    usages?: unknown;
  };
  return !(
    k.type === 'secret' &&
    k.extractable === false &&
    k.algorithm?.name === 'AES-GCM' &&
    k.algorithm?.length === 256 &&
    Array.isArray(k.usages) &&
    k.usages.includes('encrypt') &&
    k.usages.includes('decrypt')
  );
}

const aad = (appId: string, set: string): Uint8Array =>
  utf8.encode(`${marker(appId, KIND, REST_VERSION)}|${field(set)}`);

const sealedText = (appId: string, set: string, iv: Uint8Array, ct: Uint8Array): string =>
  `{"m":${q(marker(appId, KIND, REST_VERSION))},"set":${q(set)},"iv":${q(base64url(iv))},"ct":${q(
    base64url(ct),
  )}}`;

const appOk = (appId: unknown): appId is string => {
  try {
    marker(appId as string, KIND, REST_VERSION);
    return true;
  } catch {
    return false;
  }
};

/**
 * Seals the state text. One WebCrypto call (`encrypt`) after every cheap check; a fresh random 96-bit IV
 * per sealing. Message budget: with random IVs one wrap key must seal well below 2^32 texts (NIST
 * SP 800-38D); the app seals once per state change, so the budget is never near, but an app that seals
 * in a loop replaces the wrap key (re-seal under a new one) long before that.
 */
export async function sealGroupState(
  state: GroupState,
  wrapKey: CryptoKey,
  options: SealStateOptions,
): Promise<SealedState> {
  if (!isPlain(options) || !appOk(options.appId) || typeof options.random !== 'function') {
    return { ok: false, reason: 'bad-input' };
  }
  const { appId, random } = options;
  if (!isPlain(state) || !isSetText(state.dataSet) || !Array.isArray(state.keys)) {
    return { ok: false, reason: 'bad-input' };
  }
  if (wrapKeyProblem(wrapKey)) return { ok: false, reason: 'bad-key' };
  const lim = resolveGroupLimits(options.limits);
  let plain: string;
  try {
    plain = storeGroupState(appId, state);
  } catch {
    return { ok: false, reason: 'bad-input' };
  }
  if (plain.length > maxStateChars(lim)) return { ok: false, reason: 'too-large' };
  // Only a state the strict reader would accept is sealed (a junk value is the caller's bug, now).
  if (!parseStateShape(appId, plain, options.limits)) return { ok: false, reason: 'bad-input' };
  let iv: Uint8Array;
  try {
    iv = random(REST_IV_BYTES);
  } catch {
    return { ok: false, reason: 'bad-random' };
  }
  if (!(iv instanceof Uint8Array) || iv.length !== REST_IV_BYTES) {
    return { ok: false, reason: 'bad-random' };
  }
  try {
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: new Uint8Array(iv),
          additionalData: new Uint8Array(aad(appId, state.dataSet)),
        },
        wrapKey,
        new Uint8Array(utf8.encode(plain)),
      ),
    );
    return { ok: true, text: sealedText(appId, state.dataSet, iv, ct) };
  } catch {
    return { ok: false, reason: 'crypto-failure' };
  }
}

const PREFIX = /^\{"m":"([a-z][a-z0-9]{1,15})-grest:(\d{1,9})"/;

interface Sealed {
  readonly set: string;
  readonly iv: Uint8Array;
  readonly ct: Uint8Array;
}

/** The strict reader of a sealed text: no WebCrypto, never throws. */
export function readSealedState(
  appId: string,
  text: unknown,
  limits?: Partial<GroupLimits>,
):
  | { readonly ok: true; readonly sealed: Sealed }
  | { readonly ok: false; readonly reason: OpenStateRefusal } {
  const bad = (reason: OpenStateRefusal) => ({ ok: false as const, reason });
  if (typeof text !== 'string' || text.length > maxSealedStateChars(limits))
    return bad('not-sealed');
  const head = PREFIX.exec(text);
  if (!head || head[1] === undefined || head[2] === undefined) return bad('not-sealed');
  // The text names the app only inside the marker: it must be the caller's app.
  if (`${head[1]}` !== appId) return bad('not-sealed');
  if (Number(head[2]) !== REST_VERSION) {
    return bad(Number(head[2]) > REST_VERSION ? 'unsupported-version' : 'not-sealed');
  }
  const cut = !text.endsWith('"}');
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'set', 'iv', 'ct'])) {
    return bad(cut ? 'truncated' : 'not-sealed');
  }
  const lim = resolveGroupLimits(limits);
  const iv = readBytes(raw.iv, REST_IV_BYTES, REST_IV_BYTES);
  const ct = readBytes(raw.ct, 0, maxStateBytes(lim) + TAG_BYTES);
  if (!isSetText(raw.set) || !iv || !ct) return bad('not-sealed');
  if (ct.length < TAG_BYTES) return bad('truncated');
  if (sealedText(appId, raw.set, iv, ct) !== text) return bad('not-sealed');
  return { ok: true, sealed: { set: raw.set, iv, ct } };
}

/**
 * Opens a sealed state. A wrong key and a changed text are the same answer (`cannot-open`): GCM cannot
 * tell them apart. Bounded: the text length, the header and the data set are checked before the one
 * `decrypt`; the state is read strictly after it. NOT a rollback guard: an older sealed text of the
 * same data set opens fine.
 */
export async function openGroupState(
  text: string,
  wrapKey: CryptoKey,
  options: OpenStateOptions,
): Promise<OpenedState> {
  if (!isPlain(options) || !appOk(options.appId)) return { ok: false, reason: 'bad-input' };
  if (options.dataSet !== undefined && !isSetText(options.dataSet)) {
    return { ok: false, reason: 'bad-input' };
  }
  if (wrapKeyProblem(wrapKey)) return { ok: false, reason: 'bad-key' };
  const read = readSealedState(options.appId, text, options.limits);
  if (!read.ok) return read;
  const { set, iv, ct } = read.sealed;
  if (options.dataSet !== undefined && options.dataSet !== set) {
    return { ok: false, reason: 'wrong-data-set' };
  }
  let plain: string | undefined;
  try {
    const bytes = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: new Uint8Array(iv),
          additionalData: new Uint8Array(aad(options.appId, set)),
        },
        wrapKey,
        new Uint8Array(ct),
      ),
    );
    plain = decodeUtf8(bytes);
  } catch {
    return { ok: false, reason: 'cannot-open' };
  }
  if (plain === undefined) return { ok: false, reason: 'bad-state' };
  const state = await readGroupState(options.appId, plain, options.limits);
  if (!state || state.dataSet !== set) return { ok: false, reason: 'bad-state' };
  return { ok: true, state };
}
