// Encrypting opaque bytes under the key of an epoch. One message key per message (HKDF from the
// group key with a fresh salt), so no nonce is ever reused. The epoch, the key id, the app, the data
// set and the app's context are bound into the key derivation and the authenticated data.
import { TAG_BYTES, isPlain } from '../core/secure.ts';
import { fromBase64url } from '../core/encoding.ts';
import { SALT_BYTES, ZERO_IV, dataAad, dataInfo, messageKey } from './derive.ts';
import { MAX_CONTEXT_CHARS, resolveGroupLimits, type GroupLimits } from './limits.ts';
import { findKey, preferredKey } from './state.ts';
import { dataText, parseData, type GroupState } from './wire.ts';
import type { RandomBytes } from './grant.ts';

export type EncryptRefusal = 'no-key' | 'bad-input' | 'too-large' | 'bad-random' | 'crypto-failure';

export type Encrypted =
  | { readonly ok: true; readonly text: string; readonly epoch: number; readonly kid: string }
  | { readonly ok: false; readonly reason: EncryptRefusal };

export interface EncryptParams {
  readonly appId: string;
  readonly state: GroupState;
  readonly plaintext: Uint8Array;
  /** Binds the message to its object (a record id, a change id); the same text must be given to open it. */
  readonly context?: string;
  readonly random: RandomBytes;
  readonly limits?: Partial<GroupLimits>;
}

const contextOk = (c: unknown): c is string =>
  typeof c === 'string' && c.length <= MAX_CONTEXT_CHARS && !/\p{Cs}/u.test(c);

/** Encrypts under `preferredKey`. The text is compact JSON in one spelling. */
export async function encryptGroup(params: EncryptParams): Promise<Encrypted> {
  const { appId, state, plaintext, random } = params;
  const lim = resolveGroupLimits(params.limits);
  const context = params.context ?? '';
  if (!isPlain(state) || !(plaintext instanceof Uint8Array) || !contextOk(context)) {
    return { ok: false, reason: 'bad-input' };
  }
  if (plaintext.length > lim.maxPlaintextBytes) return { ok: false, reason: 'too-large' };
  const key = preferredKey(state);
  if (!key) return { ok: false, reason: 'no-key' };
  let salt: Uint8Array;
  try {
    salt = random(SALT_BYTES);
  } catch {
    return { ok: false, reason: 'bad-random' };
  }
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
    return { ok: false, reason: 'bad-random' };
  }
  try {
    const info = dataInfo(appId, state.dataSet, key.epoch, key.kid);
    const aes = await messageKey(fromBase64url(key.key), salt, info);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: ZERO_IV, additionalData: dataAad(info, context) },
        aes,
        new Uint8Array(plaintext),
      ),
    );
    return {
      ok: true,
      text: dataText(appId, state.dataSet, key.epoch, key.kid, salt, ct),
      epoch: key.epoch,
      kid: key.kid,
    };
  } catch {
    return { ok: false, reason: 'crypto-failure' };
  }
}

export type DecryptRefusal =
  'not-group-data' | 'wrong-data-set' | 'unknown-key' | 'cannot-open' | 'bad-input';

export type Decrypted =
  | {
      readonly ok: true;
      readonly plaintext: Uint8Array;
      readonly epoch: number;
      readonly kid: string;
      /** Whether it was encrypted under the key new data would be encrypted under now. */
      readonly current: boolean;
    }
  | {
      readonly ok: false;
      readonly reason: DecryptRefusal;
      /** With `unknown-key`: the epoch and key id the message names, so the app can ask for the key. */
      readonly epoch?: number;
      readonly kid?: string;
    };

export interface DecryptParams {
  readonly appId: string;
  readonly state: GroupState;
  readonly text: string;
  readonly context?: string;
  readonly limits?: Partial<GroupLimits>;
}

/** Which epoch and key id a text names, read strictly without any key; undefined if it is not group data. */
export function readGroupDataHeader(
  appId: string,
  text: unknown,
  limits?: Partial<GroupLimits>,
): { readonly set: string; readonly epoch: number; readonly kid: string } | undefined {
  const d = parseData(appId, text, limits);
  return d && { set: d.set, epoch: d.epoch, kid: d.kid };
}

/** Decrypts with the key the message names. Never throws; a refusal is a code. */
export async function decryptGroup(params: DecryptParams): Promise<Decrypted> {
  const { appId, state } = params;
  const context = params.context ?? '';
  if (!isPlain(state) || !contextOk(context)) return { ok: false, reason: 'bad-input' };
  const data = parseData(appId, params.text, params.limits);
  if (!data) return { ok: false, reason: 'not-group-data' };
  if (data.set !== state.dataSet) return { ok: false, reason: 'wrong-data-set' };
  const key = findKey(state, data.epoch, data.kid);
  if (!key) return { ok: false, reason: 'unknown-key', epoch: data.epoch, kid: data.kid };
  try {
    const info = dataInfo(appId, state.dataSet, key.epoch, key.kid);
    const aes = await messageKey(fromBase64url(key.key), data.salt, info);
    const plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ZERO_IV, additionalData: dataAad(info, context) },
        aes,
        new Uint8Array(data.ct),
      ),
    );
    if (plain.length + TAG_BYTES !== data.ct.length) return { ok: false, reason: 'cannot-open' };
    return {
      ok: true,
      plaintext: plain,
      epoch: key.epoch,
      kid: key.kid,
      current: preferredKey(state)?.kid === key.kid,
    };
  } catch {
    return { ok: false, reason: 'cannot-open' };
  }
}
