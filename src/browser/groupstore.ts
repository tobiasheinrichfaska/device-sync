// The group state at rest in the key store: a non-extractable AES-256-GCM wrap key (a structured-cloned
// `CryptoKey`, never exportable) and one sealed state text per data set. The sealing itself is the group
// layer's (`sealGroupState`/`openGroupState`); this file only generates the key and stores and loads.
import { sha256Text, base64url } from '../core/encoding.ts';
import {
  openGroupState,
  sealGroupState,
  wrapKeyProblem,
  type GroupLimits,
  type GroupState,
  type OpenStateRefusal,
  type RandomBytes,
  type SealStateRefusal,
} from '../group/index.ts';
import { fail, pass, type BrowserResult } from './limits.ts';
import { RECORD_NAMES, type KeyStore, type StoreReason } from './keystore.ts';

/** Where `generateWrapKey` finds WebCrypto. */
export interface SubtleHolderLike {
  readonly subtle: Pick<SubtleCrypto, 'generateKey'>;
}

export type WrapKeyReason = 'unsupported' | 'failed';

/**
 * A fresh wrap key: AES-256-GCM, `extractable: false`, usages encrypt and decrypt. Nothing can read its
 * bytes, not even this page: it can only be used while a script of the origin runs. Never throws.
 */
export async function generateWrapKey(
  cryptoHolder: SubtleHolderLike | undefined = globalThis.crypto,
): Promise<BrowserResult<CryptoKey, WrapKeyReason>> {
  if (!cryptoHolder?.subtle || typeof cryptoHolder.subtle.generateKey !== 'function') {
    return fail('unsupported');
  }
  try {
    const key = (await cryptoHolder.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ])) as CryptoKey;
    return wrapKeyProblem(key) ? fail('failed') : pass(key);
  } catch {
    return fail('failed');
  }
}

/**
 * The stored wrap key, or a new one stored under `name`. `created: true` on a device that already holds
 * a sealed state means the old wrap key vanished: that state can never be opened again (treat it like
 * a lost key store: ask the other devices for the keys again, `docs/browser.md`).
 */
export async function loadOrCreateWrapKey(
  store: KeyStore,
  name: string = RECORD_NAMES.groupWrapKey,
  cryptoHolder?: SubtleHolderLike,
): Promise<BrowserResult<{ key: CryptoKey; created: boolean }, StoreReason | WrapKeyReason>> {
  const got = await store.getWrapKey(name);
  if (!got.ok) return got;
  if (got.value) return pass({ key: got.value, created: false });
  const made = await generateWrapKey(cryptoHolder);
  if (!made.ok) return made;
  const put = await store.putWrapKey(name, made.value);
  return put.ok ? pass({ key: made.value, created: true }) : put;
}

/** The record name of the sealed state of one data set (a hash: any data set name is a valid record name). */
export const groupStateRecordName = (appId: string, dataSet: string): string =>
  `group-state:${base64url(sha256Text(`${appId}\n${dataSet}`)).slice(0, 32)}`;

export interface StoreStateOptions {
  readonly appId: string;
  readonly random: RandomBytes;
  readonly limits?: Partial<GroupLimits>;
}
export interface LoadStateOptions {
  readonly appId: string;
  readonly limits?: Partial<GroupLimits>;
}

/** Seals the state and writes it as the one record of its data set (replacing the earlier one). */
export async function putGroupState(
  store: KeyStore,
  wrapKey: CryptoKey,
  state: GroupState,
  options: StoreStateOptions,
): Promise<BrowserResult<null, StoreReason | SealStateRefusal>> {
  const sealed = await sealGroupState(state, wrapKey, options);
  if (!sealed.ok) return fail(sealed.reason);
  return store.putSealed(groupStateRecordName(options.appId, state.dataSet), sealed.text);
}

/** The stored state of a data set, or `undefined` when none was stored. A record that does not open is a code. */
export async function getGroupState(
  store: KeyStore,
  wrapKey: CryptoKey,
  dataSet: string,
  options: LoadStateOptions,
): Promise<BrowserResult<GroupState | undefined, StoreReason | OpenStateRefusal>> {
  const got = await store.getSealed(groupStateRecordName(options.appId, dataSet));
  if (!got.ok) return got;
  if (got.value === undefined) return pass(undefined);
  const opened = await openGroupState(got.value, wrapKey, { ...options, dataSet });
  return opened.ok ? pass(opened.state) : fail(opened.reason);
}
