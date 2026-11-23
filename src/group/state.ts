// The state of one device for one data set: the keys of every retained epoch. A plain value; every
// function returns a new one. The key of an epoch is chosen by one rule on the keys held (see
// `preferredKey`), so devices that hold the same keys choose the same key.
import { compareUtf8, isDeviceText, readBytes } from '../core/secure.ts';
import { fromBase64url } from '../core/encoding.ts';
import { deriveKeyId } from './derive.ts';
import { MAX_EPOCH, resolveGroupLimits, type GroupLimits } from './limits.ts';
import {
  compareKeys,
  isSetText,
  parseStateShape,
  stateText,
  type GroupKey,
  type GroupState,
} from './wire.ts';

export type { GroupKey, GroupState };

/** A state with no key for a data set. */
export function emptyGroupState(dataSet: string): GroupState {
  if (!isSetText(dataSet)) throw new TypeError('emptyGroupState: not a valid data set name');
  return { dataSet, floor: 0, keys: [] };
}

/** The highest epoch held, or the floor when no key is held (0 for a state that never held one). */
export const highestEpoch = (state: GroupState): number =>
  state.keys.length === 0 ? state.floor : (state.keys[state.keys.length - 1] as GroupKey).epoch;

/**
 * The key new data is encrypted under: the highest epoch; among concurrent keys of that epoch the
 * one whose author id is lowest in UTF-8 byte order. The choice depends only on the keys held, never
 * on arrival order or a clock.
 */
export function preferredKey(state: GroupState): GroupKey | undefined {
  const top = highestEpoch(state);
  return state.keys.find((k) => k.epoch === top);
}

/** The key with this epoch and key id, or undefined. */
export const findKey = (state: GroupState, epoch: number, kid: string): GroupKey | undefined =>
  state.keys.find((k) => k.epoch === epoch && k.kid === kid);

export type AddRefusal =
  | 'below-floor'
  | 'epoch-jump'
  | 'author-conflict'
  | 'epoch-full'
  | 'too-many-keys'
  | 'audience-full';

export type AddResult =
  | {
      readonly ok: true;
      readonly state: GroupState;
      /** `added`: a key new to the state. `audience`: only the audience of a held key grew. `same`: nothing new. */
      readonly change: 'added' | 'audience' | 'same';
    }
  | { readonly ok: false; readonly reason: AddRefusal };

const mergeIds = (a: readonly string[], b: readonly string[]): string[] =>
  [...new Set([...a, ...b])].sort(compareUtf8);

/**
 * Adds a key. The same key (epoch, author, key id) again only merges the audience (a union: it can
 * only grow, so devices that saw the same grants agree). A second, different key by the same author
 * for one epoch is refused. Pure: no signature or trust is looked at here.
 */
export function addKey(state: GroupState, key: GroupKey, limits?: Partial<GroupLimits>): AddResult {
  const lim = resolveGroupLimits(limits);
  if (key.epoch < state.floor) return { ok: false, reason: 'below-floor' };
  const held = state.keys.find((k) => k.epoch === key.epoch && k.author === key.author);
  if (held) {
    if (held.kid !== key.kid) return { ok: false, reason: 'author-conflict' };
    const audience = mergeIds(held.audience, key.audience);
    if (audience.length === held.audience.length) return { ok: true, state, change: 'same' };
    if (audience.length > lim.maxAudience) return { ok: false, reason: 'audience-full' };
    return {
      ok: true,
      change: 'audience',
      state: { ...state, keys: state.keys.map((k) => (k === held ? { ...k, audience } : k)) },
    };
  }
  if (highestEpoch(state) > 0 || state.keys.length > 0) {
    if (key.epoch > highestEpoch(state) + lim.maxEpochJump) {
      return { ok: false, reason: 'epoch-jump' };
    }
  }
  if (state.keys.length >= lim.maxKeys) return { ok: false, reason: 'too-many-keys' };
  if (state.keys.filter((k) => k.epoch === key.epoch).length >= lim.maxPerEpoch) {
    return { ok: false, reason: 'epoch-full' };
  }
  const keys = [...state.keys, key].sort(compareKeys);
  return { ok: true, change: 'added', state: { ...state, keys } };
}

/**
 * Forgets the keys of epochs below `keepFrom` and refuses them from now on (the floor). The highest
 * epoch is never dropped. Data still encrypted under a dropped key can no longer be read: the app
 * prunes only when everything it keeps was re-encrypted or may be lost.
 */
export function pruneGroup(state: GroupState, keepFrom: number): GroupState {
  if (!Number.isSafeInteger(keepFrom) || keepFrom < 0) return state;
  const floor = Math.min(
    Math.max(keepFrom, state.floor),
    Math.max(highestEpoch(state), 0),
    MAX_EPOCH,
  );
  if (floor <= state.floor) return state;
  return { ...state, floor, keys: state.keys.filter((k) => k.epoch >= floor) };
}

/** The state as text (compact JSON, one spelling). Holds SECRET keys: the app protects the text. */
export const storeGroupState = (appId: string, state: GroupState): string =>
  stateText(appId, state);

/** A stored state read strictly (also derives and so checks the key ids); undefined for anything else. */
export async function readGroupState(
  appId: string,
  text: unknown,
  limits?: Partial<GroupLimits>,
): Promise<GroupState | undefined> {
  const shape = parseStateShape(appId, text, limits);
  if (!shape) return undefined;
  const keys: GroupKey[] = [];
  for (const k of shape.keys) {
    if (!isDeviceText(k.author) || readBytes(k.key, 32, 32) === undefined) return undefined;
    const kid = await deriveKeyId(appId, shape.dataSet, k.epoch, fromBase64url(k.key));
    keys.push({ ...k, kid });
  }
  return { dataSet: shape.dataSet, floor: shape.floor, keys };
}
