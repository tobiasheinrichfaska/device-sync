// Limits of the group-key layer: one object, every member a bound on work or memory.
import { MAX_DEVICE_ID, overrideNumbers } from '../core/secure.ts';

/** The highest epoch number (an unsigned 32-bit integer). Epochs start at 1; 0 means "no key". */
export const MAX_EPOCH = 4_294_967_295;

export interface GroupLimits {
  /** Keys one state holds (all retained epochs, concurrent candidates included). */
  readonly maxKeys: number;
  /** Concurrent candidate keys of one epoch (different authors) a state keeps. */
  readonly maxPerEpoch: number;
  /** Device ids in the audience of one key (who was given it); a rotation to more devices is refused. */
  readonly maxAudience: number;
  /** A grant more than this many epochs above the highest one held is refused (once a state holds any). */
  readonly maxEpochJump: number;
  /** The largest plaintext `encryptGroup` accepts and `decryptGroup` can return. */
  readonly maxPlaintextBytes: number;
}

export const GROUP_LIMITS: GroupLimits = Object.freeze({
  maxKeys: 64,
  maxPerEpoch: 8,
  maxAudience: 128,
  maxEpochJump: 1000,
  maxPlaintextBytes: 1_048_576,
});

/** The defaults with a partial override of own, non-negative integers on top (counts are at least 1). */
export function resolveGroupLimits(override?: Partial<GroupLimits>): GroupLimits {
  const o = overrideNumbers({ ...GROUP_LIMITS }, override);
  const atLeastOne = (n: number): number => Math.max(n, 1);
  return {
    maxKeys: atLeastOne(o.maxKeys),
    maxPerEpoch: atLeastOne(o.maxPerEpoch),
    maxAudience: atLeastOne(o.maxAudience),
    maxEpochJump: atLeastOne(o.maxEpochJump),
    maxPlaintextBytes: o.maxPlaintextBytes,
  };
}

/** Longest text of an id list: every id as long as allowed, with quotes, escapes and a comma. */
const idsChars = (count: number): number => count * (2 * MAX_DEVICE_ID + 4);

/** The most characters of a key grant payload under these limits. */
export const maxGrantChars = (lim: GroupLimits): number =>
  idsChars(lim.maxAudience) + 6 * MAX_DEVICE_ID + 500;

/** The most characters of a stored state under these limits. */
export const maxStateChars = (lim: GroupLimits): number =>
  lim.maxKeys * (idsChars(lim.maxAudience) + 4 * MAX_DEVICE_ID + 200) + 4 * MAX_DEVICE_ID + 300;

/** The most characters of one encrypted message under these limits. */
export const maxDataChars = (lim: GroupLimits): number =>
  Math.ceil(((lim.maxPlaintextBytes + 16) * 4) / 3) + 2 * MAX_DEVICE_ID + 256;

/** The longest context text (the app's binding of a message to its object). */
export const MAX_CONTEXT_CHARS = 512;
