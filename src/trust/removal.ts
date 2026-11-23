// The removal notice: how a removed device learns, safely, that it was removed. A removed device is
// not sent anything else, so without this it would keep working on its own old copy for ever. The notice
// is the signed writes to device records that prove the removal to a device that is not in the group any
// more: the entry of the removed device, and (backwards) the entries of every device that wrote into
// those, down to the devices the receiver met in person. The writes are SPARSE (earlier numbers of their
// devices are not sent), so the receiver judges them on a throw-away copy of its replica
// (`judgeRemovalNotice`), never by merging them; only a valid proof that a trusted device removed THIS
// device yields `selfRemoved`. Nothing in the notice is taken into the receiver's data.
//
// Wire form (one spelling): `{"m":"<app>-removal:1","changes":[<change>,...]}`, the changes strictly read
// by the log's parser, only signed `set` writes to the device list, ascending by device and number, no
// repeat, at most `REMOVAL_LIMITS.maxChanges`, at most `maxBytes` bytes; the text is exactly what
// `JSON.stringify` writes. Errors are codes, never sentences.
import { hasDuplicateKeys } from '../core/json.ts';
import { marker } from '../core/markers.ts';
import { decodeUtf8, hasMembers, isPlain, parseJson } from '../core/secure.ts';
import {
  judgeRetained,
  mergeSparse,
  parseChange,
  type Change,
  type ParseOptions,
  type Replica,
} from '../log/index.ts';
import { DEVICE_COLLECTION, deriveSync, entryIndex } from './derive.ts';
import {
  computeTrust,
  deviceKeySource,
  deviceNeverErase,
  type LocalTrustOptions,
} from './devices.ts';
import { resolveValidators } from './ids.ts';
import type { KnownDevice, TrustOptions } from './types.ts';

export const REMOVAL_LIMITS = Object.freeze({
  /** Writes in one notice (a longer chain cannot be told: `too-large`). */
  maxChanges: 2000,
  /** Bytes of the notice text. */
  maxBytes: 1_000_000,
});

const utf8 = new TextEncoder();

/** The marker of a notice of this app. */
export const removalMark = (appId: string): string => marker(appId, 'removal', 1);

export type NoticeFailure =
  /** The target has no entry in the device list. */
  | 'not-entered'
  /** The removal of the target does not count in this replica (or the target is this device). */
  | 'not-removed'
  /** The chain of writes is longer than `REMOVAL_LIMITS` allow. */
  | 'too-large';

export type NoticeResult =
  | { readonly ok: true; readonly changes: readonly Change[] }
  | { readonly ok: false; readonly reason: NoticeFailure };

const byDeviceThenSeq = (a: Change, b: Change): number =>
  a.device < b.device ? -1 : a.device > b.device ? 1 : a.seq - b.seq;

/** Whether a change may be part of a notice: a signed `set` write to the device list with fields. */
const isNoticeChange = (c: Change, collection: string): boolean =>
  c.kind === 'set' &&
  c.collection === collection &&
  c.fields !== undefined &&
  typeof c.sig === 'string' &&
  typeof c.check === 'string';

/**
 * The notice for `target`, from this replica: every signed write to the device list that proves the
 * removal, found backwards from the target's entry (the writes into it, then the writes into the
 * entries of the devices that wrote those, and so on; the target's own writes are left out, they count
 * for nothing). Other devices' entries stay out of it. Only for a device whose removal counts in this
 * replica (`derive`: the target is among `Trust.removed`). Synchronous: the replica counts as judged.
 */
export function removalNotice(
  replica: Replica,
  target: string,
  o: LocalTrustOptions,
): NoticeResult {
  const collection = o.collection ?? DEVICE_COLLECTION;
  const derived = deriveSync(replica, o.direct ?? [], o);
  if (!derived.trust.removed.includes(target)) {
    return { ok: false, reason: 'not-removed' };
  }
  const targets = entryIndex(replica, collection).targets;
  if (!targets.has(target)) return { ok: false, reason: 'not-entered' };
  const picked = new Map<string, Change>();
  const visited = new Set<string>([target]);
  const queue = [target];
  while (queue.length > 0) {
    const id = queue.pop() as string;
    for (const writes of targets.get(id)?.values() ?? []) {
      for (const { change } of writes) {
        if (change.device === target || !isNoticeChange(change, collection)) continue;
        picked.set(`${change.device}#${change.seq}`, change);
        if (picked.size > REMOVAL_LIMITS.maxChanges) return { ok: false, reason: 'too-large' };
        if (!visited.has(change.device)) {
          visited.add(change.device);
          queue.push(change.device);
        }
      }
    }
  }
  const changes = [...picked.values()].sort(byDeviceThenSeq);
  if (changes.length === 0) return { ok: false, reason: 'not-entered' };
  if (writeRemovalNotice(o.appId, changes).length > REMOVAL_LIMITS.maxBytes) {
    return { ok: false, reason: 'too-large' };
  }
  return { ok: true, changes };
}

/** The notice text for these changes (compact JSON, the member order above). */
export function writeRemovalNotice(appId: string, changes: readonly Change[]): Uint8Array {
  return utf8.encode(`{"m":"${removalMark(appId)}","changes":${JSON.stringify(changes)}}`);
}

/** Whether the bytes begin like a notice of this app (a cheap look before the strict reader). */
export function looksLikeRemovalNotice(appId: string, bytes: Uint8Array): boolean {
  const head = utf8.encode(`{"m":"${removalMark(appId)}","changes":[`);
  return bytes.length > head.length && head.every((b, i) => bytes[i] === b);
}

export interface RemovalReadOptions extends ParseOptions {
  /** Name of the device list's collection; default `DEVICE_COLLECTION`. */
  readonly collection?: string;
}

/**
 * Reads a notice strictly: exactly the text `writeRemovalNotice` makes, every change read by the log's
 * parser and a signed `set` write to the device list, ascending by device and number without a repeat,
 * within `REMOVAL_LIMITS`. Anything else is undefined; never throws.
 */
export function readRemovalNotice(
  appId: string,
  bytes: unknown,
  options: RemovalReadOptions = {},
): readonly Change[] | undefined {
  if (!(bytes instanceof Uint8Array) || bytes.length > REMOVAL_LIMITS.maxBytes) return undefined;
  if (!looksLikeRemovalNotice(appId, bytes)) return undefined;
  const text = decodeUtf8(bytes);
  if (text === undefined) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'changes'])) return undefined;
  if (raw.m !== removalMark(appId) || !Array.isArray(raw.changes)) return undefined;
  if (raw.changes.length === 0 || raw.changes.length > REMOVAL_LIMITS.maxChanges) return undefined;
  if (hasDuplicateKeys(text) || JSON.stringify(raw) !== text) return undefined;
  const collection = options.collection ?? DEVICE_COLLECTION;
  const out: Change[] = [];
  for (const item of raw.changes as unknown[]) {
    const change = parseChange(item, options);
    if (!change || !isNoticeChange(change, collection)) return undefined;
    const last = out[out.length - 1];
    if (last && byDeviceThenSeq(last, change) >= 0) return undefined;
    out.push(change);
  }
  return out;
}

/** Why a notice did or did not prove the removal of this device. */
export type NoticeReason =
  /** A valid proof: a trusted device removed this device. */
  | 'removed'
  /** Judged fine, but nothing in it shows this device removed (not about it, partial, or by an untrusted device). */
  | 'no-proof'
  /** Not shaped as a notice (kind, collection, order, repeat). */
  | 'malformed'
  /** More changes than `REMOVAL_LIMITS` allow. */
  | 'too-large'
  /** A change failed judgement (wrong signature, forged, ...): the notice is refused as a whole. */
  | 'refused';

export interface NoticeVerdict {
  readonly selfRemoved: boolean;
  readonly reason: NoticeReason;
  /** With `refused`: the log's reason code of the first failed change. */
  readonly detail?: string;
}

const verdict = (reason: NoticeReason, detail?: string): NoticeVerdict => ({
  selfRemoved: reason === 'removed',
  reason,
  ...(detail !== undefined ? { detail } : {}),
});

/**
 * Judges a notice at the receiver. NOTHING is merged into `replica`: the changes are sparse (a gap would
 * hold them), they are applied only to a copy that is thrown away. Every signature must check against
 * keys this device can vouch for (its met devices in `direct`, then the entries the changes themselves
 * prove, by the trust derivation's own signature checks); one wrong signature refuses the notice. A
 * change nobody can check counts for nothing; the writes of this device itself that it does not hold
 * count for nothing. `selfRemoved` is true only when, on the copy, a removal of THIS device counts
 * (`Trust.selfRemoved`: a trusted device removed it); a notice that names another device, comes from
 * an untrusted one or is partial gives `no-proof`. `o` are the trust options the app uses everywhere.
 */
export async function judgeRemovalNotice(
  replica: Replica,
  direct: readonly KnownDevice[],
  changes: readonly Change[],
  o: TrustOptions,
): Promise<NoticeVerdict> {
  const collection = o.collection ?? DEVICE_COLLECTION;
  if (changes.length > REMOVAL_LIMITS.maxChanges) return verdict('too-large');
  const valid = resolveValidators(o.valid);
  let before: Change | undefined;
  for (const c of changes) {
    if (
      !isNoticeChange(c, collection) ||
      !valid.deviceId(c.device) ||
      (before && byDeviceThenSeq(before, c) >= 0)
    ) {
      return verdict('malformed');
    }
    before = c;
  }
  const rest = changes.filter((c) => c.device !== replica.device);
  const keys = deviceKeySource({ ...o, direct });
  const context = {
    appId: o.appId,
    dataSet: o.dataSet,
    ownDevice: replica.device,
    neverErase: deviceNeverErase(collection),
    keys,
    state: replica,
    // selfVerifying: the derivation checks every entry it reads, so the key of a device that the
    // notice itself introduces is known at once
    keyState: mergeSparse(replica, rest),
  };
  const judged = await judgeRetained(context, rest);
  const failed = judged.find((j) => j.verdict === 'false');
  if (failed) return verdict('refused', failed.reason);
  const checked = rest.filter((_, i) => judged[i]?.verdict === 'checked');
  const copy = mergeSparse(replica, checked);
  const trust = await computeTrust(copy, direct, o);
  return verdict(trust.selfRemoved ? 'removed' : 'no-proof');
}
