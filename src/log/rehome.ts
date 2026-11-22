// Moving a data set to a new device id: the same data, numbering anew under another id. The old id
// stays in the log as an author of what it wrote; the new id must never have written anything, or its
// numbers would clash with what is there.
import { DEFAULT_DEVICE_ID } from './parse.ts';
import type { Replica } from './types.ts';

export type RehomeResult =
  | { readonly ok: true; readonly replica: Replica }
  | { readonly ok: false; readonly reason: 'bad-device' | 'already-wrote' | 'unsigned-changes' };

/**
 * The same replica, writing as `newDevice` from now on. Refused when:
 * - `newDevice` is not a device id (`deviceId` option, default `DEFAULT_DEVICE_ID`): `bad-device`;
 * - the new id already wrote (a number in the vector or a change in the log): `already-wrote`;
 * - the old id has changes that are not signed yet: `unsigned-changes` (they could never be signed
 *   under the old id again, which would leave a gap in its numbering; sign them first with
 *   `signOwnChanges`). With nothing to do (`newDevice` is the replica's device) the replica is returned.
 * The key pair of the new id is the caller's business (a new device id means new keys and a new entry
 * in the device list; see `docs/channel.md`). Pure; the approval state and the base are kept as they are.
 */
export function rehome(
  replica: Replica,
  newDevice: string,
  options: { readonly deviceId?: (id: string) => boolean } = {},
): RehomeResult {
  const valid = options.deviceId ?? ((s: string) => DEFAULT_DEVICE_ID.test(s));
  if (typeof newDevice !== 'string' || !valid(newDevice))
    return { ok: false, reason: 'bad-device' };
  if (newDevice === replica.device) return { ok: true, replica };
  if (
    Object.hasOwn(replica.vector, newDevice) ||
    replica.log.some((c) => c.device === newDevice) ||
    replica.approval?.entries.some((e) => e.change.device === newDevice)
  ) {
    return { ok: false, reason: 'already-wrote' };
  }
  if (replica.log.some((c) => c.device === replica.device && c.sig === undefined)) {
    return { ok: false, reason: 'unsigned-changes' };
  }
  return { ok: true, replica: { ...replica, device: newDevice } };
}
