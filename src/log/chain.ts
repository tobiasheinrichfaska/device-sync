import { changeLink } from './check.ts';
import { LogCache } from './logCache.ts';
import type { Change, DeviceId, Replica, VersionVector } from './types.ts';
import { seen } from './vector.ts';

export const idOf = (c: Change): string => `${c.device}#${c.seq}`;

const heldCache = new LogCache<Map<string, Change>>();

/** The changes of a log by device and number (kept per log array, which a merge never changes later). */
export function heldIn(log: readonly Change[]): Map<string, Change> {
  return heldCache.getOrBuild(log, () => new Map(log.map((c) => [idOf(c), c])));
}

/** The evidence accessor: the change this replica holds with this device and number, if any. */
export function changeAt(replica: Replica, device: DeviceId, seq: number): Change | undefined {
  return heldIn(replica.log).get(`${device}#${seq}`);
}

/**
 * What a `stand` CLAIMS about the history behind its vector: per device the link (`changeLink`, a
 * hash of the whole signed head, which names its predecessor's link) of the change at the vector's
 * position. A receiver that holds another version of that number has a history that differs from the
 * sender's (`tipConflict`). It is an UNPROVEN claim, not a proof: it names no culprit.
 */
export function tipsOf(replica: Replica): Record<DeviceId, string> {
  const held = heldIn(replica.log);
  const tips = Object.create(null) as Record<DeviceId, string>;
  for (const [device, seq] of Object.entries(replica.vector)) {
    if (seq < 1) continue;
    const change = held.get(`${device}#${seq}`);
    const link = change && changeLink(change);
    if (link !== undefined) tips[device] = link;
  }
  return tips;
}

/**
 * The first device whose tip contradicts what this replica holds: the change it holds at the tip's
 * number has another link. It names the device whose HISTORY differs, not who is lying: the sender
 * may have forged the tip, or this replica holds one of two versions of a double signature. Tips of
 * numbers this replica does not hold say nothing and are skipped.
 */
export function tipConflict(
  replica: Replica,
  vector: VersionVector,
  tips: Readonly<Record<DeviceId, string>>,
): DeviceId | undefined {
  const held = heldIn(replica.log);
  for (const device of Object.keys(tips).sort()) {
    const seq = seen(vector, device);
    const tip = tips[device];
    if (seq < 1 || tip === undefined) continue;
    // Numbering is gapless: a replica that does not hold this number holds nothing after it either.
    const at = held.get(`${device}#${seq}`);
    const link = at && changeLink(at);
    if (link !== undefined && link !== tip) return device;
  }
  return undefined;
}
