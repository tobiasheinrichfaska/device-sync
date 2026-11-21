import type { DeviceId, VersionVector, WriteRef } from './types.ts';

/**
 * How far one change may move the clock: far beyond any real history (every write counts one), small
 * enough that nobody pushes the clocks to where `clock + 1 === clock`.
 */
export const MAX_CLOCK_JUMP = 10_000_000;

type Stamp = { readonly clock: number; readonly device: DeviceId };

/** Total order of writes: the higher clock wins, on a tie the higher device id. */
export function isNewer(a: Stamp, b: Stamp): boolean {
  return a.clock > b.clock || (a.clock === b.clock && a.device > b.device);
}

export function seen(vector: VersionVector | undefined, device: DeviceId): number {
  return vector?.[device] ?? 0;
}

/** What two stands hold together (a stand only grows): per device the higher number. */
export function unionVector(a: VersionVector, b: VersionVector): VersionVector {
  const out: Record<DeviceId, number> = { ...a };
  for (const [device, seq] of Object.entries(b)) out[device] = Math.max(out[device] ?? 0, seq);
  return out;
}

/** Neither write knew the other: a real conflict, not a sequence. Unknown knowledge: no conflict. */
export function concurrent(a: WriteRef, b: WriteRef): boolean {
  if (a.device === b.device || !a.knew || !b.knew) return false;
  return seen(a.knew, b.device) < b.seq && seen(b.knew, a.device) < a.seq;
}
