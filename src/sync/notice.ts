// The removal notice in the sync driver (`docs/sync.md`, "Removal notice"). Who is told: a device whose
// removal counts in this replica, once, with the writes that prove it (`removalNotice`), although the
// roster otherwise sends a removed device nothing. Who is believed: a notice that arrives from a peer is
// judged on a throw-away copy (`judgeRemovalNotice`); only a valid proof that a trusted device removed
// THIS device makes the step stop for good. The notice is never merged.
import { RELAY_DEVICE_ID } from '../relay/index.ts';
import type { Trust } from '../trust/index.ts';
import type { Peer, Roster } from './roster.ts';
import type { SyncState } from './state.ts';

/**
 * The removed devices that may be told now: removal counts, an entry that names a usable relay id and
 * agreement key, a relay id no trusted peer or this device uses, and not told within `retellMs` (a
 * message the relay lost is never noticed, but a device that learned stops collecting and so is never
 * present again, while one that did not is told again). At most `max`, in device order. They are addressed like peers (the relay id of their entry) but get nothing else.
 */
export function noticeTargetsOf(
  trust: Trust,
  roster: Roster,
  state: SyncState,
  ownRelayId: string,
  max: number,
  nowMs: number,
  retellMs: number,
): Map<string, Peer> {
  const out = new Map<string, Peer>();
  for (const id of trust.removed) {
    if (out.size >= max) break;
    const at = state.told.get(id);
    if (at !== undefined && nowMs - at < retellMs) continue;
    const entry = trust.checkableById.get(id);
    const relayId = entry?.relayId;
    if (!entry || relayId === undefined || !RELAY_DEVICE_ID.test(relayId)) continue;
    if (relayId === ownRelayId || roster.byRelay.has(relayId)) continue;
    out.set(id, { device: id, dh: entry.dh, relayId });
  }
  return out;
}

/** Remembers that a device was told; the memory is bounded (the oldest entry goes first). */
export function rememberTold(state: SyncState, device: string, nowMs: number, max: number): void {
  state.told.delete(device);
  state.told.set(device, nowMs);
  while (state.told.size > max) {
    const oldest = state.told.keys().next().value;
    if (oldest === undefined) break;
    state.told.delete(oldest);
  }
}
