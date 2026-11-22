// Who this device exchanges with: derived from the trust layer, never given by the caller. A device
// is a peer when it is TRUSTED (not removed, not merely known) and its entry names a relay id that
// no other trusted device names. The relay id of a device is what the vouching devices wrote into its
// entry (`relayId`); it is a routing address, never an identity: who sent something is decided by the
// key that opens the file (docs/sync.md).
import { RELAY_DEVICE_ID } from '../relay/index.ts';
import type { Trust } from '../trust/index.ts';
import type { SyncCode } from './limits.ts';

export interface Peer {
  readonly device: string;
  /** The agreement key as the trust layer verified it. */
  readonly dh: string;
  readonly relayId: string;
}

export interface Roster {
  /** Trusted devices with a usable relay id, by device id (no prototype). */
  readonly peers: ReadonlyMap<string, Peer>;
  /** Relay id to the device that owns it (peers only). */
  readonly byRelay: ReadonlyMap<string, string>;
  /** Relay ids of devices whose removal counts (to tell a removed sender from an unknown one). */
  readonly removedRelay: ReadonlySet<string>;
  /** Trusted devices that could not be made peers, with the reason. */
  readonly excluded: readonly { readonly device: string; readonly reason: SyncCode }[];
}

/**
 * `ownRelayId` is this device's id at the relay (a peer never has it). A relay id named by two
 * trusted devices is nobody's: a message to it could reach the wrong one, so both are left out.
 */
export function buildRoster(trust: Trust, ownDevice: string, ownRelayId: string): Roster {
  const excluded: { device: string; reason: SyncCode }[] = [];
  const named = new Map<string, string[]>();
  for (const d of trust.trusted) {
    if (d.device === ownDevice) continue;
    if (d.relayId === undefined || !RELAY_DEVICE_ID.test(d.relayId) || d.relayId === ownRelayId) {
      excluded.push({ device: d.device, reason: 'no-relay-id' });
      continue;
    }
    named.set(d.relayId, [...(named.get(d.relayId) ?? []), d.device]);
  }
  const peers = new Map<string, Peer>();
  const byRelay = new Map<string, string>();
  for (const d of trust.trusted) {
    if (d.device === ownDevice || d.relayId === undefined) continue;
    const owners = named.get(d.relayId);
    if (!owners) continue;
    if (owners.length !== 1) {
      excluded.push({ device: d.device, reason: 'relay-id-clash' });
      continue;
    }
    peers.set(d.device, { device: d.device, dh: d.dh, relayId: d.relayId });
    byRelay.set(d.relayId, d.device);
  }
  const removedRelay = new Set<string>();
  for (const id of trust.removed) {
    const entry = trust.checkableById.get(id);
    if (entry?.relayId !== undefined && !byRelay.has(entry.relayId)) {
      removedRelay.add(entry.relayId);
    }
  }
  return { peers, byRelay, removedRelay, excluded };
}
