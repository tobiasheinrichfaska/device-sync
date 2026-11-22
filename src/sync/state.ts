// The memory of the sync layer between two steps: in RAM only, never stored. Losing it costs one
// new round per peer (nothing is resumed; the log's stand says what is still missing). One value per
// device and data set; `syncOnce` changes it in place and refuses a second call while one runs.
import {
  FrameAssembler,
  splitPayload,
  FRAMING_LIMITS,
  type FramingLimits,
} from '../relay/index.ts';
import type { Session } from '../log/index.ts';
import type { SyncCode } from './limits.ts';
import type { Peer } from './roster.ts';

export interface Round {
  readonly id: string;
  readonly startedMs: number;
  session: Session;
  pieces: number;
  /** Frame transfer ids already taken in this round (a replayed piece is ignored). */
  readonly seen: Set<string>;
}

export interface PeerState {
  round?: Round | undefined;
  /** Times of asks of this peer that were answered or refused (sliding window). */
  asks: number[];
  /** Round ids of asks already answered (an identical repeat is ignored). */
  answered: string[];
  /** The peer's last ask showed it ahead of this device: pull from it. */
  ahead: boolean;
  /** The last round took something or was cut: ask again at once. */
  again: boolean;
  /** The vector of this device when it last asked this peer (a change since then is news to tell). */
  askedVector?: string;
  /** When the last round ended (or failed). */
  endedMs?: number;
}

export interface Queued {
  /** A removal notice: the one thing a removed device is sent. */
  readonly notice?: true;
  readonly frames: readonly Uint8Array[];
  readonly queuedMs: number;
  next: number;
}

export interface SyncState {
  /** True while `syncOnce` runs. */
  busy: boolean;
  readonly assembler: FrameAssembler;
  readonly peers: Map<string, PeerState>;
  readonly outbox: Map<string, Queued[]>;
  /** Until when frames count as recent activity (fast cadence). */
  busyUntil: number;
  /** Relay failures of the collect in a row. */
  failures: number;
  /** The devices whose removal counted at the last step. */
  removed: ReadonlySet<string>;
  /** Devices told of their removal (device to time), bounded by `rememberedNotices`; RAM only. */
  readonly told: Map<string, number>;
  /** The removed devices that may be told now, addressed by their entry's relay id (rebuilt every step). */
  noticeTargets: ReadonlyMap<string, Peer>;
  /** A removal notice proved that this device was removed: the step does nothing else any more. */
  removedProof: boolean;
  /** Totals since the state was made, by code. */
  readonly counters: Record<string, number>;
}

export function newSyncState(appId: string, framing: FramingLimits = FRAMING_LIMITS): SyncState {
  return {
    busy: false,
    busyUntil: 0,
    failures: 0,
    assembler: new FrameAssembler(appId, framing),
    peers: new Map(),
    outbox: new Map(),
    removed: new Set(),
    told: new Map(),
    noticeTargets: new Map(),
    removedProof: false,
    counters: Object.create(null) as Record<string, number>,
  };
}

export const peerState = (state: SyncState, device: string): PeerState => {
  let p = state.peers.get(device);
  if (!p) state.peers.set(device, (p = { asks: [], answered: [], ahead: false, again: false }));
  return p;
};

export const queuedFrames = (state: SyncState, device: string): number =>
  (state.outbox.get(device) ?? []).reduce((n, q) => n + q.frames.length - q.next, 0);

/** The count of every code the state has seen (a copy). */
export const totals = (state: SyncState): Record<SyncCode | string, number> => ({
  ...state.counters,
});

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** Frames of one payload with a fresh transfer id; undefined when the framing refuses it. */
export function frameOf(
  appId: string,
  payload: Uint8Array,
  random: (n: number) => Uint8Array,
  framing: FramingLimits = FRAMING_LIMITS,
): Uint8Array[] | undefined {
  const id = hex(random(8));
  const split = splitPayload(appId, payload, id, framing);
  return split.ok ? [...split.frames] : undefined;
}
