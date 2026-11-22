// Every number of the sync layer in one place. The table "Limits" in docs/sync.md lists exactly
// these names with exactly these values (tests/sync/docs.test.ts). The relay's own limits are
// `RELAY_LIMITS`; the log's are `LIMITS`; these are what the wiring adds on top.
import { overrideNumbers } from '../core/secure.ts';

export interface SyncLimits {
  /** A pull round waits this long for its answer, then it is dropped (the relay keeps a message 30 s). */
  readonly roundMs: number;
  /** A peer that is in sync is asked again after this long, to find what a lost message left behind. */
  readonly idleRoundMs: number;
  /** A queued message that the relay did not take within this time is dropped (the relay would drop it at 30 s). */
  readonly outboxMs: number;
  /** Frames waiting for one peer; a message that does not fit is dropped and counted. */
  readonly maxQueuedFrames: number;
  /** Most `drop` calls of one step (each takes one frame per recipient). */
  readonly maxDropsPerStep: number;
  /** Most `collect` calls of one step, and most messages and bytes it takes in. */
  readonly maxCollectCalls: number;
  readonly maxMessagesPerStep: number;
  readonly maxCollectBytes: number;
  /** Most pieces one round takes before it is ended as hostile. */
  readonly maxPiecesPerRound: number;
  /** Most asks one peer may have answered per `askWindowMs`; more are dropped. */
  readonly maxAsksPerWindow: number;
  readonly askWindowMs: number;
  /** Ask ids remembered per peer (an identical repeat of an answered ask is ignored). */
  readonly rememberedAsks: number;
  /** The budget of one answer: changes and JSON characters (a cut answer says `more`). */
  readonly answerChanges: number;
  readonly answerChars: number;
  /** Most frames of one answer; the answer budget is halved until the answer fits, else it is not sent. */
  readonly maxFramesPerAnswer: number;
  /** Most data sets a registry may hold besides the main one (more is refused as `bad-input`). */
  readonly maxSets: number;
  /** Most envelopes (the newest) one mailbox exchange of a step offers and announces. */
  readonly maxExchangeEnvelopes: number;
  /** An exchange file (`makeExchangeFile`): most payload bytes before sealing; the answer budget is halved until it fits. */
  readonly maxExchangeFileBytes: number;
  /** The optional notice slot of an exchange file: most characters. */
  readonly maxNoticeChars: number;
  /** Peers the stand memory of an exchange file remembers (the least recently used one goes first). */
  readonly maxRememberedPeers: number;
  /** Files that are not sync packets (e.g. key grants) handed to the app per step. */
  readonly maxPassedPerStep: number;
  /** Events listed in one report. */
  readonly maxEvents: number;
  /** After a frame came or went the step stays "busy" (fast cadence) this long. */
  readonly busyHoldMs: number;
  /** The pause after relay failures in a row: base, doubled each time, at most the cap. */
  readonly failureBaseMs: number;
  readonly failureCapMs: number;
}

export const SYNC_LIMITS: SyncLimits = Object.freeze({
  roundMs: 30_000,
  idleRoundMs: 30_000,
  outboxMs: 25_000,
  maxQueuedFrames: 200,
  maxDropsPerStep: 12,
  maxCollectCalls: 5,
  maxMessagesPerStep: 500,
  maxCollectBytes: 8_388_608,
  maxPiecesPerRound: 200,
  maxAsksPerWindow: 8,
  askWindowMs: 10_000,
  rememberedAsks: 16,
  answerChanges: 400,
  answerChars: 240_000,
  maxFramesPerAnswer: 60,
  maxSets: 16,
  maxExchangeEnvelopes: 100,
  maxExchangeFileBytes: 8_000_000,
  maxNoticeChars: 8000,
  maxRememberedPeers: 256,
  maxPassedPerStep: 16,
  maxEvents: 50,
  busyHoldMs: 30_000,
  failureBaseMs: 2_000,
  failureCapMs: 60_000,
});

/** The defaults with a partial override on top (own, safe, non-negative integers only). */
export function resolveSyncLimits(override?: Partial<SyncLimits>): SyncLimits {
  return overrideNumbers({ ...SYNC_LIMITS }, override);
}

/**
 * Every code the layer writes: why a message was dropped (counted per step and in total), and what
 * happened worth a line in a report. Documented in docs/sync.md.
 */
export const SYNC_CODES = [
  // inbound drops, in the order of the checks
  'unknown-sender',
  'removed-sender',
  'frame-refused',
  'duplicate-frame',
  'not-a-file',
  'wrong-recipient',
  'sender-mismatch',
  'sender-not-trusted',
  'cannot-open',
  'bad-packet',
  'ignored-message',
  'ask-rate-limited',
  'duplicate-ask',
  'stale-round',
  'duplicate-piece',
  'unknown-set',
  'set-not-allowed',
  'post-disabled',
  'post-refused',
  // rounds and answers
  'round-timeout',
  'round-overflow',
  'round-refused',
  'diverged',
  'stand-too-large',
  'answer-too-large',
  'seal-failed',
  // outbound
  'outbox-full',
  'outbox-expired',
  'drop-failed',
  'drop-refused',
  'recipient-not-trusted',
  // roster
  'no-relay-id',
  'relay-id-clash',
  // the step
  'self-removed',
  'collect-failed',
  'collect-interrupted',
] as const;

export type SyncCode = (typeof SYNC_CODES)[number];
