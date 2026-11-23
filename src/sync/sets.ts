// The registry of data sets and the mailbox the driver carries besides the main set. The main set is the
// one the trust layer reads the device list from (`SyncConfig.trust.dataSet`); every other set is
// registered here by name, with the app's rules for it. A set name is also the name of a channel of
// the channel glue (`src/channel`): one name, one replica, one signing context.
import type { Envelope } from '../core/index.ts';
import type { ApprovalOptions, JudgeOptions, Replica } from '../log/index.ts';
import type { Mailbox, PostLimits, Receipt } from '../post/index.ts';
import type { Trust } from '../trust/index.ts';
import type { Peer } from './roster.ts';

/** The app's rules for one registered data set (all optional). */
export interface SetConfig {
  /** The log's hooks for this set (who may write, final deletion, quota, special cases, field rules). */
  readonly judge?: Pick<
    JudgeOptions,
    'mayWrite' | 'allowFinalDelete' | 'quota' | 'special' | 'fieldRules'
  >;
  readonly approval?: ApprovalOptions;
  /**
   * Which trusted peers exchange this set: asked for every ask we make, every ask we answer and every
   * answer we take (default: every peer). A set that only some roles may read (a person's times) is
   * answered and asked only where this says yes; the package never sends a set to a peer the hook
   * refuses. A hook that throws counts as "no".
   */
  readonly mayExchange?: (peer: Peer, trust: Trust) => boolean;
}

/** Envelope traffic: the mailbox travels with the sync (docs/sync.md, "Envelopes and the mailbox"). */
export interface PostConfig {
  readonly limits?: Partial<PostLimits>;
  /** Which trusted peers this device carries envelopes with (default: every peer). */
  readonly mayCarry?: (peer: Peer, trust: Trust) => boolean;
  /**
   * The receipts the app's data holds right now, as `Receipt[]` (see `receiptsOf`); read strictly each
   * step. Without it nothing is dropped by receipt.
   */
  readonly receipts?: (sets: ReadonlyMap<string, Replica>) => unknown;
  /** Who may acknowledge (default: nobody, so receipts are ignored): the app's decision. */
  readonly mayAcknowledge?: (by: string, trust: Trust) => boolean;
}

/** What the caller holds besides the main replica; both are given back changed. */
export interface SyncHeld {
  /** The replicas of the registered sets, by name; a registered set not in it starts empty. */
  readonly sets?: Readonly<Record<string, Replica>>;
  readonly mailbox?: Mailbox;
}

export type { Envelope, Receipt };
