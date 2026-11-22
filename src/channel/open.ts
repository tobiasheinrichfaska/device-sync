// Opening a channel: the envelopes a device holds (its own mailbox) are opened with its keys, the
// author is checked against the trust layer and the app's role rule, and every change is judged by its
// signature and the app's rights before it is merged. One bad envelope is dropped and named; the others
// still count. Nothing here decides which role may write which channel: that is the `mayWrite` hook.
import { openEnvelope, type Envelope } from '../core/index.ts';
import {
  emptyReplica,
  merge,
  readChanges,
  seen,
  type JudgeOptions,
  type KeySource,
  type ParseOptions,
  type Replica,
  type VersionVector,
} from '../log/index.ts';
import { readChannelBody } from './body.ts';

/** Why an envelope was not taken (`rejected`: dropped for good, `waiting`: try again later). */
export type ChannelCode =
  | 'unknown-author'
  | 'bad-signature'
  | 'damaged'
  | 'key-mismatch'
  | 'bad-point'
  | 'not-an-envelope'
  | 'author-not-allowed'
  | 'bad-body'
  | 'bad-change'
  | 'pending'
  | 'held';

export interface ChannelEntry {
  readonly id: string;
  /** The envelope's day (for the receipt record). */
  readonly day: string;
  readonly channel: string;
  /** The device whose signature opened it. */
  readonly from: string;
  /** The author's stand of the channel (what it held when it sealed this). */
  readonly stand: VersionVector;
  /** Changes of this envelope that were new and merged. */
  readonly applied: number;
}

export interface ChannelProblem {
  readonly id: string;
  readonly code: ChannelCode;
  /** With `bad-change`: the log's reason of the first refused change. */
  readonly detail?: string;
}

export interface OpenChannelResult {
  /** The channels' replicas: the given ones, changed ones replaced, a channel that was new added. */
  readonly replicas: Readonly<Record<string, Replica>>;
  /** Envelopes taken in whole: write them into the receipt record (`writeReceiptRecord`). */
  readonly taken: readonly ChannelEntry[];
  /** Envelopes dropped for good, with the code. The others are not affected. */
  readonly rejected: readonly ChannelProblem[];
  /** Envelopes that cannot be judged yet (an author the device list does not know yet, a gap): keep them, try again. */
  readonly waiting: readonly ChannelProblem[];
  /** Envelopes that are not for this device, already taken, or of a channel it does not take. */
  readonly skipped: number;
  /** Changes merged. */
  readonly applied: number;
}

export interface OpenChannelParams {
  readonly appId: string;
  /** This device: its id and the agreement pairs it opens with, tried in order (an archive identity first, then the device's own). */
  readonly own: { readonly device: string; readonly agreements: readonly CryptoKeyPair[] };
  readonly envelopes: readonly (Envelope | string)[];
  /** The replicas held per channel; a channel not in it starts empty (under this device's id). */
  readonly replicas?: Readonly<Record<string, Replica>>;
  /** The channels this device takes (default: any); an envelope of another counts as skipped. */
  readonly channels?: ReadonlySet<string> | ((channel: string) => boolean);
  /** Envelope ids taken before: skipped without opening. */
  readonly already?: ReadonlySet<string>;
  /**
   * The signing key (a point) of a device the trust layer knows and checks, else undefined (the author
   * is then `unknown-author`, and the envelope waits). From the trust layer: `trust.checkableById`.
   */
  readonly authorKey: (device: string) => string | undefined | Promise<string | undefined>;
  /** The key source for the changes' signatures (the trust layer's `deviceKeySource`, or `keysOfTrust`). */
  readonly keys: KeySource;
  /**
   * The role rule: may this device write into this channel at all? Asked for the envelope's author
   * (`author-not-allowed`) and for the author of every change. Nothing is decided here.
   */
  readonly mayWrite: (device: string, channel: string) => boolean;
  /** Further rights per channel (the log's hooks); `mayWrite` above is always added. */
  readonly judge?: (
    channel: string,
  ) => Pick<JudgeOptions, 'allowFinalDelete' | 'quota' | 'special' | 'fieldRules' | 'mayWrite'>;
  readonly log?: ParseOptions;
}

/**
 * Takes the envelopes into the channels' replicas. Per envelope, in this order: not already taken, opens
 * with one of this device's keys (else it is not for it: skipped), author known (`unknown-author`:
 * waits), channel wanted (skipped), author may write the channel, envelope signature (checked by the
 * envelope layer), body read strictly, every change judged by signature and rights (one false and the
 * envelope is dropped as a whole: `bad-change`), merged. An envelope whose changes cannot all be taken
 * yet (an author not checkable, a gap) waits and is not in `taken`: no receipt until it is. Never throws
 * on foreign input; a hook that throws counts as "no".
 */
export async function openChannel(params: OpenChannelParams): Promise<OpenChannelResult> {
  const { appId, own } = params;
  const replicas: Record<string, Replica> = { ...params.replicas };
  const taken: ChannelEntry[] = [];
  const rejected: ChannelProblem[] = [];
  const waiting: ChannelProblem[] = [];
  let skipped = 0;
  let appliedTotal = 0;
  const wanted = (channel: string): boolean => {
    const c = params.channels;
    return c === undefined || (typeof c === 'function' ? c(channel) : c.has(channel));
  };
  const may = (device: string, channel: string): boolean => {
    try {
      return params.mayWrite(device, channel) === true;
    } catch {
      return false;
    }
  };
  for (const envelope of params.envelopes) {
    const id = typeof envelope === 'string' ? undefined : envelope.id;
    if (id !== undefined && params.already?.has(id)) {
      skipped += 1;
      continue;
    }
    let opened: Awaited<ReturnType<typeof openEnvelope>> | undefined;
    for (const agreement of own.agreements) {
      opened = await openEnvelope({
        appId,
        own: { agreement },
        envelope,
        authorKey: async (from) => {
          try {
            return await params.authorKey(from);
          } catch {
            return undefined;
          }
        },
      });
      // not for this key: try the next one; any other outcome is final
      if (opened.ok || opened.reason !== 'not-for-me') break;
    }
    if (!opened || (!opened.ok && opened.reason === 'not-for-me')) {
      skipped += 1;
      continue;
    }
    const name = id ?? (opened.ok ? opened.id : '');
    if (!opened.ok) {
      if (opened.reason === 'unknown-author') {
        waiting.push({ id: name, code: 'unknown-author' });
      } else if (opened.reason === 'bad-own') {
        skipped += 1;
      } else {
        const code = opened.reason as ChannelCode;
        rejected.push({ id: name, code });
      }
      continue;
    }
    if (params.already?.has(opened.id)) {
      skipped += 1;
      continue;
    }
    const channel = opened.channel;
    if (!wanted(channel)) {
      skipped += 1;
      continue;
    }
    if (!may(opened.from, channel)) {
      rejected.push({ id: opened.id, code: 'author-not-allowed' });
      continue;
    }
    const body = readChannelBody(opened.body, params.log);
    if (!body) {
      rejected.push({ id: opened.id, code: 'bad-body' });
      continue;
    }
    const replica = replicas[channel] ?? emptyReplica(own.device);
    const news = body.changes.filter((c) => c.seq > seen(replica.vector, c.device));
    const extra = params.judge?.(channel);
    const judged = await readChanges(replica, news, {
      appId,
      dataSet: channel,
      keys: params.keys,
      ownDevice: own.device,
      ...extra,
      mayWrite: (author, change, state) =>
        may(author, channel) && (extra?.mayWrite ? extra.mayWrite(author, change, state) : true),
    });
    if (judged.rejected > 0) {
      const first = judged.rejections[0];
      rejected.push({
        id: opened.id,
        code: 'bad-change',
        ...(first
          ? { detail: first.detail ? `${first.reason}:${first.detail}` : first.reason }
          : {}),
      });
      continue;
    }
    const merged = merge(replica, judged.accepted);
    if (merged.applied > 0) replicas[channel] = merged.replica;
    appliedTotal += merged.applied;
    if (judged.pending.length > 0 || merged.held.length > 0) {
      waiting.push({ id: opened.id, code: judged.pending.length > 0 ? 'pending' : 'held' });
      continue;
    }
    taken.push({
      id: opened.id,
      day: opened.day,
      channel,
      from: opened.from,
      stand: body.stand,
      applied: merged.applied,
    });
  }
  return { replicas, taken, rejected, waiting, skipped, applied: appliedTotal };
}
