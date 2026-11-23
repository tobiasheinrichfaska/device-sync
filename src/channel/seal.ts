// Sealing a channel: the changes of one data set (the channel) that its readers lack, cut into
// envelopes that fit the envelope limit, each sealed for all readers at once and signed by the author.
// The app decides who the readers are (it passes their agreement keys as the trust layer verified
// them); this layer decides nothing about roles.
import { resolveEnvelopeLimits, sealEnvelope, type Envelope } from '../core/index.ts';
import type { EnvelopeLimits } from '../core/index.ts';
import {
  insertSignatures,
  missingFor,
  signOwnChanges,
  type Change,
  type ParseOptions,
  type Replica,
  type VersionVector,
} from '../log/index.ts';
import { FAN_GROUP } from '../core/envelope.ts';
import { writeChannelBody } from './body.ts';

export type SealChannelRefusal =
  | 'no-reader'
  | 'too-many-readers'
  | 'bad-reader'
  | 'bad-author'
  | 'bad-channel'
  | 'bad-day'
  | 'bad-input'
  | 'wrong-device'
  | 'change-too-large'
  | 'crypto-failure';

export type SealChannelResult =
  | {
      readonly ok: true;
      /** The replica with this device's own changes signed (keep it: the next call signs only new ones). */
      readonly replica: Replica;
      /** Sealed envelopes, in order (empty when the readers lack nothing). */
      readonly envelopes: readonly Envelope[];
      /** Changes put into them. */
      readonly changes: number;
    }
  | {
      readonly ok: false;
      readonly reason: SealChannelRefusal;
      /** The replica as it is (signed as far as it got), so the caller can keep it. */
      readonly replica: Replica;
    };

export interface SealChannelParams {
  readonly appId: string;
  /** The author: this device's id and its signing private key. */
  readonly author: { readonly device: string; readonly signing: CryptoKey };
  /** The channel; it is also the data set the changes are signed for. */
  readonly channel: string;
  /** This author's replica of the channel (its own changes are signed here). */
  readonly replica: Replica;
  /** Agreement keys (points) of the devices that read the channel: the app's decision, from the trust layer. */
  readonly readers: readonly string[];
  /** What the readers are known to hold (a remembered stand); default: nothing, so everything is sent. */
  readonly known?: VersionVector;
  /** Only the author's own changes (an archive that forwards nothing it received). */
  readonly onlyOwn?: boolean;
  /** Day of sealing, `YYYY-MM-DD`. */
  readonly day: string;
  readonly random: (n: number) => Uint8Array;
  readonly limits?: Partial<EnvelopeLimits>;
  readonly log?: ParseOptions;
}

/**
 * Signs the author's own unsigned changes of the channel, takes what the readers lack and seals it into
 * as many envelopes as the envelope limit needs (a part that does not fit is halved again; a single
 * change that does not fit alone is `change-too-large`). Nothing to send: `{ ok: true, envelopes: [] }`.
 * Something to send and no reader: `no-reader` (said, not silent: nobody may read it yet).
 */
export async function sealChannel(params: SealChannelParams): Promise<SealChannelResult> {
  const { appId, author, channel, readers, random } = params;
  const lim = resolveEnvelopeLimits(params.limits);
  const refuse = (reason: SealChannelRefusal, replica: Replica): SealChannelResult => ({
    ok: false,
    reason,
    replica,
  });
  let replica = params.replica;
  if (replica.device !== author.device) return refuse('wrong-device', replica);
  if (typeof channel !== 'string' || channel.length === 0) return refuse('bad-channel', replica);
  if (!Array.isArray(readers)) return refuse('bad-input', replica);
  replica = insertSignatures(
    replica,
    await signOwnChanges(appId, author.signing, replica, channel),
  );
  // Signed changes only, and each device's run stops at its first unsigned one (the numbering stays gapless).
  const stopped = new Set<string>();
  const lacking: Change[] = [];
  for (const change of missingFor(replica, params.known ?? {})) {
    if (stopped.has(change.device)) continue;
    if (change.sig === undefined) {
      stopped.add(change.device);
      continue;
    }
    if (!params.onlyOwn || change.device === author.device) lacking.push(change);
  }
  if (lacking.length === 0) return { ok: true, replica, envelopes: [], changes: 0 };
  const distinct = [...new Set(readers)];
  if (distinct.length === 0) return refuse('no-reader', replica);
  if (distinct.length > lim.maxFans) return refuse('too-many-readers', replica);
  const fan = Math.ceil(distinct.length / FAN_GROUP) * FAN_GROUP;
  // What fits, first guess: the envelope text minus the fan (64 characters a slot) and the head.
  const budget = Math.max(200, Math.floor(((lim.maxEnvelopeBytes - 900 - fan * 64) * 3) / 4) - 300);
  const envelopes: Envelope[] = [];
  const stand = replica.vector;
  const sealPart = async (part: readonly Change[]): Promise<SealChannelRefusal | undefined> => {
    const sealed = await sealEnvelope({
      appId,
      author: { device: author.device, signing: author.signing },
      recipients: distinct,
      channel,
      day: params.day,
      body: writeChannelBody(stand, part),
      random,
      limits: lim,
    });
    if (sealed.ok) {
      envelopes.push(sealed.envelope);
      return undefined;
    }
    if (sealed.reason === 'too-large') {
      if (part.length === 1) return 'change-too-large';
      const half = Math.ceil(part.length / 2);
      return (await sealPart(part.slice(0, half))) ?? (await sealPart(part.slice(half)));
    }
    switch (sealed.reason) {
      case 'bad-author':
      case 'bad-channel':
      case 'bad-day':
      case 'bad-input':
        return sealed.reason;
      case 'bad-recipient':
        return 'bad-reader';
      case 'no-recipients':
        return 'no-reader';
      case 'too-many-recipients':
        return 'too-many-readers';
      default:
        return 'crypto-failure';
    }
  };
  let part: Change[] = [];
  let size = 0;
  const flush = async (): Promise<SealChannelRefusal | undefined> => {
    if (part.length === 0) return undefined;
    const reason = await sealPart(part);
    part = [];
    size = 0;
    return reason;
  };
  for (const change of lacking) {
    const n = JSON.stringify(change).length + 1;
    if (part.length > 0 && size + n > budget) {
      const reason = await flush();
      if (reason) return refuse(reason, replica);
    }
    part.push(change);
    size += n;
  }
  const reason = await flush();
  if (reason) return refuse(reason, replica);
  return { ok: true, replica, envelopes, changes: lacking.length };
}
