// Every limit of the mailbox and its exchange in one place. Documented in docs/wire-format.md,
// "Mailbox". The envelope limits (`maxEnvelopeBytes`, `maxFans`) are part of it, so one object
// configures everything a carrier reads.
import { ENVELOPE_LIMITS, resolveEnvelopeLimits, type EnvelopeLimits } from '../core/envelope.ts';
import { overrideNumbers } from '../core/secure.ts';

export interface PostLimits extends EnvelopeLimits {
  /** An envelope is carried for this many days after its day (a day this old or older is dropped). */
  readonly postDays: number;
  /** Most envelopes in one mailbox (newest days stay). */
  readonly maxEnvelopes: number;
  /** Most wire characters in one mailbox (newest days stay; the first envelope that does not fit ends it). */
  readonly maxChars: number;
  /** Most NEW envelopes per day from one other device (the rest is refused and counted). */
  readonly maxPerSupplier: number;
  /** Most different other devices counted per day; a further device delivers nothing that day. */
  readonly maxSuppliers: number;
  /** Most remembered acknowledged ids. */
  readonly maxAcknowledged: number;
  /** Most receipts one call takes, and most ids in one receipt. */
  readonly maxReceipts: number;
  readonly maxReceiptIds: number;
  /** Most ids or envelopes in one message, most days in a `days` message. */
  readonly maxPerMessage: number;
  readonly maxDays: number;
  /** A piece (one message) is cut at this many characters; one envelope may exceed it alone. */
  readonly pieceChars: number;
  /** Most ids the other side may announce in one session (more ends the session). */
  readonly maxTheirIds: number;
}

export const POST_LIMITS: PostLimits = Object.freeze({
  ...ENVELOPE_LIMITS,
  postDays: 30,
  maxEnvelopes: 2000,
  maxChars: 8_000_000,
  maxPerSupplier: 400,
  maxSuppliers: 256,
  maxAcknowledged: 4000,
  maxReceipts: 256,
  maxReceiptIds: 400,
  maxPerMessage: 400,
  maxDays: 64,
  pieceChars: 12_000,
  maxTheirIds: 4000,
});

/** Envelopes with a day this far ahead of today are still taken (clocks differ a little). */
export const FUTURE_DAYS = 2;

/** The defaults with a partial override on top (own, safe, non-negative integers only). */
export function resolvePostLimits(override?: Partial<PostLimits>): PostLimits {
  const out = overrideNumbers({ ...POST_LIMITS }, override);
  return { ...out, ...resolveEnvelopeLimits(out) };
}

/** The longest message text a reader takes (before it parses anything). */
export const maxMessageChars = (lim: PostLimits): number =>
  Math.max(lim.pieceChars, lim.maxEnvelopeBytes) + 512;
