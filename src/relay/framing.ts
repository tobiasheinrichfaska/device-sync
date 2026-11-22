// Putting a payload larger than one relay message onto the relay: a versioned frame per message,
// cut into parts, put together again strictly and within limits. This is a CONVENTION of this
// package, not part of the relay protocol (the relay sees opaque bytes; docs/relay-protocol.md,
// "Message framing"). The payload is opaque too: the app seals it before and opens it after.
//
// Frame (UTF-8 JSON, members in this order, one spelling):
//   {"m":"<app>-frame:1","t":"part","id":"<16 hex>","i":<index>,"n":<count>,"d":"<base64url>"}
import { base64url } from '../core/encoding.ts';
import { hasDuplicateKeys } from '../core/json.ts';
import { decodeUtf8, hasMembers, isPlain, parseJson, readBytes } from '../core/secure.ts';
import { RELAY_DEVICE_ID } from './readers.ts';
import { RELAY_LIMITS } from './limits.ts';

export const FRAME_VERSION = 1;

export interface FramingLimits {
  /** Payload bytes in one frame (before base64url). */
  readonly partBytes: number;
  /** Most parts of one payload. */
  readonly maxParts: number;
  /** Most payload bytes of one transfer. */
  readonly maxPayloadBytes: number;
  /** Incomplete transfers kept per sender; a further one pushes out the oldest. */
  readonly maxTransfersPerSender: number;
  /** Senders with an incomplete transfer; a further sender is refused until one is done or expired. */
  readonly maxSenders: number;
  /** Payload bytes held for all incomplete transfers together. */
  readonly maxBufferedBytes: number;
  /** An incomplete transfer is dropped this long after its first part came. */
  readonly holdMs: number;
}

export const FRAMING_LIMITS: FramingLimits = {
  partBytes: 40_000,
  maxParts: 210,
  maxPayloadBytes: 8_388_608,
  maxTransfersPerSender: 4,
  maxSenders: 64,
  maxBufferedBytes: 16_777_216,
  holdMs: 120_000,
};

const APP_ID = /^[a-z][a-z0-9]{1,15}$/;
const TRANSFER_ID = /^[0-9a-f]{16}$/;
const utf8 = new TextEncoder();

/** The marker of the frames of an app: `<app>-frame:1`, or undefined for a bad app id. */
export function frameMark(appId: string): string | undefined {
  return typeof appId === 'string' && APP_ID.test(appId)
    ? `${appId}-frame:${FRAME_VERSION}`
    : undefined;
}

export interface Frame {
  readonly id: string;
  readonly index: number;
  readonly count: number;
  readonly data: Uint8Array;
}

const frameText = (
  mark: string,
  id: string,
  index: number,
  count: number,
  data: Uint8Array,
): string =>
  `{"m":"${mark}","t":"part","id":"${id}","i":${index},"n":${count},"d":"${base64url(data)}"}`;

export type SplitResult =
  | { readonly ok: true; readonly frames: readonly Uint8Array[] }
  | {
      readonly ok: false;
      readonly reason: 'bad-app' | 'bad-id' | 'empty' | 'too-large' | 'bad-limits';
    };

/** Cuts a payload into frames, each small enough for one relay message. `id` is 16 fresh lower-case hex digits. */
export function splitPayload(
  appId: string,
  payload: Uint8Array,
  id: string,
  limits: FramingLimits = FRAMING_LIMITS,
): SplitResult {
  const mark = frameMark(appId);
  if (mark === undefined) return { ok: false, reason: 'bad-app' };
  if (typeof id !== 'string' || !TRANSFER_ID.test(id)) return { ok: false, reason: 'bad-id' };
  if (!(payload instanceof Uint8Array) || payload.length === 0)
    return { ok: false, reason: 'empty' };
  if (payload.length > limits.maxPayloadBytes) return { ok: false, reason: 'too-large' };
  const count = Math.ceil(payload.length / limits.partBytes);
  if (!(limits.partBytes >= 1) || count > limits.maxParts)
    return { ok: false, reason: 'too-large' };
  const frames: Uint8Array[] = [];
  for (let i = 0; i < count; i += 1) {
    const part = payload.subarray(i * limits.partBytes, (i + 1) * limits.partBytes);
    const bytes = utf8.encode(frameText(mark, id, i, count, part));
    if (bytes.length > RELAY_LIMITS.maxContentBytes) return { ok: false, reason: 'bad-limits' };
    frames.push(bytes);
  }
  return { ok: true, frames };
}

/** A frame from message bytes, strictly (one spelling, bounded before parsing), else undefined. Never throws. */
export function readFrame(
  appId: string,
  bytes: unknown,
  limits: FramingLimits = FRAMING_LIMITS,
): Frame | undefined {
  const mark = frameMark(appId);
  if (mark === undefined || !(bytes instanceof Uint8Array)) return undefined;
  if (bytes.length === 0 || bytes.length > RELAY_LIMITS.maxContentBytes) return undefined;
  const text = decodeUtf8(bytes);
  if (text === undefined || !text.startsWith(`{"m":"${mark}","t":"part","id":"`)) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 't', 'id', 'i', 'n', 'd'])) return undefined;
  if (hasDuplicateKeys(text)) return undefined;
  const { m, t, id, i, n, d } = raw;
  if (m !== mark || t !== 'part' || typeof id !== 'string' || !TRANSFER_ID.test(id))
    return undefined;
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 1 || n > limits.maxParts)
    return undefined;
  if (typeof i !== 'number' || !Number.isInteger(i) || i < 0 || i >= n) return undefined;
  const data = readBytes(d, 1, limits.partBytes);
  if (!data) return undefined;
  // One spelling: the text must be exactly what `splitPayload` writes.
  if (text !== frameText(mark, id, i, n, data)) return undefined;
  return { id, index: i, count: n, data: Uint8Array.from(data) };
}

export type AssembleRefusal =
  | 'malformed'
  | 'bad-sender'
  | 'bad-time'
  | 'count-mismatch'
  | 'conflicting-duplicate'
  | 'too-large'
  | 'too-many-senders'
  | 'buffer-full';

export type AssembleResult =
  | {
      readonly kind: 'complete';
      readonly from: string;
      readonly id: string;
      readonly payload: Uint8Array;
    }
  | { readonly kind: 'pending' }
  | { readonly kind: 'duplicate' }
  | { readonly kind: 'refused'; readonly reason: AssembleRefusal };

interface Transfer {
  readonly count: number;
  readonly parts: Map<number, Uint8Array>;
  bytes: number;
  readonly startedMs: number;
  readonly order: number;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Puts the frames of each sender's transfers together. Parts may come in any order; an identical
 * repeat is ignored; a repeat with other bytes is refused (the first stays); a refusal never changes
 * the state. Only completion, expiry (`sweep`) and pushing out the oldest of a sender's transfers
 * remove anything. Time is a parameter; memory is bounded by `FramingLimits`; work per frame is
 * constant except when a transfer completes.
 */
export class FrameAssembler {
  private readonly senders = new Map<string, Map<string, Transfer>>();
  private held = 0;
  private counter = 0;

  constructor(
    private readonly appId: string,
    private readonly limits: FramingLimits = FRAMING_LIMITS,
  ) {}

  /** Payload bytes held for incomplete transfers. */
  get bufferedBytes(): number {
    return this.held;
  }

  /** Incomplete transfers held. */
  get transferCount(): number {
    let n = 0;
    for (const transfers of this.senders.values()) n += transfers.size;
    return n;
  }

  /** Drops the transfers whose first part came `holdMs` ago or longer; returns who and which. */
  sweep(nowMs: number): { readonly from: string; readonly id: string }[] {
    const gone: { from: string; id: string }[] = [];
    if (!Number.isFinite(nowMs)) return gone;
    for (const [from, transfers] of this.senders) {
      for (const [id, t] of transfers) {
        if (nowMs - t.startedMs >= this.limits.holdMs) {
          this.held -= t.bytes;
          transfers.delete(id);
          gone.push({ from, id });
        }
      }
      if (transfers.size === 0) this.senders.delete(from);
    }
    return gone;
  }

  /** Takes one frame that came from `from` (the device id the relay names) at time `nowMs`. */
  accept(from: string, frame: Uint8Array, nowMs: number): AssembleResult {
    if (typeof from !== 'string' || !RELAY_DEVICE_ID.test(from)) return refused('bad-sender');
    if (typeof nowMs !== 'number' || !Number.isFinite(nowMs)) return refused('bad-time');
    const f = readFrame(this.appId, frame, this.limits);
    if (!f) return refused('malformed');
    this.sweep(nowMs);
    const transfers = this.senders.get(from);
    const known = transfers?.get(f.id);
    if (known) {
      if (known.count !== f.count) return refused('count-mismatch');
      const have = known.parts.get(f.index);
      if (have)
        return sameBytes(have, f.data) ? { kind: 'duplicate' } : refused('conflicting-duplicate');
      if (known.bytes + f.data.length > this.limits.maxPayloadBytes) return refused('too-large');
      if (this.held + f.data.length > this.limits.maxBufferedBytes) return refused('buffer-full');
      known.parts.set(f.index, f.data);
      known.bytes += f.data.length;
      this.held += f.data.length;
      return known.parts.size === known.count
        ? this.finish(from, f.id, known)
        : { kind: 'pending' };
    }
    // A new transfer.
    if (!transfers && this.senders.size >= this.limits.maxSenders)
      return refused('too-many-senders');
    let victim: [string, Transfer] | undefined;
    if (transfers && transfers.size >= this.limits.maxTransfersPerSender) {
      for (const entry of transfers)
        if (!victim || entry[1].order < victim[1].order) victim = entry;
    }
    const freed = victim ? victim[1].bytes : 0;
    if (this.held - freed + f.data.length > this.limits.maxBufferedBytes)
      return refused('buffer-full');
    if (victim && transfers) {
      transfers.delete(victim[0]);
      this.held -= victim[1].bytes;
    }
    const t: Transfer = {
      count: f.count,
      parts: new Map([[f.index, f.data]]),
      bytes: f.data.length,
      startedMs: nowMs,
      order: (this.counter += 1),
    };
    this.held += f.data.length;
    const mine = transfers ?? new Map<string, Transfer>();
    mine.set(f.id, t);
    this.senders.set(from, mine);
    return t.count === 1 ? this.finish(from, f.id, t) : { kind: 'pending' };
  }

  private finish(from: string, id: string, t: Transfer): AssembleResult {
    const payload = new Uint8Array(t.bytes);
    let at = 0;
    for (let i = 0; i < t.count; i += 1) {
      const part = t.parts.get(i) as Uint8Array;
      payload.set(part, at);
      at += part.length;
    }
    const transfers = this.senders.get(from);
    transfers?.delete(id);
    if (transfers && transfers.size === 0) this.senders.delete(from);
    this.held -= t.bytes;
    return { kind: 'complete', from, id, payload };
  }
}

const refused = (reason: AssembleRefusal): AssembleResult => ({ kind: 'refused', reason });
