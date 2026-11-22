// Fountain-coded frames for animated QR codes. The payload is cut into K blocks; frame 0..K-1 carry the
// blocks as they are, every later frame the XOR of a pseudo-random half of them, chosen from the transfer
// id and the sequence number so the receiver recomputes the mix. Any K independent frames rebuild the
// payload (elimination over GF(2)); with random mixes about K + 2 frames suffice, whichever were missed.
// Everything is deterministic: the transfer id is a parameter, nothing here draws randomness or reads a clock.
// FountainFrame: version 1 | transfer id u32 | seq u32 | blocks u16 | length u32 | payload check u32 | block | frame check u32
// (all big endian). The check values are CRC-32 over a domain marker of the app, so they catch damage and
// frames of another app; they do not authenticate anything (see docs/transfer.md).
import { base64url, fromBase64url } from '../core/encoding.ts';
import { crc32, domainBytes } from './check.ts';
import { TRANSFER_LIMITS as L, fail, pass, type TransferResult } from './limits.ts';

export type FrameReason =
  | 'bad-app-id'
  | 'bad-payload'
  | 'bad-block-size'
  | 'too-large'
  | 'bad-transfer-id'
  | 'bad-seq'
  | 'too-short'
  | 'too-long'
  | 'bad-version'
  | 'bad-check'
  | 'bad-blocks'
  | 'bad-text'
  | 'too-many-frames';

export interface FountainFrame {
  readonly transferId: number;
  readonly seq: number;
  readonly blocks: number;
  readonly length: number;
  readonly payloadCheck: number;
  readonly data: Uint8Array;
}

export function blocksFor(length: number, blockBytes: number): number {
  return Math.max(1, Math.ceil(length / blockBytes));
}

const isU32 = (n: unknown): n is number =>
  typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= 0xffffffff;

/** Small seeded generator (mulberry32), 32 bits per call: the same mix on sender and receiver. */
function generator(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  };
}

/** The blocks frame `seq` mixes, as a bit set (bit i = block i); never empty. */
export function mixOf(transferId: number, seq: number, blocks: number): Uint32Array {
  const words = Math.ceil(blocks / 32);
  const mix = new Uint32Array(words);
  if (seq < blocks) {
    mix[seq >>> 5] = (1 << (seq & 31)) >>> 0;
    return mix;
  }
  const next = generator((transferId ^ Math.imul(seq + 1, 0x9e3779b1)) >>> 0);
  for (let w = 0; w < words; w++) mix[w] = next();
  const tail = blocks & 31;
  if (tail) mix[words - 1] = ((mix[words - 1] as number) & ((1 << tail) - 1)) >>> 0;
  if (mix.every((w) => w === 0)) {
    const b = seq % blocks;
    mix[b >>> 5] = (1 << (b & 31)) >>> 0;
  }
  return mix;
}

const bitSet = (mix: Uint32Array, i: number): boolean =>
  (((mix[i >>> 5] as number) >>> (i & 31)) & 1) === 1;

export interface FountainSenderOptions {
  readonly appId: string;
  readonly payload: Uint8Array;
  /** Any 32-bit number, fresh per transfer (the caller draws it). */
  readonly transferId: number;
  /** Data octets per frame, 1 to `blockBytesMax`. */
  readonly blockBytes: number;
}

export interface FountainSender {
  readonly blocks: number;
  /** Frames 0 .. K-1 carry the blocks themselves; a perfect scan needs exactly this many. */
  frame(seq: number): TransferResult<Uint8Array, FrameReason>;
  /** The frames in order 0, 1, 2 ... without end (until `seqMax`). */
  next(): TransferResult<Uint8Array, FrameReason>;
}

export function createFountainSender(
  o: FountainSenderOptions,
): TransferResult<FountainSender, FrameReason> {
  if (!o || typeof o !== 'object') return fail('bad-payload');
  const domainPayload = domainBytes(o.appId, 'qrdata');
  const domainFrame = domainBytes(o.appId, 'qr');
  if (!domainPayload || !domainFrame) return fail('bad-app-id');
  if (!(o.payload instanceof Uint8Array)) return fail('bad-payload');
  if (o.payload.length > L.payloadMax) return fail('too-large');
  if (!isU32(o.transferId)) return fail('bad-transfer-id');
  if (!Number.isInteger(o.blockBytes) || o.blockBytes < 1 || o.blockBytes > L.blockBytesMax)
    return fail('bad-block-size');
  const blocks = blocksFor(o.payload.length, o.blockBytes);
  if (blocks > L.blocksMax) return fail('too-large');
  const payload = o.payload.slice();
  const { transferId, blockBytes } = o;
  const payloadCheck = crc32([domainPayload, payload]);
  let cursor = 0;
  const frame = (seq: number): TransferResult<Uint8Array, FrameReason> => {
    if (!Number.isInteger(seq) || seq < 0 || seq > L.seqMax) return fail('bad-seq');
    const out = new Uint8Array(L.frameHeaderBytes + blockBytes + L.frameCheckBytes);
    const data = out.subarray(L.frameHeaderBytes, L.frameHeaderBytes + blockBytes);
    const mix = mixOf(transferId, seq, blocks);
    for (let i = 0; i < blocks; i++) {
      if (!bitSet(mix, i)) continue;
      const block = payload.subarray(i * blockBytes, (i + 1) * blockBytes);
      for (let j = 0; j < block.length; j++) data[j] = (data[j] as number) ^ (block[j] as number);
    }
    const view = new DataView(out.buffer);
    view.setUint8(0, L.frameVersion);
    view.setUint32(1, transferId);
    view.setUint32(5, seq);
    view.setUint16(9, blocks);
    view.setUint32(11, payload.length);
    view.setUint32(15, payloadCheck);
    const end = L.frameHeaderBytes + blockBytes;
    view.setUint32(end, crc32([domainFrame, out.subarray(0, end)]));
    return pass(out);
  };
  return pass({
    blocks,
    frame,
    next() {
      const r = frame(cursor);
      if (r.ok) cursor++;
      return r;
    },
  });
}

/** Strict reader of one frame. Anything else (another QR code, damage, another app) is a code. */
export function parseFrame(
  appId: string,
  bytes: unknown,
): TransferResult<FountainFrame, FrameReason> {
  const domain = domainBytes(appId, 'qr');
  if (!domain) return fail('bad-app-id');
  if (!(bytes instanceof Uint8Array)) return fail('too-short');
  if (bytes.length > L.frameBytesMax) return fail('too-long');
  if (bytes.length < L.frameHeaderBytes + 1 + L.frameCheckBytes) return fail('too-short');
  if (bytes[0] !== L.frameVersion) return fail('bad-version');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = bytes.length - L.frameCheckBytes;
  if (view.getUint32(end) !== crc32([domain, bytes.subarray(0, end)])) return fail('bad-check');
  const blocks = view.getUint16(9);
  const length = view.getUint32(11);
  const seq = view.getUint32(5);
  const blockBytes = end - L.frameHeaderBytes;
  if (
    blocks < 1 ||
    blocks > L.blocksMax ||
    length > L.payloadMax ||
    blocksFor(length, blockBytes) !== blocks ||
    seq > L.seqMax
  )
    return fail('bad-blocks');
  return pass({
    transferId: view.getUint32(1),
    seq,
    blocks,
    length,
    payloadCheck: view.getUint32(15),
    data: bytes.slice(L.frameHeaderBytes, end),
  });
}

/** The frame as base64url text (for a QR code in text mode); at most `frameCharsMax` characters. */
export function frameToText(frame: Uint8Array): string {
  return base64url(frame);
}

/** Strict inverse of `frameToText`: only the canonical spelling, bounded. */
export function frameFromText(text: unknown): TransferResult<Uint8Array, FrameReason> {
  if (typeof text !== 'string' || text.length === 0 || text.length > L.frameCharsMax)
    return fail('bad-text');
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) return fail('bad-text');
  let bytes: Uint8Array;
  try {
    bytes = fromBase64url(text);
  } catch {
    return fail('bad-text');
  }
  return base64url(bytes) === text ? pass(bytes) : fail('bad-text');
}

export type AddOutcome =
  'new' | 'redundant' | 'repeat' | 'other-transfer' | 'done' | 'check-failed';

export interface FountainStatus {
  readonly transferId: number | undefined;
  readonly blocks: number;
  readonly length: number;
  readonly rank: number;
  readonly complete: boolean;
  /** Different frames that brought nothing new. */
  readonly redundant: number;
  /** Frames read again (a camera reads one shown code several times). */
  readonly repeats: number;
  /** Times a finished payload failed its check and everything was dropped. */
  readonly checkFailures: number;
}

interface Row {
  readonly mix: Uint32Array;
  readonly data: Uint32Array;
}

export interface FountainReceiverOptions {
  readonly appId: string;
  /** Start over when a frame of another transfer arrives (default: stay with the first, ignore the others). */
  readonly switchOnOther?: boolean;
  /** Frames looked at per transfer before more are refused (default and largest `framesMax`). */
  readonly framesMax?: number;
}

export class FountainReceiver {
  private readonly appId: string;
  private readonly domainPayload: Uint8Array;
  private readonly switchOnOther: boolean;
  private transferId: number | undefined;
  private blocks = 0;
  private length = 0;
  private payloadCheck = 0;
  private blockBytes = 0;
  private rank = 0;
  private redundant = 0;
  private repeats = 0;
  private checkFailures = 0;
  private looked = 0;
  private pivots: (Row | undefined)[] = [];
  private seen = new Set<number>();
  private result: Uint8Array | undefined;

  constructor(
    appId: string,
    domainPayload: Uint8Array,
    switchOnOther: boolean,
    private readonly framesMax: number,
  ) {
    this.appId = appId;
    this.domainPayload = domainPayload;
    this.switchOnOther = switchOnOther;
  }

  status(): FountainStatus {
    return {
      transferId: this.transferId,
      blocks: this.blocks,
      length: this.length,
      rank: this.rank,
      complete: this.result !== undefined,
      redundant: this.redundant,
      repeats: this.repeats,
      checkFailures: this.checkFailures,
    };
  }

  /** The payload once complete and its check value held. */
  payload(): TransferResult<Uint8Array, 'incomplete'> {
    return this.result ? pass(this.result.slice()) : fail('incomplete');
  }

  /** Forgets everything (the app starts a new scan). */
  reset(): void {
    this.transferId = undefined;
    this.blocks = this.length = this.payloadCheck = this.blockBytes = 0;
    this.clear();
    this.checkFailures = 0;
  }

  private clear(): void {
    this.rank = this.redundant = this.repeats = this.looked = 0;
    this.pivots = new Array<Row | undefined>(this.blocks);
    this.seen = new Set();
    this.result = undefined;
  }

  /** Takes one frame (bytes, or the base64url text of it). */
  add(input: Uint8Array | string): TransferResult<AddOutcome, FrameReason> {
    let bytes: Uint8Array;
    if (typeof input === 'string') {
      const t = frameFromText(input);
      if (!t.ok) return t;
      bytes = t.value;
    } else bytes = input;
    const parsed = parseFrame(this.appId, bytes);
    if (!parsed.ok) return parsed;
    const f = parsed.value;
    const same =
      f.transferId === this.transferId &&
      f.blocks === this.blocks &&
      f.length === this.length &&
      f.payloadCheck === this.payloadCheck &&
      f.data.length === this.blockBytes;
    if (!same) {
      if (this.transferId !== undefined && !this.switchOnOther) return pass('other-transfer');
      this.transferId = f.transferId;
      this.blocks = f.blocks;
      this.length = f.length;
      this.payloadCheck = f.payloadCheck;
      this.blockBytes = f.data.length;
      this.clear();
      this.checkFailures = 0;
    }
    if (this.seen.has(f.seq)) {
      this.repeats++;
      return pass('repeat');
    }
    if (this.seen.size < L.seenMax) this.seen.add(f.seq);
    if (this.result) {
      this.redundant++;
      return pass('redundant');
    }
    if (++this.looked > this.framesMax) return fail('too-many-frames');
    const mix = mixOf(f.transferId, f.seq, f.blocks);
    const words = new Uint32Array(Math.ceil(this.blockBytes / 4));
    new Uint8Array(words.buffer).set(f.data);
    if (!this.insert(mix, words)) {
      this.redundant++;
      return pass('redundant');
    }
    this.rank++;
    if (this.rank < this.blocks) return pass('new');
    return pass(this.finish());
  }

  /** Reduces a row against the pivots; stores it if it is independent. */
  private insert(mix: Uint32Array, data: Uint32Array): boolean {
    let w = 0;
    for (;;) {
      while (w < mix.length && mix[w] === 0) w++;
      if (w === mix.length) return false;
      const word = mix[w] as number;
      const lead = w * 32 + (31 - Math.clz32(word & -word));
      const pivot = this.pivots[lead];
      if (!pivot) {
        this.pivots[lead] = { mix, data };
        return true;
      }
      for (let i = w; i < mix.length; i++) mix[i] = (mix[i] as number) ^ (pivot.mix[i] as number);
      for (let i = 0; i < data.length; i++)
        data[i] = (data[i] as number) ^ (pivot.data[i] as number);
    }
  }

  private finish(): AddOutcome {
    const K = this.blocks;
    // Pivot c has bits only at columns >= c; clear the later columns, last pivot first.
    for (let c = K - 1; c >= 0; c--) {
      const row = this.pivots[c] as Row;
      for (let d = c + 1; d < K; d++) {
        if (!bitSet(row.mix, d)) continue;
        const later = this.pivots[d] as Row;
        for (let i = 0; i < row.data.length; i++)
          row.data[i] = (row.data[i] as number) ^ (later.data[i] as number);
      }
    }
    const all = new Uint8Array(K * this.blockBytes);
    for (let c = 0; c < K; c++)
      all.set(
        new Uint8Array((this.pivots[c] as Row).data.buffer, 0, this.blockBytes),
        c * this.blockBytes,
      );
    const payload = all.slice(0, this.length);
    // The padding after the payload is zero on an honest sender; anything else is a tampered frame.
    let padZero = true;
    for (let i = this.length; i < all.length; i++) if (all[i] !== 0) padZero = false;
    if (padZero && crc32([this.domainPayload, payload]) === this.payloadCheck) {
      this.result = payload;
      return 'done';
    }
    // Drop everything and collect again: one bad frame must not stop the transfer for good.
    const failures = this.checkFailures + 1;
    this.clear();
    this.checkFailures = failures;
    return 'check-failed';
  }
}

export function createFountainReceiver(
  o: FountainReceiverOptions,
): TransferResult<FountainReceiver, 'bad-app-id' | 'bad-config'> {
  const d = domainBytes(o?.appId, 'qrdata');
  if (!d) return fail('bad-app-id');
  const max = o.framesMax ?? L.framesMax;
  if (!Number.isInteger(max) || max < 1 || max > L.framesMax) return fail('bad-config');
  return pass(new FountainReceiver(o.appId, d, o.switchOnOther === true, max));
}
