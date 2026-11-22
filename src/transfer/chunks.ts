// Messages over a data channel: cut into chunks of at most `chunkBytes` (what every browser passes unsplit)
// and put together again, with limits. The channel is ordered, so the reader takes the chunks in order and
// refuses anything else.
// Chunk: version 1 | message id u32 | index u16 | count u16 | data. All chunks but the last are full.
import { TRANSFER_LIMITS as L, fail, pass, type TransferResult } from './limits.ts';

export type ChunkReason =
  'bad-message' | 'bad-id' | 'too-large' | 'bad-chunk' | 'out-of-order' | 'mismatch';

const DATA = L.chunkBytes - L.chunkHeaderBytes;

export function chunkMessage(
  messageId: number,
  message: Uint8Array,
): TransferResult<Uint8Array<ArrayBuffer>[], ChunkReason> {
  if (!Number.isInteger(messageId) || messageId < 0 || messageId > 0xffffffff)
    return fail('bad-id');
  if (!(message instanceof Uint8Array)) return fail('bad-message');
  if (message.length > L.messageBytesMax) return fail('too-large');
  const count = Math.max(1, Math.ceil(message.length / DATA));
  const out: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < count; i++) {
    const part = message.subarray(i * DATA, (i + 1) * DATA);
    const chunk = new Uint8Array(L.chunkHeaderBytes + part.length);
    const view = new DataView(chunk.buffer);
    view.setUint8(0, 1);
    view.setUint32(1, messageId);
    view.setUint16(5, i);
    view.setUint16(7, count);
    chunk.set(part, L.chunkHeaderBytes);
    out.push(chunk);
  }
  return pass(out);
}

export interface Chunk {
  readonly id: number;
  readonly index: number;
  readonly count: number;
  readonly data: Uint8Array;
}

/** Strict reader of one chunk. */
export function readChunk(bytes: unknown): TransferResult<Chunk, 'bad-chunk'> {
  if (!(bytes instanceof Uint8Array)) return fail('bad-chunk');
  if (bytes.length < L.chunkHeaderBytes || bytes.length > L.chunkBytes || bytes[0] !== 1)
    return fail('bad-chunk');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const index = view.getUint16(5);
  const count = view.getUint16(7);
  const dataLength = bytes.length - L.chunkHeaderBytes;
  const maxCount = Math.max(1, Math.ceil(L.messageBytesMax / DATA));
  if (count < 1 || count > maxCount || index >= count) return fail('bad-chunk');
  if (index < count - 1 ? dataLength !== DATA : dataLength > DATA) return fail('bad-chunk');
  if (count > 1 && index === count - 1 && dataLength === 0) return fail('bad-chunk');
  return pass({
    id: view.getUint32(1),
    index,
    count,
    data: bytes.subarray(L.chunkHeaderBytes),
  });
}

/** Puts chunks together. A chunk 0 while a message is half done drops the half (the sender gave up). */
export class ChunkAssembler {
  private id = 0;
  private count = 0;
  private next = 0;
  private parts: Uint8Array[] = [];
  private total = 0;

  /** Returns the message when its last chunk arrives, `undefined` while more are due. */
  push(bytes: unknown): TransferResult<Uint8Array | undefined, ChunkReason> {
    const r = readChunk(bytes);
    if (!r.ok) {
      this.reset();
      return r;
    }
    const c = r.value;
    if (c.index === 0) {
      this.reset();
      this.id = c.id;
      this.count = c.count;
    } else if (this.count === 0) {
      return fail('out-of-order');
    } else if (c.id !== this.id || c.count !== this.count) {
      this.reset();
      return fail('mismatch');
    } else if (c.index !== this.next) {
      this.reset();
      return fail('out-of-order');
    }
    this.total += c.data.length;
    if (this.total > L.messageBytesMax) {
      this.reset();
      return fail('too-large');
    }
    this.parts.push(c.data.slice());
    this.next = c.index + 1;
    if (this.next < this.count) return pass(undefined);
    const out = new Uint8Array(this.total);
    let at = 0;
    for (const p of this.parts) {
      out.set(p, at);
      at += p.length;
    }
    this.reset();
    return pass(out);
  }

  /** Whether a message is half received. */
  pending(): boolean {
    return this.count !== 0;
  }

  reset(): void {
    this.id = this.count = this.next = this.total = 0;
    this.parts = [];
  }
}
