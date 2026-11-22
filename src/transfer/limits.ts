/** Numbers of the transfer layer. */
export const TRANSFER_LIMITS = {
  /** Fountain frame: version octet. */
  frameVersion: 1,
  /** Fountain frame header: version 1, transfer id 4, sequence 4, blocks 2, length 4, payload check 4. */
  frameHeaderBytes: 19,
  /** Fountain frame trailer: the check value over everything before it. */
  frameCheckBytes: 4,
  /** Largest block (data octets of one frame); fits a QR code at the lowest correction level. */
  blockBytesMax: 2_048,
  /** Most blocks of one payload. */
  blocksMax: 1_024,
  /** Largest payload of one transfer. */
  payloadMax: 1_048_576,
  /** Highest frame sequence number; the sender stops here. */
  seqMax: 1_000_000,
  /** Largest frame in octets (header, one block, trailer). */
  frameBytesMax: 2_071,
  /** Largest frame as base64url text. */
  frameCharsMax: 2_762,
  /** Frames one receiver looks at per transfer before it refuses more. */
  framesMax: 100_000,
  /** Sequence numbers one receiver remembers (to tell a repeat from a useless frame). */
  seenMax: 16_384,
  /** Tone message: most payload octets. */
  toneMessageMax: 16,
  /** Tone message: octets of check value after the payload. */
  toneCheckBytes: 2,
  /** Tone listener: most analysis frames kept. */
  toneSymbolsMax: 4_096,
  /** Direct connection text: most characters of one offer or answer text. */
  textCharsMax: 11_000,
  /** Direct connection: most characters of one description (SDP). */
  sdpCharsMax: 8_192,
  /** Direct connection: most lines of a description. */
  sdpLinesMax: 200,
  /** Direct connection: longest line of a description. */
  sdpLineCharsMax: 512,
  /** Data channel message: version 1, message id 4, index 2, count 2. */
  chunkHeaderBytes: 9,
  /** Largest data channel message the browsers all pass unsplit. */
  chunkBytes: 16_384,
  /** Largest message sent over the data channel (before chunking). */
  messageBytesMax: 4_194_304,
  /** Messages (not yet read) a connection buffers. */
  inboxMax: 256,
  /** Bytes of those messages together (the count alone would allow 256 messages of 4 MiB). */
  inboxBytesMax: 16_777_216,
  /** Entries of `getStats()` the path reader looks at. */
  statsMax: 500,
  /** Send side: wait for the buffer to drain above this many buffered octets. */
  highWaterBytes: 1_048_576,
  /** Send side: low-water mark that wakes a waiting sender. */
  lowWaterBytes: 262_144,
} as const;

export type TransferLimits = typeof TRANSFER_LIMITS;

/** Result of a transfer helper: a value or a code (never an exception for bad input). */
export type TransferResult<T, R extends string> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly reason: R };

export const fail = <R extends string>(reason: R): { readonly ok: false; readonly reason: R } => ({
  ok: false,
  reason,
});
export const pass = <T>(value: T): { readonly ok: true; readonly value: T } => ({
  ok: true,
  value,
});
