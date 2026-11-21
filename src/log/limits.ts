/**
 * Every limit of the exchange in one place. The parsers and the session take an optional partial
 * override (`ParseOptions.limits`); anything not named keeps its default. Documented in
 * `docs/wire-format.md`, section "Exchange".
 */
export interface Limits {
  /** Most fields one `set` change may carry. */
  readonly maxFields: number;
  /** Longest text (UTF-16 units) anywhere in a field value. */
  readonly maxText: number;
  /** One field value as JSON text may be at most this long (also bounds the work of reading it). */
  readonly maxValueChars: number;
  /** Most nested lists/objects inside one field value (the value itself counts as level one). */
  readonly maxDepth: number;
  /** Most entries in one list or object of a value. */
  readonly maxEntries: number;
  /** Most devices in one version vector. */
  readonly maxDevices: number;
  /** Most changes in one message. */
  readonly maxChanges: number;
  /** A piece (one changes message) is cut at this many UTF-8 bytes of JSON; one change may exceed it alone. */
  readonly pieceBytes: number;
  /**
   * One `changes` message as JSON may be at most this long (UTF-16 units). Bounds the work and memory
   * a single message can cost; a transport should also cap what it hands to the parser.
   */
  readonly maxMessageChars: number;
  /** Most changes `receiveJudged` collects over the pieces of one session before it gives up. */
  readonly maxSessionChanges: number;
  /** Longest field name, author label (`by`) and object key inside a value. */
  readonly maxName: number;
  /** Longest collection name and record id. */
  readonly maxId: number;
}

export const LIMITS: Limits = Object.freeze({
  maxFields: 40,
  maxText: 2000,
  maxValueChars: 16000,
  maxDepth: 6,
  maxEntries: 200,
  maxDevices: 50,
  maxChanges: 500,
  pieceBytes: 12000,
  maxMessageChars: 1_000_000,
  maxSessionChanges: 100_000,
  maxName: 120,
  maxId: 200,
});

/** The default piece size, as a name of its own. */
export const PIECE_BYTES = LIMITS.pieceBytes;

/** The defaults with a partial override on top; members that are not numbers are ignored. */
export function resolveLimits(override?: Partial<Limits>): Limits {
  if (!override) return LIMITS;
  const out: Record<string, number> = { ...LIMITS };
  for (const key of Object.keys(LIMITS)) {
    const value = (override as Record<string, unknown>)[key];
    if (typeof value === 'number' && Number.isFinite(value)) out[key] = value;
  }
  return out as unknown as Limits;
}
