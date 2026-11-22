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
  /**
   * Most devices in one `knew` (the unresolved concurrent heads a write names); also bounds how many
   * concurrent heads a field may have before local writing answers `too-many-devices`.
   */
  readonly maxDevices: number;
  /**
   * Most devices in the version vector of a `stand` or `done` (and so in its `tips`): the vector
   * lists every device that ever wrote, so it grows over the years and needs room of its own. A
   * receiver that gets more ENDS THE SESSION (`Session.truncated`, `limit: 'stand-devices'`); it
   * is not a refusal. The message size still bounds it: one stand entry costs about 50 characters of
   * vector and 90 of tips for a 39-character device id, so 10000 devices are about 1.4 million
   * characters, and a stand over `maxMessageChars` is too large as well.
   */
  readonly maxStandDevices: number;
  /** Most changes in one message. */
  readonly maxChanges: number;
  /** A piece (one changes message) is cut at this many UTF-8 bytes of JSON; one change may exceed it alone. */
  readonly pieceBytes: number;
  /**
   * One `changes` message as JSON may be at most this long (UTF-16 units). Bounds the work and memory
   * a single message can cost; a transport should also cap what it hands to the parser.
   */
  readonly maxMessageChars: number;
  /** Most changes `receiveJudged` holds over the pieces of one session before it gives up. */
  readonly maxSessionChanges: number;
  /**
   * The same two budgets while the session holds an erased change whose deletion has not arrived
   * (`maxGroupChanges` instead of `maxSessionChanges`, `maxGroupChars` instead of `maxSessionChars`).
   * An erased change can only be applied together with its record's deletion, and the deletion only
   * after every earlier number of its author: that group of changes is indivisible, so a sender
   * answers with it whole even when it is larger than the session budget (progress guarantee), and a
   * receiver reads on until the deletion has come, up to these ceilings. A group larger than the
   * ceilings cannot be taken: the session ends `truncated` every time and the app raises the limits.
   */
  readonly maxGroupChanges: number;
  readonly maxGroupChars: number;
  /**
   * Most characters (UTF-16 units of the JSON) of changes `receiveJudged` holds over one session:
   * the count limit alone does not bound memory, as one change may be long.
   */
  readonly maxSessionChars: number;
  /** Most changes of a session that wait because their author cannot be checked yet. */
  readonly maxPendingChanges: number;
  /**
   * Most retained changes in one snapshot, and its size as JSON (UTF-16 units). A snapshot is one
   * text that a transport cuts into frames; a receiver refuses what is over (`too-large`), it never
   * takes a prefix.
   */
  readonly maxSnapshotChanges: number;
  readonly maxSnapshotChars: number;
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
  maxStandDevices: 10_000,
  maxChanges: 500,
  pieceBytes: 12000,
  maxMessageChars: 1_000_000,
  maxSessionChanges: 100_000,
  maxSessionChars: 16_000_000,
  maxGroupChanges: 400_000,
  maxGroupChars: 64_000_000,
  maxPendingChanges: 2000,
  maxSnapshotChanges: 400_000,
  maxSnapshotChars: 128_000_000,
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
