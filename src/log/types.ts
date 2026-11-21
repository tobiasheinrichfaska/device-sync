/** Random id a device creates on its first start; never derived from a person. */
export type DeviceId = string;

/** Per device, the highest change number received without a gap (the "stand"). */
export type VersionVector = Readonly<Record<DeviceId, number>>;

/**
 * 'set' writes fields, 'delete' deletes the record for good, 'redacted' is a former 'set' whose
 * content was erased because its record was deleted: it only keeps the numbering gapless.
 */
export type ChangeKind = 'set' | 'delete' | 'redacted';

/** One entry of a device's change log. Only its author creates it; everyone forwards it. */
export interface Change {
  readonly device: DeviceId;
  /** 1, 2, 3 ... per device, without gaps. */
  readonly seq: number;
  /** Lamport clock at creation; orders writes across devices. */
  readonly clock: number;
  readonly collection: string;
  readonly id: string;
  readonly kind: ChangeKind;
  /** Only for kind 'set'. */
  readonly fields?: Readonly<Record<string, unknown>>;
  /**
   * What the author knew when writing: its version vector, shortened to the devices that wrote the
   * fields this change writes (see `knownFor`). Tells a conflict from a sequence.
   */
  readonly knew?: VersionVector;
  /** When (ms since 1970, the author's own clock) and by whom, for the history only; never used to order writes. */
  readonly time?: number;
  readonly by?: string;
  /**
   * Check value of the content (see `changeCheckValue`) and the author's signature over the head
   * and it. Both stay when a final deletion erases the content.
   */
  readonly check?: string;
  readonly sig?: string;
}

/** Who wrote and when; the caller supplies it, the logic never reads a clock. */
export interface Origin {
  readonly time?: number;
  readonly by?: string;
}

/** A field's current value and the write it came from. */
export interface FieldValue {
  readonly value: unknown;
  readonly clock: number;
  readonly device: DeviceId;
  /** Number of that write at its author, to look up what it knew. */
  readonly seq?: number;
  readonly time?: number;
  readonly by?: string;
}

/** One write to a record, as the history shows it; `applies` = the fields whose current value it is. */
export interface HistoryEntry {
  readonly device: DeviceId;
  readonly seq: number;
  readonly clock: number;
  readonly signed: boolean;
  readonly time?: number;
  readonly by?: string;
  readonly fields: Readonly<Record<string, unknown>>;
  readonly applies: readonly string[];
}

/** One value a field had; `applies` = it is the current one. */
export interface FieldHistoryEntry {
  readonly value: unknown;
  readonly device: DeviceId;
  readonly seq: number;
  readonly clock: number;
  readonly time?: number;
  readonly by?: string;
  readonly applies: boolean;
}

export interface NoticeValue {
  readonly value: unknown;
  readonly device: DeviceId;
  readonly seq: number;
}

/**
 * Two (or more) writes to the same field with different values, none of which knew the others: one
 * value applies (the usual rule), the notice asks a person to check. Gone with a write that knew
 * them all, or with the record's final deletion (its content goes too).
 */
export interface Notice {
  readonly collection: string;
  readonly id: string;
  readonly field: string;
  readonly values: readonly NoticeValue[];
  /** The value that currently applies. */
  readonly applies: unknown;
}

export interface StoredRecord {
  readonly id: string;
  readonly fields: Readonly<Record<string, FieldValue>>;
  /**
   * Final deletion: the content is gone and later writes are ignored. The undoable soft delete is the
   * field `DELETED_FIELD` instead.
   */
  readonly deleted: boolean;
}

export type Collection = Readonly<Record<string, StoredRecord>>;

/** Everything one device holds: its data, its log of all known changes and its stand. */
export interface Replica {
  readonly device: DeviceId;
  readonly clock: number;
  readonly vector: VersionVector;
  /** Every change known here, from all devices; forwarded to devices that lack it. */
  readonly log: readonly Change[];
  readonly collections: Readonly<Record<string, Collection>>;
  /** Conflict notices this device found while merging (each device finds the same ones). */
  readonly notices: readonly Notice[];
}

/** A write and what its author knew; `knew` missing = unknown. */
export interface WriteRef {
  readonly device: DeviceId;
  readonly seq: number;
  readonly knew?: VersionVector;
}

export interface MergeResult {
  readonly replica: Replica;
  readonly applied: number;
  /** Changes after a gap (or with an impossible clock jump); they wait until they can be applied. */
  readonly held: readonly Change[];
}

/**
 * Extension point (not used yet): a future merge option may ask this hook before it applies the
 * next change in line; `false` = hold the change back until someone approves it. The default is to
 * apply everything.
 */
export type ApprovalHook = (change: Change, replica: Replica) => boolean;
