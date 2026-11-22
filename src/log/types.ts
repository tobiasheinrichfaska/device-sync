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
  /**
   * Hash chain: the check value of the same device's previous change (`seq - 1`, see
   * `changeLink`). Present on every change with `seq > 1`, absent on the first. It is part of the
   * signed head and survives redaction, so two versions of one number can never both be followed by
   * an honest successor, and a session's `stand` can prove which version a device holds.
   */
  readonly prev?: string;
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
  /**
   * Changes held back by an approval hook (`mergeApproved`); absent until a hook was ever used. They
   * are NOT in `log` or `vector`, so no stand claims them.
   */
  readonly approval?: ApprovalState;
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

/** What an approval hook says of one incoming change (see `approval.ts`). */
export type ApprovalDecision = 'apply' | 'hold' | 'reject';

/**
 * Asked once per incoming change that is new to a replica (not applied, not already held back).
 * `apply`: merge takes it as usual. `hold`: not applied, remembered in `Replica.approval` until the app
 * approves or rejects it. `reject`: dropped for good, its number still counted (see `docs/approval.md`).
 * `true` means `apply`, `false` means `hold`; a hook that throws or answers anything else holds.
 * `replica` is the replica as it was when the call began (never the half merged one), so the answer
 * cannot depend on the order inside one batch. For convergence between replicas answer from the
 * change alone.
 */
export type ApprovalHook = (change: Change, replica: Replica) => boolean | ApprovalDecision;

/** `hold`: waits for the app. `approved` / `rejected`: decided, waits until it can be applied. */
export type ApprovalStatus = 'hold' | 'approved' | 'rejected';

/** One change the approval layer remembers. */
export interface ApprovalEntry {
  readonly change: Change;
  readonly decision: ApprovalStatus;
}

/**
 * The changes held back for approval: a plain value (JSON), sorted by device and number, stored
 * with the replica and read back with `readApprovalState`.
 */
export interface ApprovalState {
  readonly entries: readonly ApprovalEntry[];
}
