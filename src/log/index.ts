export type {
  ApprovalDecision,
  ApprovalEntry,
  ApprovalHook,
  ApprovalState,
  ApprovalStatus,
  Change,
  ChangeKind,
  Collection,
  DeviceId,
  FieldHistoryEntry,
  FieldRules,
  FieldValue,
  HistoryEntry,
  MergeResult,
  Notice,
  NoticeValue,
  Origin,
  Replica,
  StoredRecord,
  VersionVector,
  WriteRef,
} from './types.ts';
export { MAX_CLOCK_JUMP, concurrent, isNewer, seen, unionVector } from './vector.ts';
export { changeCheckValue, changeLink } from './check.ts';
export { changeAt, needsSnapshot, tipConflict, tipsOf } from './chain.ts';
export {
  SNAPSHOT_VERSION,
  catchUp,
  condense,
  parseSnapshot,
  parseSnapshotText,
  snapshot,
  snapshotSigningText,
} from './snapshot.ts';
export type {
  CatchUpFailure,
  CatchUpOptions,
  CatchUpResult,
  Snapshot,
  SnapshotFailure,
  SnapshotInfo,
  SnapshotOptions,
  SnapshotResult,
} from './snapshot.ts';
export { merge } from './merge.ts';
export {
  APPROVAL_LIMITS,
  approve,
  decide,
  decidedWaiting,
  mergeApproved,
  pendingApproval,
  readApprovalState,
  reject,
} from './approval.ts';
export type {
  ApprovalOptions,
  ApprovalReadFailure,
  ApprovalReadResult,
  ApprovalReport,
  ApprovedMergeResult,
  ChangeRef,
} from './approval.ts';
export {
  changeSigningText,
  insertSignatures,
  judgeChange,
  judgeChanges,
  judgeDetailed,
  proveEquivocation,
  readChanges,
  signChange,
  signOwnChanges,
} from './signing.ts';
export type {
  JudgeContext,
  JudgeOptions,
  Judgement,
  KeySource,
  LimitReason,
  ReadResult,
  Reason,
  Rejection,
  Verdict,
} from './signing.ts';
export {
  DELETED_FIELD,
  emptyReplica,
  fieldHistory,
  findRecord,
  historyOf,
  isHidden,
  knownFor,
  liveRecords,
  missingFor,
  remove,
  restore,
  softDelete,
  undo,
  valueOf,
  valuesOf,
  visibleRecords,
  write,
} from './replica.ts';
export type { WriteFailure, WriteResult } from './replica.ts';
export { LIMITS, PIECE_BYTES, resolveLimits } from './limits.ts';
export type { Limits } from './limits.ts';
export {
  DEFAULT_DEVICE_ID,
  parseChange,
  parseSyncMessage,
  parseSyncMessageText,
  parseVector,
} from './parse.ts';
export type { ParseOptions, SyncMessage } from './parse.ts';
export {
  fingerprint,
  onSyncMessage,
  outcome,
  pieces,
  receive,
  receiveJudged,
  startSession,
} from './protocol.ts';
export type {
  ChangesMessage,
  Outcome,
  Refusal,
  RefusalReason,
  Session,
  SessionOptions,
  Step,
} from './protocol.ts';
export {
  REPLICA_AT_REST,
  REPLICA_VERSION,
  readReplica,
  readReplicaText,
  replicaToStored,
  storeReplica,
} from './readReplica.ts';
export type {
  ReadReplicaFailure,
  ReadReplicaOptions,
  ReadReplicaResult,
  StoredReplica,
  StoreReplicaResult,
} from './readReplica.ts';
export { rehome } from './rehome.ts';
export type { RehomeResult } from './rehome.ts';
