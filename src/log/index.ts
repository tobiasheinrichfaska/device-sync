export type {
  ApprovalHook,
  Change,
  ChangeKind,
  Collection,
  DeviceId,
  FieldHistoryEntry,
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
export { changeCheckValue } from './check.ts';
export { merge } from './merge.ts';
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
export type { WriteResult } from './replica.ts';
