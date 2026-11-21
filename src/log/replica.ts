import { byDeviceThenSeq, merge, originOf } from './merge.ts';
import type {
  Change,
  ChangeKind,
  DeviceId,
  FieldHistoryEntry,
  HistoryEntry,
  Origin,
  Replica,
  StoredRecord,
  VersionVector,
} from './types.ts';
import { isNewer, seen } from './vector.ts';

/**
 * Name of the field that carries the undoable soft delete: the record stays (and travels), hidden,
 * with its history. It is an ordinary field, so it travels, is decided and shown in the history like
 * any other; an app must not use this name for its own data.
 */
export const DELETED_FIELD = 'deleted';

export function emptyReplica(device: DeviceId): Replica {
  return { device, clock: 0, vector: {}, log: [], collections: {}, notices: [] };
}

export function findRecord(
  replica: Replica,
  collection: string,
  id: string,
): StoredRecord | undefined {
  return replica.collections[collection]?.[id];
}

/** The records not finally deleted; hidden ones (soft delete) included. */
export function liveRecords(replica: Replica, collection: string): StoredRecord[] {
  return Object.values(replica.collections[collection] ?? {}).filter((r) => !r.deleted);
}

export function isHidden(record: StoredRecord): boolean {
  return record.fields[DELETED_FIELD]?.value === true;
}

/** The records a list shows: neither finally deleted nor hidden. */
export function visibleRecords(replica: Replica, collection: string): StoredRecord[] {
  return liveRecords(replica, collection).filter((r) => !isHidden(r));
}

export function valuesOf(record: StoredRecord): Record<string, unknown> {
  return Object.fromEntries(Object.entries(record.fields).map(([name, f]) => [name, f.value]));
}

export type WriteResult =
  | { readonly ok: true; readonly replica: Replica }
  | {
      readonly ok: false;
      readonly reason:
        'no-fields' | 'record-deleted' | 'no-record' | 'unknown-change' | 'unchanged';
    };

/** Writes fields on this device; fields not named keep their value. */
export function write(
  replica: Replica,
  collection: string,
  id: string,
  fields: Readonly<Record<string, unknown>>,
  origin: Origin = {},
): WriteResult {
  if (Object.keys(fields).length === 0) return { ok: false, reason: 'no-fields' };
  if (findRecord(replica, collection, id)?.deleted) return { ok: false, reason: 'record-deleted' };
  return { ok: true, replica: commit(replica, collection, id, 'set', origin, fields) };
}

/** Final delete: content and history go on this device; the deletion travels to all others. */
export function remove(
  replica: Replica,
  collection: string,
  id: string,
  origin: Origin = {},
): Replica {
  if (findRecord(replica, collection, id)?.deleted) return replica;
  return commit(replica, collection, id, 'delete', origin);
}

/** Soft delete: hides the record; undoable, the content and its history stay. */
export function softDelete(
  replica: Replica,
  collection: string,
  id: string,
  origin: Origin = {},
): WriteResult {
  return setHidden(replica, collection, id, true, origin);
}

export function restore(
  replica: Replica,
  collection: string,
  id: string,
  origin: Origin = {},
): WriteResult {
  return setHidden(replica, collection, id, false, origin);
}

function setHidden(
  replica: Replica,
  collection: string,
  id: string,
  hidden: boolean,
  origin: Origin,
): WriteResult {
  const record = findRecord(replica, collection, id);
  if (!record) return { ok: false, reason: 'no-record' };
  if (record.deleted) return { ok: false, reason: 'record-deleted' };
  if (isHidden(record) === hidden) return { ok: false, reason: 'unchanged' };
  return write(replica, collection, id, { [DELETED_FIELD]: hidden }, origin);
}

/** Every write to a record still on this device, newest first (in the order that decides values). */
export function historyOf(replica: Replica, collection: string, id: string): HistoryEntry[] {
  const record = findRecord(replica, collection, id);
  if (!record || record.deleted) return [];
  return replica.log
    .filter((c) => c.kind === 'set' && c.collection === collection && c.id === id)
    .sort((a, b) => (isNewer(a, b) ? -1 : isNewer(b, a) ? 1 : 0))
    .map((c) => {
      const fields = c.fields ?? {};
      return {
        device: c.device,
        seq: c.seq,
        clock: c.clock,
        signed: !!c.sig,
        ...originOf(c),
        fields,
        // Device and clock name one write.
        applies: Object.keys(fields).filter((name) => {
          const current = record.fields[name];
          return current?.device === c.device && current.clock === c.clock;
        }),
      };
    });
}

/** The values one field had, newest first. */
export function fieldHistory(
  replica: Replica,
  collection: string,
  id: string,
  field: string,
): FieldHistoryEntry[] {
  return historyOf(replica, collection, id)
    .filter((entry) => Object.hasOwn(entry.fields, field))
    .map(({ device, seq, clock, time, by, fields, applies }) => ({
      value: fields[field],
      device,
      seq,
      clock,
      ...originOf({ time, by }),
      applies: applies.includes(field),
    }));
}

/**
 * A field as one device left it: what other devices wrote into it counts for nothing. For records a
 * device owns.
 */
export function valueOf(
  replica: Replica,
  collection: string,
  record: StoredRecord,
  device: DeviceId,
  field: string,
): unknown {
  const current = record.fields[field];
  if (!current || current.device === device) return current?.value;
  return fieldHistory(replica, collection, record.id, field).find((h) => h.device === device)
    ?.value;
}

/**
 * Undo as a new write, so it travels like any change: each field this write still decides gets the
 * value it had before (null if it had none). Fields written again since are left alone. Undoing the
 * write that created the record hides the record instead of emptying it.
 */
export function undo(
  replica: Replica,
  collection: string,
  id: string,
  target: { readonly device: DeviceId; readonly seq: number },
  origin: Origin = {},
): WriteResult {
  const record = findRecord(replica, collection, id);
  if (!record) return { ok: false, reason: 'no-record' };
  if (record.deleted) return { ok: false, reason: 'record-deleted' };
  const writes = historyOf(replica, collection, id);
  const at = writes.findIndex((e) => e.device === target.device && e.seq === target.seq);
  const entry = writes[at];
  if (!entry) return { ok: false, reason: 'unknown-change' };
  const earlier = writes.slice(at + 1);
  if (earlier.length === 0) return softDelete(replica, collection, id, origin);
  const fields = Object.fromEntries(
    entry.applies.map((name) => [
      name,
      earlier.find((e) => Object.hasOwn(e.fields, name))?.fields[name] ?? null,
    ]),
  );
  if (Object.keys(fields).length === 0) return { ok: false, reason: 'unchanged' };
  return write(replica, collection, id, fields, origin);
}

/** The changes a device with this stand lacks, in an order it can apply directly. */
export function missingFor(replica: Replica, vector: VersionVector): Change[] {
  return replica.log.filter((c) => c.seq > seen(vector, c.device)).sort(byDeviceThenSeq);
}

/**
 * What a new change of this device says it knew: of its stand, only the devices that wrote the named
 * fields of the record (writes in its log, current values; notices are derived from the log, so
 * their devices are in it already). `fields` null = every
 * field (a final delete). Every check of the model asks `knew` only about such devices, so it
 * decides as with the whole stand, at a fraction of the size.
 */
export function knownFor(
  replica: Replica,
  collection: string,
  id: string,
  fields: readonly string[] | null,
): VersionVector {
  // A record this replica never held: nothing it knew (and no scan of the whole log: a new stand
  // writes every record once, which would make its build quadratic).
  const record = findRecord(replica, collection, id);
  if (!record) return {};
  const concerns = (name: string) => fields === null || fields.includes(name);
  const devices = new Set<DeviceId>();
  for (const c of replica.log) {
    if (c.collection !== collection || c.id !== id) continue;
    if (fields === null || Object.keys(c.fields ?? {}).some(concerns)) devices.add(c.device);
  }
  for (const [name, value] of Object.entries(record.fields)) {
    if (concerns(name)) devices.add(value.device);
  }
  return Object.fromEntries(
    [...devices]
      .filter((d) => seen(replica.vector, d) > 0)
      .sort()
      .map((d) => [d, seen(replica.vector, d)]),
  );
}

function commit(
  replica: Replica,
  collection: string,
  id: string,
  kind: ChangeKind,
  origin: Origin,
  fields?: Readonly<Record<string, unknown>>,
): Replica {
  const base = {
    device: replica.device,
    seq: seen(replica.vector, replica.device) + 1,
    clock: replica.clock + 1,
    collection,
    id,
    kind,
    knew: knownFor(replica, collection, id, fields ? Object.keys(fields) : null),
    ...originOf(origin),
  };
  return merge(replica, [fields ? { ...base, fields } : base]).replica;
}
