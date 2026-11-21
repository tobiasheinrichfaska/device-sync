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
import { resolveLimits } from './limits.ts';
import { DEFAULT_DEVICE_ID, type ParseOptions } from './parse.ts';
import { indexOf } from './recordIndex.ts';
import {
  FORBIDDEN_NAMES,
  checkFields,
  dict,
  own,
  validHead,
  validOrigin,
  type Problem,
} from './validate.ts';
import { isNewer, seen } from './vector.ts';

/**
 * Name of the field that carries the undoable soft delete: the record stays (and travels), hidden,
 * with its history. It is an ordinary field, so it travels, is decided and shown in the history like
 * any other; an app must not use this name for its own data.
 */
export const DELETED_FIELD = 'deleted';

export function emptyReplica(device: DeviceId): Replica {
  return { device, clock: 0, vector: dict(), log: [], collections: dict(), notices: [] };
}

export function findRecord(
  replica: Replica,
  collection: string,
  id: string,
): StoredRecord | undefined {
  return own(own(replica.collections, collection), id);
}

/** The records not finally deleted; hidden ones (soft delete) included. */
export function liveRecords(replica: Replica, collection: string): StoredRecord[] {
  return Object.values(own(replica.collections, collection) ?? {}).filter((r) => !r.deleted);
}

export function isHidden(record: StoredRecord): boolean {
  return own(record.fields, DELETED_FIELD)?.value === true;
}

/** The records a list shows: neither finally deleted nor hidden. */
export function visibleRecords(replica: Replica, collection: string): StoredRecord[] {
  return liveRecords(replica, collection).filter((r) => !isHidden(r));
}

export function valuesOf(record: StoredRecord): Record<string, unknown> {
  return Object.fromEntries(Object.entries(record.fields).map(([name, f]) => [name, f.value]));
}

export type WriteFailure =
  | 'no-fields'
  | 'record-deleted'
  | 'no-record'
  | 'unknown-change'
  | 'unchanged'
  | Problem
  /** This device's own id is not one the receivers accept. */
  | 'invalid-device'
  /** More devices wrote the fields than one `knew` may name (`maxDevices`). */
  | 'too-many-devices'
  /** The clock or the numbering cannot count further. */
  | 'clock-overflow';

export type WriteResult =
  | { readonly ok: true; readonly replica: Replica }
  | { readonly ok: false; readonly reason: WriteFailure };

/**
 * Writes fields on this device; fields not named keep their value. Everything a receiver's strict
 * parser would refuse is refused here first (names, values, limits, origin): a change this device
 * creates is never one the others cannot take, which would block everything later from it.
 * `options` are the same as the parser's (`limits`, `deviceId`).
 */
export function write(
  replica: Replica,
  collection: string,
  id: string,
  fields: Readonly<Record<string, unknown>>,
  origin: Origin = {},
  options: ParseOptions = {},
): WriteResult {
  if (typeof fields === 'object' && fields !== null && Object.keys(fields).length === 0) {
    return { ok: false, reason: 'no-fields' };
  }
  const refused = precheck(replica, collection, id, origin, options);
  if (refused) return { ok: false, reason: refused };
  const checked = checkFields(fields, resolveLimits(options.limits));
  if (!checked.ok) return { ok: false, reason: checked.reason };
  if (findRecord(replica, collection, id)?.deleted) return { ok: false, reason: 'record-deleted' };
  return commit(replica, collection, id, 'set', origin, options, checked.value);
}

/** The checks every new change passes, whatever its kind. */
function precheck(
  replica: Replica,
  collection: string,
  id: string,
  origin: Origin,
  options: ParseOptions,
): 'invalid-device' | 'invalid-name' | 'invalid-origin' | undefined {
  const limits = resolveLimits(options.limits);
  const deviceOk = options.deviceId ?? ((s: string) => DEFAULT_DEVICE_ID.test(s));
  let valid = false;
  try {
    valid =
      typeof replica.device === 'string' &&
      !FORBIDDEN_NAMES.has(replica.device) &&
      deviceOk(replica.device) === true;
  } catch {
    valid = false;
  }
  if (!valid) return 'invalid-device';
  if (!validHead(collection, id, limits)) return 'invalid-name';
  if (!validOrigin(origin, limits)) return 'invalid-origin';
  return undefined;
}

/** Final delete: content and history go on this device; the deletion travels to all others. */
export function remove(
  replica: Replica,
  collection: string,
  id: string,
  origin: Origin = {},
  options: ParseOptions = {},
): WriteResult {
  const refused = precheck(replica, collection, id, origin, options);
  if (refused) return { ok: false, reason: refused };
  if (findRecord(replica, collection, id)?.deleted) return { ok: true, replica };
  return commit(replica, collection, id, 'delete', origin, options);
}

/** Soft delete: hides the record; undoable, the content and its history stay. */
export function softDelete(
  replica: Replica,
  collection: string,
  id: string,
  origin: Origin = {},
  options: ParseOptions = {},
): WriteResult {
  return setHidden(replica, collection, id, true, origin, options);
}

export function restore(
  replica: Replica,
  collection: string,
  id: string,
  origin: Origin = {},
  options: ParseOptions = {},
): WriteResult {
  return setHidden(replica, collection, id, false, origin, options);
}

function setHidden(
  replica: Replica,
  collection: string,
  id: string,
  hidden: boolean,
  origin: Origin,
  options: ParseOptions,
): WriteResult {
  const record = findRecord(replica, collection, id);
  if (!record) return { ok: false, reason: 'no-record' };
  if (record.deleted) return { ok: false, reason: 'record-deleted' };
  if (isHidden(record) === hidden) return { ok: false, reason: 'unchanged' };
  return write(replica, collection, id, { [DELETED_FIELD]: hidden }, origin, options);
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
          const current = own(record.fields, name);
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
  const current = own(record.fields, field);
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
  options: ParseOptions = {},
): WriteResult {
  const record = findRecord(replica, collection, id);
  if (!record) return { ok: false, reason: 'no-record' };
  if (record.deleted) return { ok: false, reason: 'record-deleted' };
  const writes = historyOf(replica, collection, id);
  const at = writes.findIndex((e) => e.device === target.device && e.seq === target.seq);
  const entry = writes[at];
  if (!entry) return { ok: false, reason: 'unknown-change' };
  const earlier = writes.slice(at + 1);
  if (earlier.length === 0) return softDelete(replica, collection, id, origin, options);
  const fields = Object.fromEntries(
    entry.applies.map((name) => [
      name,
      earlier.find((e) => Object.hasOwn(e.fields, name))?.fields[name] ?? null,
    ]),
  );
  if (Object.keys(fields).length === 0) return { ok: false, reason: 'unchanged' };
  return write(replica, collection, id, fields, origin, options);
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
  const index = indexOf(replica.log).get(collection)?.get(id);
  const devices = new Set<DeviceId>();
  if (fields === null) {
    for (const device of index?.devices ?? []) devices.add(device);
  } else {
    for (const name of fields) {
      for (const device of index?.fields.get(name)?.last.keys() ?? []) devices.add(device);
    }
  }
  for (const [name, value] of Object.entries(record.fields)) {
    if (fields === null || fields.includes(name)) devices.add(value.device);
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
  options: ParseOptions,
  fields?: Readonly<Record<string, unknown>>,
): WriteResult {
  const limits = resolveLimits(options.limits);
  const seq = seen(replica.vector, replica.device) + 1;
  const clock = replica.clock + 1;
  if (!Number.isSafeInteger(seq) || !Number.isSafeInteger(clock)) {
    return { ok: false, reason: 'clock-overflow' };
  }
  const knew = knownFor(replica, collection, id, fields ? Object.keys(fields) : null);
  if (Object.keys(knew).length > limits.maxDevices)
    return { ok: false, reason: 'too-many-devices' };
  const base = {
    device: replica.device,
    seq,
    clock,
    collection,
    id,
    kind,
    knew,
    ...originOf(origin),
  };
  const change: Change = fields ? { ...base, fields } : base;
  // What a receiver reads must fit its message limit.
  if (JSON.stringify(change).length > limits.maxMessageChars) {
    return { ok: false, reason: 'too-large' };
  }
  return { ok: true, replica: merge(replica, [change]).replica };
}
