import { LogCache } from './logCache.ts';
import type { Change, DeviceId } from './types.ts';

/** What the writes of one field say: the last write of each device and what writers knew of others. */
export interface FieldIndex {
  /** The newest write of each device to this field (a later write of a device always dominates). */
  last: Map<DeviceId, Change>;
  /** Per device, the highest number any write to this field says its author knew. */
  maxKnew: Map<DeviceId, number>;
}

/** What the log holds about one record, kept so nothing rescans the whole log. */
export interface RecordIndex {
  fields: Map<string, FieldIndex>;
  /** Every device that wrote anything to the record (any kind of change). */
  devices: Set<DeviceId>;
  /** Log positions of the record's writes that still carry content (to erase them on deletion). */
  positions: number[];
}

/** collection -> id -> index. Maps, so any string is an ordinary key. */
export type LogIndex = Map<string, Map<string, RecordIndex>>;

const cache = new LogCache<LogIndex>();

/** The index of a log: remembered for the log array a merge produced, built from the log otherwise. */
export function indexOf(log: readonly Change[]): LogIndex {
  const known = cache.get(log);
  if (known) return known;
  const editor = new IndexEditor(new Map());
  log.forEach((change, position) => {
    const record = editor.record(change.collection, change.id);
    if (change.kind === 'set') editor.addSet(record, change, position);
    else if (change.kind === 'delete') editor.clear(record, change);
    else record.devices.add(change.device);
  });
  cache.set(log, editor.index);
  return editor.index;
}

export function rememberIndex(log: readonly Change[], index: LogIndex): void {
  cache.set(log, index);
}

/**
 * Changes an index without touching the one it started from (other replica states still use it):
 * a collection's map, a record's index and a field's index are copied the first time they change.
 */
export class IndexEditor {
  readonly index: LogIndex;
  private readonly ownedCollections = new Set<Map<string, RecordIndex>>();
  private readonly ownedRecords = new Set<RecordIndex>();
  private readonly ownedFields = new Set<FieldIndex>();

  constructor(from: LogIndex) {
    this.index = new Map(from);
  }

  /** The (editable) index of a record; created when new. */
  record(collection: string, id: string): RecordIndex {
    let records = this.index.get(collection);
    if (!records) {
      records = new Map();
      this.index.set(collection, records);
      this.ownedCollections.add(records);
    } else if (!this.ownedCollections.has(records)) {
      records = new Map(records);
      this.index.set(collection, records);
      this.ownedCollections.add(records);
    }
    let record = records.get(id);
    if (!record) {
      record = { fields: new Map(), devices: new Set(), positions: [] };
      this.ownedRecords.add(record);
      records.set(id, record);
    } else if (!this.ownedRecords.has(record)) {
      record = {
        fields: new Map(record.fields),
        devices: new Set(record.devices),
        positions: [...record.positions],
      };
      this.ownedRecords.add(record);
      records.set(id, record);
    }
    return record;
  }

  private field(record: RecordIndex, name: string): FieldIndex {
    let field = record.fields.get(name);
    if (!field) {
      field = { last: new Map(), maxKnew: new Map() };
      this.ownedFields.add(field);
      record.fields.set(name, field);
    } else if (!this.ownedFields.has(field)) {
      field = { last: new Map(field.last), maxKnew: new Map(field.maxKnew) };
      this.ownedFields.add(field);
      record.fields.set(name, field);
    }
    return field;
  }

  /** A write that carries content, at its position in the log. */
  addSet(record: RecordIndex, change: Change, position: number): void {
    record.devices.add(change.device);
    record.positions.push(position);
    for (const name of Object.keys(change.fields ?? {})) {
      const field = this.field(record, name);
      field.last.set(change.device, change);
      for (const [device, seq] of Object.entries(change.knew ?? {})) {
        if (seq > (field.maxKnew.get(device) ?? 0)) field.maxKnew.set(device, seq);
      }
    }
  }

  /** The record is deleted for good: no write keeps content. */
  clear(record: RecordIndex, change: Change): void {
    record.devices.add(change.device);
    record.fields = new Map();
    record.positions = [];
  }
}
