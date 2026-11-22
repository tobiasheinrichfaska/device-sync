import { canonical } from '../core/index.ts';
import { heldIn } from './chain.ts';
import { changeCheckValue } from './check.ts';
import { IndexEditor, indexOf, rememberIndex, type LogIndex } from './recordIndex.ts';
import type {
  Change,
  Collection,
  DeviceId,
  FieldValue,
  MergeResult,
  Notice,
  Origin,
  Replica,
  StoredRecord,
} from './types.ts';
import { copyDict, dict, own } from './validate.ts';
import { MAX_CLOCK_JUMP, concurrent, isNewer, seen } from './vector.ts';

/** `time`/`by` of a source, as an `Origin` without undefined members. */
export function originOf(source: {
  readonly time?: number | undefined;
  readonly by?: string | undefined;
}): Origin {
  return {
    ...(source.time !== undefined ? { time: source.time } : {}),
    ...(source.by !== undefined ? { by: source.by } : {}),
  };
}

interface Queue {
  readonly items: Change[];
  at: number;
}

/**
 * Applies received changes in any order and any number of times; all devices converge.
 *
 * A change is applied when (1) it is the next of its device (no gap), (2) its clock is no further
 * ahead than `MAX_CLOCK_JUMP`, and (3) the replica already holds every change its author says it
 * knew (`knew`; the causal hold). It is applied in the same call as soon as that becomes true, so
 * the order of delivery inside one call does not matter. `held` are the changes that cannot be
 * applied yet; they wait. A change that names more than its author could have known (or none, for a
 * `set` or `delete`) blocks only its own author's later changes.
 */
export function merge(replica: Replica, incoming: readonly Change[]): MergeResult {
  const vector = copyDict(replica.vector);
  const log: Change[] = [...replica.log];
  let notices: Notice[] = [...replica.notices];
  let { clock } = replica;
  // A collection is copied once per merge (when first changed), not once per change: copying it for
  // every change made a large batch quadratic.
  const collections = copyDict(replica.collections) as Record<string, Record<string, StoredRecord>>;
  const owned = new Set<string>();
  const edit = (name: string): Record<string, StoredRecord> => {
    if (!owned.has(name)) {
      collections[name] = copyDict(own(collections, name) ?? {});
      owned.add(name);
    }
    return collections[name] as Record<string, StoredRecord>;
  };
  const editor = new IndexEditor(indexOf(replica.log));
  let applied = 0;
  const touched = new Map<string, Map<string, Set<string>>>();
  const deleted = new Set<string>();

  const queues = new Map<DeviceId, Queue>();
  for (const change of unique(incoming)) {
    const queue = queues.get(change.device) ?? { items: [], at: 0 };
    queue.items.push(change);
    queues.set(change.device, queue);
  }
  for (const queue of queues.values()) queue.items.sort((a, b) => a.seq - b.seq);
  // Devices to look at (smallest id popped first). A device that has to wait is looked at again
  // when what it waits for happens: the number of another device, or the clock.
  const ready = [...queues.keys()].sort().reverse();
  const waitingForDevice = new Map<DeviceId, DeviceId[]>();
  const waitingForClock = new MinHeap();

  while (ready.length > 0) {
    const device = ready.pop() as DeviceId;
    const queue = queues.get(device) as Queue;
    for (;;) {
      while (
        queue.at < queue.items.length &&
        (queue.items[queue.at] as Change).seq <= seen(vector, device)
      ) {
        queue.at += 1;
      }
      const change = queue.items[queue.at];
      if (!change) break;
      // A gap waits for what is missing.
      if (change.seq !== seen(vector, device) + 1) break;
      // Without what the author knew no device could tell a conflict: never applied.
      if (change.kind !== 'redacted' && !change.knew) break;
      // A clock jump like no real history waits until the clock has come close.
      if (change.clock > clock + MAX_CLOCK_JUMP) {
        waitingForClock.push(change.clock - MAX_CLOCK_JUMP, device);
        break;
      }
      const missing = missingDependency(change, vector);
      if (missing !== undefined) {
        const list = waitingForDevice.get(missing) ?? [];
        list.push(device);
        waitingForDevice.set(missing, list);
        break;
      }
      // Approval (a hook that holds a change back) never happens here: `mergeApproved` decides
      // before and passes on only what is to be applied (`approval.ts`).
      const position = log.length;
      const logged = apply(collections, edit, change);
      log.push(logged);
      const record = editor.record(change.collection, change.id);
      if (logged.kind === 'set') {
        editor.addSet(record, logged, position);
        markTouched(touched, change);
      } else if (change.kind === 'delete') {
        // The content of every earlier write goes; numbering stays gapless.
        for (const at of record.positions) log[at] = redacted(log[at] as Change);
        editor.clear(record, change);
        deleted.add(JSON.stringify([change.collection, change.id]));
      } else {
        record.devices.add(change.device);
      }
      vector[device] = change.seq;
      applied += 1;
      queue.at += 1;
      for (const waiting of waitingForDevice.get(device) ?? []) ready.push(waiting);
      waitingForDevice.delete(device);
      if (change.clock > clock) {
        clock = change.clock;
        for (const waiting of waitingForClock.popUpTo(clock)) ready.push(waiting);
      }
    }
  }

  const held: Change[] = [];
  for (const device of [...queues.keys()].sort()) {
    const queue = queues.get(device) as Queue;
    for (const change of queue.items.slice(queue.at)) {
      if (change.seq > seen(vector, device)) held.push(change);
    }
  }
  if (deleted.size > 0) {
    // The notices name the values: they go with the content.
    notices = notices.filter((n) => !deleted.has(JSON.stringify([n.collection, n.id])));
  }
  if (touched.size > 0) notices = refreshNotices(notices, touched, editor.index, collections);
  rememberIndex(log, editor.index);
  return { replica: { ...replica, clock, vector, log, collections, notices }, applied, held };
}

/** A device whose stand here is lower than this change says its author knew, if any. */
function missingDependency(change: Change, vector: Replica['vector']): DeviceId | undefined {
  for (const [device, seq] of Object.entries(change.knew ?? {})) {
    if (seen(vector, device) < seq) return device;
  }
  return undefined;
}

function markTouched(touched: Map<string, Map<string, Set<string>>>, change: Change): void {
  const byId = touched.get(change.collection) ?? new Map<string, Set<string>>();
  touched.set(change.collection, byId);
  const fields = byId.get(change.id) ?? new Set<string>();
  byId.set(change.id, fields);
  for (const field of Object.keys(change.fields ?? {})) fields.add(field);
}

type Entry = readonly [number, DeviceId];

/** Smallest-first queue of devices that wait for the clock to reach a number. */
class MinHeap {
  private readonly items: Entry[] = [];

  push(key: number, device: DeviceId): void {
    const items = this.items;
    items.push([key, device]);
    let i = items.length - 1;
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if ((items[parent] as Entry)[0] <= (items[i] as Entry)[0]) break;
      [items[parent], items[i]] = [items[i] as Entry, items[parent] as Entry];
      i = parent;
    }
  }

  /** Removes and returns every device whose number is at most `limit`. */
  popUpTo(limit: number): DeviceId[] {
    const items = this.items;
    const out: DeviceId[] = [];
    while (items.length > 0 && (items[0] as Entry)[0] <= limit) {
      out.push((items[0] as Entry)[1]);
      const last = items.pop() as Entry;
      if (items.length === 0) break;
      items[0] = last;
      let i = 0;
      for (;;) {
        const left = 2 * i + 1;
        const right = left + 1;
        let smallest = i;
        if (left < items.length && (items[left] as Entry)[0] < (items[smallest] as Entry)[0]) {
          smallest = left;
        }
        if (right < items.length && (items[right] as Entry)[0] < (items[smallest] as Entry)[0]) {
          smallest = right;
        }
        if (smallest === i) break;
        [items[smallest], items[i]] = [items[i] as Entry, items[smallest] as Entry];
        i = smallest;
      }
    }
    return out;
  }
}

export function apply(
  collections: Readonly<Record<string, Collection>>,
  edit: (collection: string) => Record<string, StoredRecord>,
  change: Change,
): Change {
  const current = own(own(collections, change.collection), change.id);
  if (change.kind === 'redacted') return change;
  // A write to a deleted record never stores its content, not even in the log.
  if (current?.deleted && change.kind === 'set') return redacted(change);
  if (change.kind === 'delete') {
    edit(change.collection)[change.id] = { id: change.id, fields: dict(), deleted: true };
    return change;
  }
  const fields = copyDict<FieldValue>(current?.fields ?? {});
  for (const [name, value] of Object.entries(change.fields ?? {})) {
    const candidate: FieldValue = {
      value,
      clock: change.clock,
      device: change.device,
      seq: change.seq,
      ...originOf(change),
    };
    const existing = own(fields, name);
    if (!existing || isNewer(candidate, existing)) fields[name] = candidate;
  }
  edit(change.collection)[change.id] = { id: change.id, fields, deleted: false };
  return change;
}

/**
 * Conflict notices are a pure function of the log, so every device that holds the same changes finds
 * the same notices, whatever the order of arrival. For one field: the writes no other write knew
 * (the "heads"; a later write of the same device counts as knowing, so only the last write of each
 * device can be a head) and that are concurrent with at least one other head; a notice exists when
 * they carry different values. Writes with unknown knowledge (no `knew`) never conflict. A write
 * that knew every head settles the notice. The record index keeps, per field, each device's last
 * write and the highest number any write said it knew of each device, so nothing rescans the log.
 */
function refreshNotices(
  notices: readonly Notice[],
  touched: ReadonlyMap<string, ReadonlyMap<string, ReadonlySet<string>>>,
  index: LogIndex,
  collections: Replica['collections'],
): Notice[] {
  const isTouched = (n: Notice): boolean =>
    touched.get(n.collection)?.get(n.id)?.has(n.field) === true;
  const kept = notices.filter((n) => !isTouched(n));
  for (const [collection, byId] of touched) {
    for (const [id, fields] of byId) {
      const record = own(own(collections, collection), id);
      if (!record || record.deleted) continue;
      const recordIndex = index.get(collection)?.get(id);
      for (const field of fields) {
        const fieldIndex = recordIndex?.fields.get(field);
        if (!fieldIndex) continue;
        const heads = [...fieldIndex.last.values()].filter(
          (w) => (fieldIndex.maxKnew.get(w.device) ?? 0) < w.seq,
        );
        const clashing = heads.filter((w) => heads.some((o) => concurrent(w, o)));
        const first = clashing[0];
        if (!first || clashing.every((w) => sameValue(w.fields?.[field], first.fields?.[field])))
          continue;
        kept.push({
          collection,
          id,
          field,
          values: clashing
            .map((w) => ({ value: w.fields?.[field], device: w.device, seq: w.seq }))
            .sort((a, b) => (a.device < b.device ? -1 : a.device > b.device ? 1 : a.seq - b.seq)),
          applies: own(record.fields, field)?.value,
        });
      }
    }
  }
  return kept.sort(byNoticeKey);
}

const sameValue = (a: unknown, b: unknown): boolean => canonical(a) === canonical(b);

function byNoticeKey(a: Notice, b: Notice): number {
  const x = JSON.stringify([a.collection, a.id, a.field]);
  const y = JSON.stringify([b.collection, b.id, b.field]);
  return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * The head, the link to the previous change, the check value of the content (taken now if the
 * author had not set it yet) and the signature stay: the head remains checkable, the numbering
 * gapless and the hash chain unbroken.
 */
export function redacted(change: Change): Change {
  const { device, seq, clock, collection, id, sig, prev } = change;
  return {
    device,
    seq,
    clock,
    collection,
    id,
    kind: 'redacted',
    check: change.check ?? changeCheckValue(change),
    ...(prev !== undefined ? { prev } : {}),
    ...(sig ? { sig } : {}),
  };
}

const keyOf = (change: Change): string => `${change.device}#${change.seq}`;

function unique(changes: readonly Change[]): Change[] {
  const byKey = new Map<string, Change>();
  for (const change of changes) {
    const key = keyOf(change);
    if (!byKey.has(key)) byKey.set(key, change);
  }
  return [...byKey.values()];
}

export function byDeviceThenSeq(a: Change, b: Change): number {
  return a.device < b.device ? -1 : a.device > b.device ? 1 : a.seq - b.seq;
}

/**
 * Takes the retained changes of a snapshot into a replica (`catchUp`; the changes were judged by the
 * caller). They are NOT a gapless run: what lies between them is covered by `vector`, which is the
 * snapshot's stand, so nothing is held back for a gap or a `knew`. Deletions take effect after the
 * writes (a deletion wins over any write whatever their order), and the log keeps the changes ordered
 * by device and number. The caller has dropped everything this replica already holds.
 */
export function mergeRetained(
  replica: Replica,
  retained: readonly Change[],
  vector: Replica['vector'],
  clock: number,
  base: NonNullable<Replica['base']>,
): Replica {
  const log: Change[] = [...replica.log];
  const collections = copyDict(replica.collections) as Record<string, Record<string, StoredRecord>>;
  const owned = new Set<string>();
  const edit = (name: string): Record<string, StoredRecord> => {
    if (!owned.has(name)) {
      collections[name] = copyDict(own(collections, name) ?? {});
      owned.add(name);
    }
    return collections[name] as Record<string, StoredRecord>;
  };
  const editor = new IndexEditor(indexOf(replica.log));
  const touched = new Map<string, Map<string, Set<string>>>();
  const deleted = new Set<string>();
  const deletions: Change[] = [];
  const sorted = [...retained].sort(byDeviceThenSeq);
  for (const change of sorted) {
    const position = log.length;
    const record = editor.record(change.collection, change.id);
    if (change.kind === 'delete') {
      log.push(change);
      deletions.push(change);
    } else {
      const logged = apply(collections, edit, change);
      log.push(logged);
      if (logged.kind === 'set') {
        editor.addSet(record, logged, position);
        markTouched(touched, logged);
      } else {
        record.devices.add(change.device);
      }
    }
  }
  for (const change of deletions) {
    const record = editor.record(change.collection, change.id);
    apply(collections, edit, change);
    for (const at of record.positions) log[at] = redacted(log[at] as Change);
    editor.clear(record, change);
    deleted.add(JSON.stringify([change.collection, change.id]));
  }
  let notices: Notice[] = [...replica.notices];
  if (deleted.size > 0) {
    notices = notices.filter((n) => !deleted.has(JSON.stringify([n.collection, n.id])));
  }
  if (touched.size > 0) notices = refreshNotices(notices, touched, editor.index, collections);
  rememberIndex(log, editor.index);
  return {
    ...replica,
    clock: Math.max(replica.clock, clock),
    vector: copyDict(vector),
    log,
    collections,
    notices,
    base: { ...replica.base, ...base },
  };
}

/**
 * The replica with sparse changes put in: changes that are NOT a gapless run (the writes a removal
 * notice carries, the retained changes of a snapshot), applied without waiting for a gap or a `knew`.
 * It is for judging on a throw-away copy (`vector` and the clock stay as they were, so nothing here
 * says the replica "has" these numbers, and the copy must never be stored or sent on). Changes the
 * replica already holds are left out. Cost linear in the changes (plus the copy of the log).
 */
export function mergeSparse(replica: Replica, changes: readonly Change[]): Replica {
  const held = heldIn(replica.log);
  const fresh = unique(changes).filter((c) => !held.has(keyOf(c)));
  if (fresh.length === 0) return replica;
  const out = mergeRetained(replica, fresh, replica.vector, replica.clock, {});
  if (replica.base) return out;
  const { base: _marker, ...plain } = out;
  return plain;
}
