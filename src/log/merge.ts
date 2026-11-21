import { canonical } from '../core/index.ts';
import { changeCheckValue } from './check.ts';
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

/**
 * Applies received changes in any order and any number of times; all devices converge.
 * `held` are changes after a gap; they wait until the gap is filled.
 */
export function merge(replica: Replica, incoming: readonly Change[]): MergeResult {
  const vector: Record<DeviceId, number> = { ...replica.vector };
  const log: Change[] = [...replica.log];
  let notices: Notice[] = [...replica.notices];
  let { clock } = replica;
  // A collection is copied once per merge (when first changed), not once per change: copying it for
  // every change made a large batch quadratic.
  const collections: Record<string, Record<string, StoredRecord>> = { ...replica.collections };
  const owned = new Set<string>();
  const edit = (name: string): Record<string, StoredRecord> => {
    if (!owned.has(name)) {
      collections[name] = { ...(collections[name] ?? {}) };
      owned.add(name);
    }
    return collections[name] as Record<string, StoredRecord>;
  };
  let applied = 0;
  const held: Change[] = [];
  const touched = new Map<string, readonly [string, string, string]>();
  for (const change of unique(incoming).sort(byDeviceThenSeq)) {
    const known = seen(vector, change.device);
    if (change.seq <= known) continue;
    // A gap waits for what is missing; a clock jump like no real history waits for good.
    if (change.seq !== known + 1 || change.clock > clock + MAX_CLOCK_JUMP) {
      held.push(change);
      continue;
    }
    // Extension point: a future `ApprovalHook` is asked here; a refused change goes to `held`.
    const logged = apply(collections, edit, change);
    log.push(logged);
    if (logged.kind === 'set') {
      for (const field of Object.keys(change.fields ?? {})) {
        touched.set(JSON.stringify([change.collection, change.id, field]), [
          change.collection,
          change.id,
          field,
        ]);
      }
    }
    if (change.kind === 'delete') {
      redactRecord(log, change.collection, change.id);
      // The notices name the values: they go with the content.
      notices = notices.filter((n) => n.collection !== change.collection || n.id !== change.id);
    }
    vector[change.device] = change.seq;
    clock = Math.max(clock, change.clock);
    applied += 1;
  }
  if (touched.size > 0) notices = refreshNotices(notices, touched, log, collections);
  return { replica: { ...replica, clock, vector, log, collections, notices }, applied, held };
}

function apply(
  collections: Readonly<Record<string, Collection>>,
  edit: (collection: string) => Record<string, StoredRecord>,
  change: Change,
): Change {
  const current = collections[change.collection]?.[change.id];
  if (change.kind === 'redacted') return change;
  // A write to a deleted record never stores its content, not even in the log.
  if (current?.deleted && change.kind === 'set') return redacted(change);
  if (change.kind === 'delete') {
    edit(change.collection)[change.id] = { id: change.id, fields: {}, deleted: true };
    return change;
  }
  const fields: Record<string, FieldValue> = { ...(current?.fields ?? {}) };
  for (const [name, value] of Object.entries(change.fields ?? {})) {
    const candidate: FieldValue = {
      value,
      clock: change.clock,
      device: change.device,
      seq: change.seq,
      ...originOf(change),
    };
    const existing = fields[name];
    if (!existing || isNewer(candidate, existing)) fields[name] = candidate;
  }
  edit(change.collection)[change.id] = { id: change.id, fields, deleted: false };
  return change;
}

/**
 * Conflict notices are a pure function of the log, so every device that holds the same changes finds
 * the same notices, whatever the order of arrival. For one field: the writes no other write knew
 * (the "heads", a later write of the same device counts as knowing) and that are concurrent with at
 * least one other head; a notice exists when they carry different values. Writes with unknown
 * knowledge (no `knew`) never conflict. A write that knew every head settles the notice.
 */
function refreshNotices(
  notices: readonly Notice[],
  touched: ReadonlyMap<string, readonly [string, string, string]>,
  log: readonly Change[],
  collections: Replica['collections'],
): Notice[] {
  const records = new Set([...touched.values()].map(([c, i]) => JSON.stringify([c, i])));
  const writes = new Map<string, Change[]>();
  for (const c of log) {
    if (c.kind !== 'set') continue;
    const key = JSON.stringify([c.collection, c.id]);
    if (records.has(key)) (writes.get(key) ?? writes.set(key, []).get(key)!).push(c);
  }
  const kept = notices.filter((n) => !touched.has(JSON.stringify([n.collection, n.id, n.field])));
  for (const [collection, id, field] of touched.values()) {
    const record = collections[collection]?.[id];
    if (!record || record.deleted) continue;
    const all = (writes.get(JSON.stringify([collection, id])) ?? []).filter((c) =>
      Object.hasOwn(c.fields ?? {}, field),
    );
    const heads = all.filter(
      (w) =>
        !all.some(
          (o) =>
            o !== w && (o.device === w.device ? o.seq > w.seq : seen(o.knew, w.device) >= w.seq),
        ),
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
      applies: record.fields[field]?.value,
    });
  }
  return kept.sort(byNoticeKey);
}

const sameValue = (a: unknown, b: unknown): boolean => canonical(a) === canonical(b);

function byNoticeKey(a: Notice, b: Notice): number {
  const x = JSON.stringify([a.collection, a.id, a.field]);
  const y = JSON.stringify([b.collection, b.id, b.field]);
  return x < y ? -1 : x > y ? 1 : 0;
}

/** Erases the content of every earlier write to a deleted record; numbering stays gapless. */
function redactRecord(log: Change[], collection: string, id: string): void {
  log.forEach((change, index) => {
    if (change.collection === collection && change.id === id && change.kind === 'set') {
      log[index] = redacted(change);
    }
  });
}

/**
 * The head, the check value of the content (taken now if the author had not set it yet) and the
 * signature stay: the head remains checkable and the numbering gapless.
 */
export function redacted(change: Change): Change {
  const { device, seq, clock, collection, id, sig } = change;
  return {
    device,
    seq,
    clock,
    collection,
    id,
    kind: 'redacted',
    check: change.check ?? changeCheckValue(change),
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
