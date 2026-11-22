import { canonical } from '../core/index.ts';
import { originOf } from './merge.ts';
import type { ParseOptions } from './parse.ts';
import { indexOf } from './recordIndex.ts';
import { DELETED_FIELD, findRecord, write, type WriteFailure } from './replica.ts';
import type { Change, DeviceId, FieldValue, Origin, Replica, StoredRecord } from './types.ts';
import { dict } from './validate.ts';
import { isNewer } from './vector.ts';

/**
 * Office review as a derived view of the log (`docs/review.md`). Everything is merged as usual; what an
 * approver wrote is approved, what anybody else wrote is a request until an approver write that knew it
 * settles it. Nothing here is stored: the approved view, the requests, the conflicts and the settled
 * conflicts are pure functions of the replica and of the app's `isApprover`, so every device that holds
 * the same changes derives the same answer, whatever the order of arrival. A decision is an ordinary
 * write (its `knew` names the heads it saw), so it travels and settles the field everywhere.
 *
 * Not the hold-back model of `approval.ts`: this module never reads or writes `Replica.approval`.
 */

/** What the app tells the review. `isApprover` is the only app-specific question. */
export interface ReviewConfig {
  /**
   * Whether a device's writes are approved. A pure function of the device (and of state the app derives
   * from the log, e.g. a role that the trust layer computes): two devices that hold the same changes
   * must answer alike, or their views differ. A throwing answer counts as `false`.
   */
  readonly isApprover: (device: DeviceId) => boolean;
  /** Which collections are reviewed; the others pass the view unchanged and have no requests. Default: all. */
  readonly reviewed?: (collection: string) => boolean;
  /** The soft-delete field of the app's records. Default `DELETED_FIELD`. */
  readonly hiddenField?: string;
}

export type ReviewConflictKind =
  /** Two requests to one field that did not know each other and ask for different values. */
  | 'concurrent-requests'
  /** A request that did not know the field's last approved write. */
  | 'approval-not-known'
  /** Two approved values that did not know each other (several approvers). */
  | 'approver-clash';

/** One value of a field and the write it came from. */
export interface ReviewValue {
  readonly value: unknown;
  readonly device: DeviceId;
  readonly seq: number;
}

/** What one device asks for in one field: its newest write to it. */
export interface ReviewRequest {
  readonly collection: string;
  readonly id: string;
  readonly field: string;
  readonly value: unknown;
  readonly device: DeviceId;
  readonly seq: number;
  readonly time?: number;
  readonly by?: string;
  /** The field's last approved write, if an approver ever wrote it. */
  readonly approved?: ReviewValue;
  readonly conflict?: ReviewConflictKind;
}

export interface ReviewConflict {
  readonly kind: ReviewConflictKind;
  readonly collection: string;
  readonly id: string;
  readonly field: string;
  /** The requests (or, for `approver-clash`, the approved values) that clash, by device. */
  readonly values: readonly ReviewValue[];
  /** The field's last approved write, if any (for `approver-clash` it is one of `values`' rivals). */
  readonly approved?: ReviewValue;
}

/**
 * An approver conflict that an approver write has settled: `value` is that write. A hint for the other
 * approvers ("someone decided this"); it stays derivable, so the app keeps its own list of the ones it
 * showed (key `device#seq`).
 */
export interface ReviewSettlement {
  readonly collection: string;
  readonly id: string;
  readonly field: string;
  readonly value: unknown;
  readonly device: DeviceId;
  readonly seq: number;
  /** The values that clashed before. */
  readonly values: readonly ReviewValue[];
}

export interface ReviewState {
  readonly requests: readonly ReviewRequest[];
  readonly conflicts: readonly ReviewConflict[];
  readonly settlements: readonly ReviewSettlement[];
}

export type ReviewFailure =
  | WriteFailure
  | 'not-approver'
  | 'not-reviewed'
  | 'no-record'
  | 'not-an-approver-clash'
  | 'unknown-value';

export type ReviewWriteResult =
  | { readonly ok: true; readonly replica: Replica }
  | { readonly ok: false; readonly reason: ReviewFailure; readonly detail?: string };

const fail = (reason: ReviewFailure): ReviewWriteResult => ({ ok: false, reason });

interface Context {
  readonly approver: (device: DeviceId) => boolean;
  readonly reviewed: (collection: string) => boolean;
  readonly hidden: string;
}

function contextOf(config: ReviewConfig): Context {
  const memo = new Map<DeviceId, boolean>();
  const reviewed = config.reviewed;
  return {
    approver: (device) => {
      let answer = memo.get(device);
      if (answer === undefined) {
        try {
          answer = config.isApprover(device) === true;
        } catch {
          answer = false;
        }
        memo.set(device, answer);
      }
      return answer;
    },
    reviewed: (collection) => {
      if (!reviewed) return true;
      try {
        return reviewed(collection) === true;
      } catch {
        return false;
      }
    },
    hidden: config.hiddenField ?? DELETED_FIELD,
  };
}

const same = (a: unknown, b: unknown): boolean => {
  try {
    return canonical(a) === canonical(b);
  } catch {
    return false;
  }
};

/** The clock of the write a request came from, for ordering only. */
const clocks = new WeakMap<ReviewRequest, number>();

const ref = (w: FieldWrite): ReviewValue => ({
  value: w.value,
  device: w.change.device,
  seq: w.change.seq,
});

const byDevice = (a: ReviewValue, b: ReviewValue): number =>
  a.device < b.device ? -1 : a.device > b.device ? 1 : a.seq - b.seq;

/** A write to one field and everything its author knew of this field's writes (transitively). */
interface FieldWrite {
  readonly change: Change;
  readonly value: unknown;
  /** Per device, the highest number of that device whose writes to this field the author knew. */
  readonly cov: ReadonlyMap<DeviceId, number>;
}

const knows = (a: FieldWrite, b: FieldWrite): boolean =>
  a.change.device === b.change.device
    ? a.change.seq > b.change.seq
    : (a.cov.get(b.change.device) ?? 0) >= b.change.seq;

const concurrentWrites = (a: FieldWrite, b: FieldWrite): boolean =>
  a.change.device !== b.change.device && !knows(a, b) && !knows(b, a);

const newest = (writes: readonly FieldWrite[]): FieldWrite | undefined =>
  writes.reduce<FieldWrite | undefined>(
    (best, w) => (!best || isNewer(w.change, best.change) ? w : best),
    undefined,
  );

/** The newest write of `list` (ascending by number) whose number is at most `seq`. */
function upTo(list: readonly FieldWrite[], seq: number): FieldWrite | undefined {
  let low = 0;
  let high = list.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if ((list[mid] as FieldWrite).change.seq <= seq) low = mid + 1;
    else high = mid;
  }
  return list[low - 1];
}

const order = (a: Change, b: Change): number =>
  isNewer(a, b) ? 1 : isNewer(b, a) ? -1 : a.device < b.device ? -1 : a.seq - b.seq;

/**
 * All writes to one field of a record, oldest first, each with what its author knew. A `knew` names the
 * heads only (`knownFor`), so what a head knew counts too; the clock order is a causal order (a write's
 * clock is above every clock its author held), so every write a `knew` refers to is already processed.
 */
function fieldWrites(
  changes: readonly Change[],
  field: string,
): { all: FieldWrite[]; perDevice: Map<DeviceId, FieldWrite[]> } {
  const all: FieldWrite[] = [];
  const perDevice = new Map<DeviceId, FieldWrite[]>();
  for (const change of changes) {
    if (!change.fields || !Object.hasOwn(change.fields, field)) continue;
    const mine = perDevice.get(change.device) ?? [];
    const previous = mine[mine.length - 1];
    const cov = new Map<DeviceId, number>(previous?.cov);
    if (previous)
      cov.set(change.device, Math.max(cov.get(change.device) ?? 0, previous.change.seq));
    for (const [device, seq] of Object.entries(change.knew ?? {})) {
      if (seq > (cov.get(device) ?? 0)) cov.set(device, seq);
      const theirs = device === change.device ? undefined : perDevice.get(device);
      const known = theirs && upTo(theirs, seq);
      if (known) {
        for (const [d, s] of known.cov) if (s > (cov.get(d) ?? 0)) cov.set(d, s);
      }
    }
    const entry: FieldWrite = { change, value: change.fields[field], cov };
    mine.push(entry);
    perDevice.set(change.device, mine);
    all.push(entry);
  }
  return { all, perDevice };
}

interface FieldResult {
  readonly requests: ReviewRequest[];
  readonly conflicts: ReviewConflict[];
  readonly settlements: ReviewSettlement[];
}

function reviewField(
  collection: string,
  id: string,
  field: string,
  perDevice: ReadonlyMap<DeviceId, FieldWrite[]>,
  ctx: Context,
  open: boolean,
): FieldResult {
  const out: FieldResult = { requests: [], conflicts: [], settlements: [] };
  const lasts = [...perDevice.values()].map((list) => list[list.length - 1] as FieldWrite);
  const approvers = lasts.filter((w) => ctx.approver(w.change.device));
  const others = lasts.filter((w) => !ctx.approver(w.change.device));
  const approved = newest(approvers);
  const approvedRef = approved && ref(approved);

  // Requests: the newest write of every other device, unless an approved write knew it, asks for what
  // is approved already, or is answered by a newer write that asks for what is approved.
  if (open) {
    const equal = others.filter(
      (w) => approved && !knows(approved, w) && same(approved.value, w.value),
    );
    const pending = others.filter(
      (w) =>
        !(approved && (knows(approved, w) || same(approved.value, w.value))) &&
        !equal.some((e) => knows(e, w)),
    );
    for (const w of pending) {
      const clash = pending.some(
        (b) => b !== w && !same(w.value, b.value) && concurrentWrites(w, b),
      );
      const overtaken = approved !== undefined && !knows(w, approved);
      const conflict: ReviewConflictKind | undefined = clash
        ? 'concurrent-requests'
        : overtaken
          ? 'approval-not-known'
          : undefined;
      const request: ReviewRequest = {
        collection,
        id,
        field,
        value: w.value,
        device: w.change.device,
        seq: w.change.seq,
        ...originOf(w.change),
        ...(approvedRef ? { approved: approvedRef } : {}),
        ...(conflict ? { conflict } : {}),
      };
      clocks.set(request, w.change.clock);
      out.requests.push(request);
    }
    for (const kind of ['concurrent-requests', 'approval-not-known'] as const) {
      const values = out.requests.filter((r) => r.conflict === kind).map(ref2);
      if (values.length > 0) {
        out.conflicts.push({
          kind,
          collection,
          id,
          field,
          values: values.sort(byDevice),
          ...(approvedRef ? { approved: approvedRef } : {}),
        });
      }
    }
  }

  // Several approvers: approved values that did not know each other.
  if (approvers.length > 1) {
    const heads = approvers.filter((w) => !approvers.some((o) => o !== w && knows(o, w)));
    const clashing = heads.filter((w) => heads.some((o) => concurrentWrites(w, o)));
    const first = clashing[0];
    if (first && !clashing.every((w) => same(w.value, first.value))) {
      out.conflicts.push({
        kind: 'approver-clash',
        collection,
        id,
        field,
        values: clashing.map(ref).sort(byDevice),
        ...(approvedRef ? { approved: approvedRef } : {}),
      });
    }
    // A write of an approver that knew such a clash settles it.
    for (const s of approvers) {
      const known: FieldWrite[] = [];
      for (const [device, list] of perDevice) {
        if (!ctx.approver(device)) continue;
        const w =
          device === s.change.device
            ? upTo(list, s.change.seq - 1)
            : upTo(list, s.cov.get(device) ?? 0);
        if (w) known.push(w);
      }
      const settled = known.filter((w) => !known.some((o) => o !== w && knows(o, w)));
      const rivals = settled.filter((w) => settled.some((o) => concurrentWrites(w, o)));
      const one = rivals[0];
      if (one && !rivals.every((w) => same(w.value, one.value))) {
        out.settlements.push({
          collection,
          id,
          field,
          value: s.value,
          device: s.change.device,
          seq: s.change.seq,
          values: rivals.map(ref).sort(byDevice),
        });
      }
    }
  }
  return out;
}

const ref2 = (r: ReviewRequest): ReviewValue => ({ value: r.value, device: r.device, seq: r.seq });

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Everything the review derives, in one pass over the log: the requests (conflicts first, then by
 * collection, record and field, newest first), the conflicts and the settled approver conflicts.
 * Cost: linear in the writes of the reviewed records; a field written by many different devices costs
 * the product of its writes and its writers (the same bound as the notices of `merge`).
 */
export function review(replica: Replica, config: ReviewConfig): ReviewState {
  const ctx = contextOf(config);
  const index = indexOf(replica.log);
  const requests: ReviewRequest[] = [];
  const conflicts: ReviewConflict[] = [];
  const settlements: ReviewSettlement[] = [];
  for (const [collection, records] of Object.entries(replica.collections)) {
    if (!ctx.reviewed(collection)) continue;
    for (const [id, record] of Object.entries(records)) {
      if (record.deleted) continue;
      const recordIndex = index.get(collection)?.get(id);
      if (!recordIndex) continue;
      let changes: Change[] | undefined;
      const hiddenByApprover = isHiddenByApprover(recordIndex.fields.get(ctx.hidden), ctx);
      for (const [field, fieldIndex] of recordIndex.fields) {
        const writers = [...fieldIndex.last.keys()];
        const approving = writers.filter((d) => ctx.approver(d)).length;
        // approvers only and at most one of them: nothing to compare
        if (writers.length === approving && approving < 2) continue;
        changes ??= recordIndex.positions
          .map((p) => replica.log[p] as Change)
          .filter((c) => c.kind === 'set')
          .sort(order);
        const { perDevice } = fieldWrites(changes, field);
        // a record an approver hid: only a request to bring it back is open
        const open = !hiddenByApprover || field === ctx.hidden;
        const result = reviewField(collection, id, field, perDevice, ctx, open);
        requests.push(...result.requests);
        conflicts.push(...result.conflicts);
        settlements.push(...result.settlements);
      }
    }
  }
  const rank = (r: ReviewRequest): number => (r.conflict ? 0 : 1);
  requests.sort(
    (a, b) =>
      rank(a) - rank(b) ||
      cmp(a.collection, b.collection) ||
      cmp(a.id, b.id) ||
      cmp(a.field, b.field) ||
      newerFirst(a, b),
  );
  const key = (x: { collection: string; id: string; field: string }): string[] => [
    x.collection,
    x.id,
    x.field,
  ];
  const byKey = (
    a: ReviewConflict | ReviewSettlement,
    b: ReviewConflict | ReviewSettlement,
  ): number =>
    cmp(key(a)[0] as string, key(b)[0] as string) ||
    cmp(key(a)[1] as string, key(b)[1] as string) ||
    cmp(key(a)[2] as string, key(b)[2] as string);
  conflicts.sort((a, b) => byKey(a, b) || cmp(a.kind, b.kind));
  settlements.sort((a, b) => byKey(a, b) || cmp(a.device, b.device) || a.seq - b.seq);
  return { requests, conflicts, settlements };
}

/** Newest first, in the order that decides values (clock, then device). */
function newerFirst(a: ReviewRequest, b: ReviewRequest): number {
  const x = { clock: clockOf(a), device: a.device };
  const y = { clock: clockOf(b), device: b.device };
  return isNewer(x, y) ? -1 : isNewer(y, x) ? 1 : b.seq - a.seq;
}

const clockOf = (r: ReviewRequest): number => clocks.get(r) ?? 0;

function isHiddenByApprover(
  field: { last: ReadonlyMap<DeviceId, Change> } | undefined,
  ctx: Context,
): boolean {
  if (!field) return false;
  let best: Change | undefined;
  for (const [device, change] of field.last) {
    if (ctx.approver(device) && (!best || isNewer(change, best))) best = change;
  }
  return best?.fields?.[ctx.hidden] === true;
}

/** Every pending request: conflicts first, then by collection, record and field. */
export function reviewRequests(replica: Replica, config: ReviewConfig): ReviewRequest[] {
  return [...review(replica, config).requests];
}

/** The three kinds of conflict, by collection, record and field. */
export function reviewConflicts(replica: Replica, config: ReviewConfig): ReviewConflict[] {
  return [...review(replica, config).conflicts];
}

/** Approver conflicts that an approver write has settled (a hint for the other approvers). */
export function reviewSettlements(replica: Replica, config: ReviewConfig): ReviewSettlement[] {
  return [...review(replica, config).settlements];
}

/**
 * The approved view: a replica whose records hold per field the newest write of an approver. A field no
 * approver wrote is left out, a record no approver wrote is not there, finally deleted records stay
 * deleted, collections that are not reviewed pass unchanged. `notices` is empty (the approved values
 * are what they are). Read it like the replica itself (`visibleRecords`, `valuesOf`).
 */
export function reviewView(replica: Replica, config: ReviewConfig): Replica {
  const ctx = contextOf(config);
  const index = indexOf(replica.log);
  const collections: Record<string, Record<string, StoredRecord>> = dict();
  for (const [collection, records] of Object.entries(replica.collections)) {
    if (!ctx.reviewed(collection)) {
      collections[collection] = records;
      continue;
    }
    const out: Record<string, StoredRecord> = dict();
    for (const [id, record] of Object.entries(records)) {
      if (record.deleted) {
        out[id] = record;
        continue;
      }
      const recordIndex = index.get(collection)?.get(id);
      const fields: Record<string, FieldValue> = dict();
      for (const name of Object.keys(record.fields)) {
        let best: Change | undefined;
        for (const [device, change] of recordIndex?.fields.get(name)?.last ?? []) {
          if (ctx.approver(device) && (!best || isNewer(change, best))) best = change;
        }
        if (!best) continue;
        fields[name] = {
          value: best.fields?.[name],
          clock: best.clock,
          device: best.device,
          seq: best.seq,
          ...originOf(best),
        };
      }
      if (Object.keys(fields).length > 0) out[id] = { id, fields, deleted: false };
    }
    collections[collection] = out;
  }
  return { ...replica, collections, notices: [] };
}

/** The records with a pending request (for markers in the approved view): keys `JSON.stringify([collection, id])`. */
export function recordsWithRequests(requests: readonly ReviewRequest[]): Set<string> {
  return new Set(requests.map((r) => JSON.stringify([r.collection, r.id])));
}

/** How many requests wait: each field counts once. */
export function requestCount(requests: readonly ReviewRequest[]): number {
  return new Set(requests.map((r) => JSON.stringify([r.collection, r.id, r.field]))).size;
}

// ---- decisions: ordinary writes of an approver device ----

interface DecisionOptions {
  readonly origin?: Origin;
  /** `limits`, `deviceId`, `fieldRules` of the app, as for `write`. */
  readonly write?: ParseOptions;
}

function decision(
  replica: Replica,
  config: ReviewConfig,
  collection: string,
  id: string,
  fields: Readonly<Record<string, unknown>>,
  options: DecisionOptions,
): ReviewWriteResult {
  const ctx = contextOf(config);
  if (!ctx.reviewed(collection)) return fail('not-reviewed');
  if (!ctx.approver(replica.device)) return fail('not-approver');
  if (!findRecord(replica, collection, id)) return fail('no-record');
  const result = write(replica, collection, id, fields, options.origin ?? {}, options.write ?? {});
  return result.ok
    ? result
    : { ok: false, reason: result.reason, ...(result.detail ? { detail: result.detail } : {}) };
}

type Target = Pick<ReviewRequest, 'collection' | 'id' | 'field'>;

/** "Take over": the approver writes the request's value. */
export function approveChange(
  replica: Replica,
  request: ReviewRequest,
  config: ReviewConfig,
  options: DecisionOptions = {},
): ReviewWriteResult {
  return decision(
    replica,
    config,
    request.collection,
    request.id,
    { [request.field]: request.value },
    options,
  );
}

/**
 * "Keep": the approver writes the approved value again, knowing the request, which settles it. A field
 * no approver wrote gets `null`; a record no approver wrote at all is hidden (the soft delete, so a new
 * request can still bring it back).
 */
export function keepValue(
  replica: Replica,
  request: ReviewRequest,
  config: ReviewConfig,
  options: DecisionOptions = {},
): ReviewWriteResult {
  const ctx = contextOf(config);
  if (request.approved) {
    return decision(
      replica,
      config,
      request.collection,
      request.id,
      { [request.field]: request.approved.value },
      options,
    );
  }
  const devices = indexOf(replica.log).get(request.collection)?.get(request.id)?.devices;
  const approverKnown = [...(devices ?? [])].some((d) => ctx.approver(d));
  return decision(
    replica,
    config,
    request.collection,
    request.id,
    approverKnown ? { [request.field]: null } : { [request.field]: null, [ctx.hidden]: true },
    options,
  );
}

/** "Correct": the approver writes another value. */
export function correctValue(
  replica: Replica,
  target: Target,
  value: unknown,
  config: ReviewConfig,
  options: DecisionOptions = {},
): ReviewWriteResult {
  return decision(
    replica,
    config,
    target.collection,
    target.id,
    { [target.field]: value },
    options,
  );
}

/**
 * A clash of several approvers: the approver picks which of the values holds. The write knows every
 * value, so it settles the clash here and, once it travels, everywhere.
 */
export function takeApproverValue(
  replica: Replica,
  conflict: ReviewConflict,
  value: unknown,
  config: ReviewConfig,
  options: DecisionOptions = {},
): ReviewWriteResult {
  if (conflict.kind !== 'approver-clash') return fail('not-an-approver-clash');
  if (!conflict.values.some((v) => same(v.value, value))) return fail('unknown-value');
  return decision(
    replica,
    config,
    conflict.collection,
    conflict.id,
    { [conflict.field]: value },
    options,
  );
}

export interface ApproveAllOptions extends DecisionOptions {
  /** Which requests to take (per person or all); default all. */
  readonly select?: (request: ReviewRequest) => boolean;
}

/**
 * "Take all": every request without a conflict, one write per record (newest request of a field first,
 * a field with any conflict is left for one-by-one decisions, also its requests without one).
 * `approved` counts fields taken, `skipped` the requests left because of a conflict, `failed` the
 * fields of writes that were refused.
 */
export function approveAll(
  replica: Replica,
  requests: readonly ReviewRequest[],
  config: ReviewConfig,
  options: ApproveAllOptions = {},
): { replica: Replica; approved: number; skipped: number; failed: number } {
  if (!contextOf(config).approver(replica.device)) {
    return { replica, approved: 0, skipped: requests.length, failed: 0 };
  }
  const fieldKey = (r: Target): string => JSON.stringify([r.collection, r.id, r.field]);
  const contested = new Set(requests.filter((r) => r.conflict).map(fieldKey));
  const perRecord = new Map<
    string,
    { collection: string; id: string; fields: Record<string, unknown> }
  >();
  let skipped = 0;
  for (const r of requests) {
    if (options.select && !options.select(r)) continue;
    if (contested.has(fieldKey(r))) {
      skipped += 1;
      continue;
    }
    const key = JSON.stringify([r.collection, r.id]);
    let entry = perRecord.get(key);
    if (!entry) {
      entry = { collection: r.collection, id: r.id, fields: dict() };
      perRecord.set(key, entry);
    }
    // newest first: two requests to one field without a conflict are a sequence, the newer knew the older
    if (!Object.hasOwn(entry.fields, r.field)) entry.fields[r.field] = r.value;
  }
  let current = replica;
  let approved = 0;
  let failed = 0;
  for (const { collection, id, fields } of perRecord.values()) {
    const done = decision(current, config, collection, id, fields, options);
    const count = Object.keys(fields).length;
    if (done.ok) {
      current = done.replica;
      approved += count;
    } else {
      failed += count;
    }
  }
  return { replica: current, approved, skipped, failed };
}
