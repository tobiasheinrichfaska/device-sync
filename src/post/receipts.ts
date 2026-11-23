// The record of receipts: how an office-like device tells the carriers of the mailbox which envelopes
// it has taken in, so they drop them (`applyReceipts`). The record lives in the app's own data (a
// collection of a data set that the carriers hold), one record per writing device, one field per
// DAY of the carried window with the ids of that day. Days that left the window are cleared (null),
// so the record stays small. Which devices may acknowledge is the app's decision (`mayAcknowledge`),
// and the author of a receipt is the device that signed the write of its field, never a name inside
// the data.
import { dayNumber, isDay } from '../core/day.ts';
import { readBytes } from '../core/secure.ts';
import {
  resolveLimits,
  write,
  type Origin,
  type ParseOptions,
  type Replica,
  type WriteResult,
} from '../log/index.ts';
import { FUTURE_DAYS, resolvePostLimits, type PostLimits } from './limits.ts';
import type { Receipt } from './mailbox.ts';

/** The default collection name of the record. */
export const RECEIPT_COLLECTION = 'receipt';

const isId = (value: unknown): value is string =>
  typeof value === 'string' && readBytes(value, 16, 16) !== undefined;

/** Whether an envelope of `day` is still carried on `today` (the window of the mailbox). */
export function inWindow(day: string, today: string, limits?: Partial<PostLimits>): boolean {
  const age = dayNumber(today) - dayNumber(day);
  return Number.isFinite(age) && age < resolvePostLimits(limits).postDays && age >= -FUTURE_DAYS;
}

export interface ReceiptOptions {
  /** The collection of the record (default `RECEIPT_COLLECTION`). */
  readonly collection?: string;
  readonly limits?: Partial<PostLimits>;
}

/**
 * This device's receipt for the envelopes it took in (`taken`: id and day of each) as a write into its
 * own record: one field per day of the window with the sorted ids of that day (at most `maxReceiptIds`
 * and what one field of the log may hold: 200 with the default limits),
 * days that left the window cleared (null). Nothing is written when the record already stands so
 * (`{ ok: true, replica, written: false }`). Ids of earlier writes of the same day are kept (a receipt
 * grows), ones of days outside the window are not.
 */
export function writeReceiptRecord(
  replica: Replica,
  taken: readonly { readonly id: string; readonly day: string }[],
  today: string,
  origin: Origin = {},
  options: ReceiptOptions & ParseOptions = {},
): WriteResult & { readonly written?: boolean } {
  if (!isDay(today)) return { ok: false, reason: 'invalid-name' };
  const lim = resolvePostLimits(options.limits);
  const collection = options.collection ?? RECEIPT_COLLECTION;
  // what one field of the log may hold: an id is 22 characters plus quotes and a comma
  const log = resolveLimits(options.limits as never);
  const perDay = Math.max(
    1,
    Math.min(lim.maxReceiptIds, log.maxEntries, Math.floor((log.maxValueChars - 2) / 26)),
  );
  const record = replica.collections[collection]?.[replica.device];
  const old = (day: string): readonly string[] => {
    const value = record?.fields[day]?.value;
    return Array.isArray(value) ? (value as unknown[]).filter(isId) : [];
  };
  const days = new Map<string, Set<string>>();
  for (const { id, day } of taken) {
    if (!isId(id) || !isDay(day) || !inWindow(day, today, lim)) continue;
    if (!days.has(day)) days.set(day, new Set(old(day)));
    days.get(day)?.add(id);
  }
  const fields: Record<string, unknown> = {};
  for (const [day, ids] of days) {
    const sorted = [...ids].sort().slice(0, perDay);
    if (JSON.stringify(old(day)) !== JSON.stringify(sorted)) fields[day] = sorted;
  }
  for (const [name, field] of Object.entries(record?.fields ?? {})) {
    if (!days.has(name) && field.value !== null && (!isDay(name) || !inWindow(name, today, lim))) {
      fields[name] = null;
    }
  }
  if (Object.keys(fields).length === 0) return { ok: true, replica, written: false };
  const out = write(replica, collection, replica.device, fields, origin, options);
  return out.ok ? { ...out, written: true } : out;
}

/**
 * Every receipt the replica holds, in the shape `applyReceipts` takes: `by` is the device that wrote
 * the field (the author of the signed change, never a name read from the data), `ids` the ids of the
 * fields it wrote. Records that were finally deleted, fields that are not a day, and values that are
 * not a list of ids count for nothing. At most `maxReceipts` receipts of at most `maxReceiptIds` ids
 * (the rest is left out; the next step brings it again). Sorted, so the answer does not depend on
 * the order of the log.
 */
export function receiptsOf(replica: Replica, options: ReceiptOptions = {}): Receipt[] {
  const lim = resolvePostLimits(options.limits);
  const records = replica.collections[options.collection ?? RECEIPT_COLLECTION] ?? {};
  const byAuthor = new Map<string, Set<string>>();
  for (const record of Object.values(records)) {
    if (record.deleted) continue;
    for (const [name, field] of Object.entries(record.fields)) {
      if (!isDay(name) || !Array.isArray(field.value)) continue;
      const set = byAuthor.get(field.device) ?? new Set<string>();
      for (const id of field.value as unknown[]) if (isId(id)) set.add(id);
      byAuthor.set(field.device, set);
    }
  }
  const out: Receipt[] = [];
  for (const [by, ids] of [...byAuthor].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const list = [...ids].sort();
    for (let i = 0; i < list.length && out.length < lim.maxReceipts; i += lim.maxReceiptIds) {
      out.push({ by, ids: list.slice(i, i + lim.maxReceiptIds) });
    }
  }
  return out;
}
