// The mailbox: sealed envelopes a device carries for others. Pure functions over an immutable
// value; the clock ("today") and the sender ("from") are parameters. Every operation is linear in
// the size of the mailbox and of what comes in. Wire details: docs/wire-format.md, "Mailbox".
import { base64url, sha256Text } from '../core/encoding.ts';
import { dayNumber, isDay } from '../core/day.ts';
import {
  isKnownEnvelope,
  readEnvelope,
  type Envelope,
  type EnvelopeLimits,
} from '../core/envelope.ts';
import { FORMAT_VERSION, marker } from '../core/markers.ts';
import { field, isDeviceText, isPlain, readBytes } from '../core/secure.ts';
import { FUTURE_DAYS, resolvePostLimits, type PostLimits } from './limits.ts';

/** How many envelopes each other device brought on one day. Null-prototype: a device id is a key. */
export interface Delivered {
  readonly day: string;
  readonly per: Readonly<Record<string, number>>;
}

/** An id that a receipt covered, and the day it was noted (it is forgotten after `postDays`). */
export interface Acknowledged {
  readonly id: string;
  readonly day: string;
}

export interface Mailbox {
  readonly items: readonly Envelope[];
  readonly delivered?: Delivered;
  readonly acknowledged?: readonly Acknowledged[];
}

export const EMPTY_MAILBOX: Mailbox = Object.freeze({ items: Object.freeze([]) });

export type MailboxRefusal = 'bad-day' | 'bad-supplier' | 'too-many' | 'bad-input';

export type AddResult =
  | {
      readonly ok: true;
      /** The same object as before when nothing came in and nothing left. */
      readonly mailbox: Mailbox;
      /** The envelopes that are new in the mailbox now (fresh array). */
      readonly added: readonly Envelope[];
      /** Refused over the other device's quota of the day. */
      readonly rejected: number;
      /** Offered but not a valid envelope of this app (counted, never stored). */
      readonly invalid: number;
    }
  | { readonly ok: false; readonly reason: MailboxRefusal };

const noRecord = (): Record<string, number> => Object.create(null) as Record<string, number>;

/** Day number lookups, cached for one call (a mailbox spans a few dozen different days at most). */
function dayNumbers(): (day: string) => number {
  const cache = new Map<string, number>();
  return (day) => {
    let n = cache.get(day);
    if (n === undefined) {
      n = dayNumber(day);
      cache.set(day, n);
    }
    return n;
  };
}

/** Newest days first; within a day the order is kept. Linear: one bucket per distinct day. */
function newestFirst<T>(items: readonly T[], dayOf: (item: T) => string): T[] {
  const buckets = new Map<string, T[]>();
  for (const item of items) {
    const day = dayOf(item);
    const list = buckets.get(day);
    if (list) list.push(item);
    else buckets.set(day, [item]);
  }
  // ISO days sort like the calendar
  return [...buckets.keys()]
    .sort()
    .reverse()
    .flatMap((day) => buckets.get(day) as T[]);
}

function update(
  appId: string,
  mailbox: Mailbox,
  incoming: readonly Envelope[],
  today: string,
  from: string | undefined,
  lim: PostLimits,
): AddResult {
  if (!isDay(today)) return { ok: false, reason: 'bad-day' };
  if (from !== undefined && !isDeviceText(from)) return { ok: false, reason: 'bad-supplier' };
  if (!Array.isArray(incoming)) return { ok: false, reason: 'bad-input' };
  if (incoming.length > lim.maxEnvelopes) return { ok: false, reason: 'too-many' };
  const dn = dayNumbers();
  const t = dn(today);
  const isCurrent = (day: string): boolean => {
    const age = t - dn(day);
    return age < lim.postDays && age >= -FUTURE_DAYS;
  };
  const acks = (mailbox.acknowledged ?? []).filter((a) => isCurrent(a.day));
  const acked = new Set(acks.map((a) => a.id));
  const kept = mailbox.items.filter((e) => isCurrent(e.day) && !acked.has(e.id));
  const present = new Set(mailbox.items.map((e) => e.id));

  const candidates: Envelope[] = [];
  let invalid = 0;
  for (const item of incoming as readonly unknown[]) {
    const candidate = (typeof item === 'object' && item !== null ? item : {}) as Partial<Envelope>;
    const { id, day } = candidate;
    if (typeof id !== 'string' || typeof day !== 'string' || !isDay(day)) {
      invalid += 1;
      continue;
    }
    if (present.has(id) || acked.has(id) || !isCurrent(day)) continue;
    const envelope = isKnownEnvelope(item, appId) ? item : readEnvelope(appId, candidate.text, lim);
    if (!envelope || envelope.id !== id || envelope.day !== day) {
      invalid += 1;
      continue;
    }
    present.add(id);
    candidates.push(envelope);
  }

  // The quota of the day for the other device that brought them: the newest days first.
  const per = mailbox.delivered?.day === today ? mailbox.delivered.per : noRecord();
  const before = from !== undefined && Object.hasOwn(per, from) ? (per[from] as number) : 0;
  let neu = candidates;
  if (from !== undefined) {
    let free = Math.max(0, lim.maxPerSupplier - before);
    if (!Object.hasOwn(per, from) && Object.keys(per).length >= lim.maxSuppliers) free = 0;
    if (candidates.length > free) neu = newestFirst(candidates, (e) => e.day).slice(0, free);
  }
  const rejected = candidates.length - neu.length;

  const all = neu.length === 0 ? kept : [...kept, ...neu];
  let items = all;
  let stay: Set<string> | undefined;
  let chars = 0;
  for (const e of all) chars += e.text.length;
  if (all.length > lim.maxEnvelopes || chars > lim.maxChars) {
    stay = new Set<string>();
    let count = 0;
    let sum = 0;
    for (const e of newestFirst(all, (x) => x.day)) {
      if (count + 1 > lim.maxEnvelopes || sum + e.text.length > lim.maxChars) break;
      stay.add(e.id);
      count += 1;
      sum += e.text.length;
    }
    const keep = stay;
    items = all.filter((e) => keep.has(e.id));
  }

  // Nothing new, nothing gone: the very same mailbox (whoever watches it is not woken for nothing).
  if (
    neu.length === 0 &&
    items.length === mailbox.items.length &&
    acks.length === (mailbox.acknowledged?.length ?? 0)
  ) {
    return { ok: true, mailbox, added: [], rejected, invalid };
  }
  let delivered = mailbox.delivered;
  if (from !== undefined && neu.length > 0) {
    const next = noRecord();
    for (const key of Object.keys(per)) next[key] = per[key] as number;
    next[from] = before + neu.length;
    delivered = { day: today, per: next };
  }
  const next: Mailbox = {
    items: Object.freeze(items),
    ...(delivered ? { delivered } : {}),
    ...(acks.length > 0 ? { acknowledged: Object.freeze(acks) } : {}),
  };
  const retained = stay ? neu.filter((e) => (stay as Set<string>).has(e.id)) : [...neu];
  return { ok: true, mailbox: next, added: retained, rejected, invalid };
}

/**
 * Takes the envelopes that are not there yet; drops what is too old (`postDays`), from a clock far
 * ahead or acknowledged; keeps the newest `maxEnvelopes` and `maxChars`. `from` = the other device
 * that brought them: at most `maxPerSupplier` new ones a day from it, the newest days first, the rest
 * refused and counted; without `from` (sealed here) there is no quota. Envelopes already there, too
 * old or acknowledged count for nothing. Refusals are codes and change nothing.
 */
export function addEnvelopes(
  appId: string,
  mailbox: Mailbox,
  incoming: readonly Envelope[],
  today: string,
  options: { readonly from?: string; readonly limits?: Partial<PostLimits> } = {},
): AddResult {
  marker(appId, 'post', FORMAT_VERSION);
  return update(appId, mailbox, incoming, today, options.from, resolvePostLimits(options.limits));
}

/** Drops what is too old or acknowledged and trims to the limits; the same object when nothing goes. */
export function pruneMailbox(
  appId: string,
  mailbox: Mailbox,
  today: string,
  limits?: Partial<PostLimits>,
): Mailbox | undefined {
  const result = addEnvelopes(appId, mailbox, [], today, limits ? { limits } : {});
  return result.ok ? result.mailbox : undefined;
}

/** What the other device brought today, per device (an empty record on another day). */
export function deliveredToday(mailbox: Mailbox, today: string): Readonly<Record<string, number>> {
  const out = noRecord();
  if (mailbox.delivered?.day === today) {
    for (const key of Object.keys(mailbox.delivered.per))
      out[key] = mailbox.delivered.per[key] as number;
  }
  return out;
}

/** The mailbox with only its newest `count` envelopes (by day), in their old order. */
export function keepNewest(mailbox: Mailbox, count: number): Mailbox {
  const limit = Math.max(0, Math.floor(Number.isFinite(count) ? count : 0));
  if (mailbox.items.length <= limit) return mailbox;
  const stay = new Set(
    newestFirst(mailbox.items, (e) => e.day)
      .slice(0, limit)
      .map((e) => e.id),
  );
  return { ...mailbox, items: Object.freeze(mailbox.items.filter((e) => stay.has(e.id))) };
}

/**
 * Writes the mailbox with `write`. The mailbox only carries envelopes for others (it is nobody's
 * data), so a store that is full must not refuse what a file brought: when the write fails the
 * mailbox is halved (newest days stay) and tried again, up to 8 times, down to nothing; then the old
 * stored state stays as it was. Returns how many envelopes did not fit (0 = all kept); never throws.
 */
export async function storeMailbox(
  write: (mailbox: Mailbox) => Promise<void> | void,
  mailbox: Mailbox,
): Promise<number> {
  let candidate = mailbox;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      await write(candidate);
      return mailbox.items.length - candidate.items.length;
    } catch {
      if (candidate.items.length === 0) break;
      candidate = keepNewest(candidate, Math.floor(candidate.items.length / 2));
    }
  }
  return mailbox.items.length;
}

// ---- receipts ------------------------------------------------------------------------------

/** "The device `by` took these envelopes in": the app carries receipts in its own data. */
export interface Receipt {
  readonly by: string;
  readonly ids: readonly string[];
}

const isId = (value: unknown): value is string =>
  typeof value === 'string' && readBytes(value, 16, 16) !== undefined;

function exactKeys(value: Record<string, unknown>, names: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  const wanted = [...names].sort();
  return keys.length === wanted.length && keys.every((key, i) => key === wanted[i]);
}

/** Receipts from untrusted data, strictly: fresh copies, or undefined for anything else. */
export function readReceipts(raw: unknown, limits?: Partial<PostLimits>): Receipt[] | undefined {
  const lim = resolvePostLimits(limits);
  if (!Array.isArray(raw) || raw.length > lim.maxReceipts) return undefined;
  const out: Receipt[] = [];
  for (const entry of raw as unknown[]) {
    if (!isPlain(entry) || !exactKeys(entry, ['by', 'ids'])) return undefined;
    const { by, ids } = entry;
    if (!isDeviceText(by) || !Array.isArray(ids) || ids.length > lim.maxReceiptIds) {
      return undefined;
    }
    if (!(ids as unknown[]).every(isId)) return undefined;
    out.push({ by, ids: [...(ids as string[])] });
  }
  return out;
}

export type ReceiptResult =
  | {
      readonly ok: true;
      readonly mailbox: Mailbox;
      /** Envelopes dropped because a receipt covered them. */
      readonly dropped: number;
      /** Receipts that were ignored: malformed or from a device that may not acknowledge. */
      readonly refused: number;
    }
  | { readonly ok: false; readonly reason: MailboxRefusal };

/**
 * Drops what receipts cover. `mayAcknowledge(by)` is the app's decision who may acknowledge (asked
 * once per device; a throwing predicate counts as "no"); the mailbox only drops what an allowed
 * receipt covers. Covered ids are remembered (`maxAcknowledged`, `postDays`) so a neighbour that
 * still holds the envelope cannot hand it back. A receipt cannot drop anything its signer's
 * rights do not allow: the app decides that before it passes the receipt on.
 */
export function applyReceipts(
  appId: string,
  mailbox: Mailbox,
  receipts: readonly Receipt[],
  mayAcknowledge: (by: string) => boolean,
  today: string,
  limits?: Partial<PostLimits>,
): ReceiptResult {
  marker(appId, 'post', FORMAT_VERSION);
  const lim = resolvePostLimits(limits);
  if (!isDay(today)) return { ok: false, reason: 'bad-day' };
  if (typeof mayAcknowledge !== 'function') return { ok: false, reason: 'bad-input' };
  if (!Array.isArray(receipts) || receipts.length > lim.maxReceipts) {
    return { ok: false, reason: 'too-many' };
  }
  const base = update(appId, mailbox, [], today, undefined, lim);
  if (!base.ok) return base;
  const verdicts = new Map<string, boolean>();
  const covered = new Set<string>();
  let refused = 0;
  for (const receipt of receipts as readonly unknown[]) {
    if (!isPlain(receipt) || !isDeviceText(receipt.by)) {
      refused += 1;
      continue;
    }
    const ids = receipt.ids;
    if (!Array.isArray(ids) || ids.length > lim.maxReceiptIds) {
      refused += 1;
      continue;
    }
    let allowed = verdicts.get(receipt.by);
    if (allowed === undefined) {
      try {
        allowed = mayAcknowledge(receipt.by) === true;
      } catch {
        allowed = false;
      }
      verdicts.set(receipt.by, allowed);
    }
    if (!allowed) {
      refused += 1;
      continue;
    }
    for (const id of ids as unknown[]) if (isId(id)) covered.add(id);
  }
  const held = base.mailbox;
  const filtered = held.items.filter((e) => !covered.has(e.id));
  const dropped = held.items.length - filtered.length;
  const items = dropped === 0 ? held.items : filtered;
  const known = new Set((held.acknowledged ?? []).map((a) => a.id));
  const dayOfHeld = new Map(held.items.map((e) => [e.id, e.day] as const));
  const fresh: Acknowledged[] = [];
  for (const id of covered) if (!known.has(id)) fresh.push({ id, day: dayOfHeld.get(id) ?? today });
  if (fresh.length === 0 && dropped === 0) return { ok: true, mailbox: held, dropped, refused };
  let acknowledged: readonly Acknowledged[] = [...(held.acknowledged ?? []), ...fresh];
  if (acknowledged.length > lim.maxAcknowledged) {
    acknowledged = newestFirst(acknowledged, (a) => a.day).slice(0, lim.maxAcknowledged);
  }
  const next: Mailbox = {
    items: Object.freeze(items),
    ...(held.delivered ? { delivered: held.delivered } : {}),
    ...(acknowledged.length > 0 ? { acknowledged: Object.freeze([...acknowledged]) } : {}),
  };
  return { ok: true, mailbox: next, dropped, refused };
}

// ---- check values --------------------------------------------------------------------------

const idsText = (ids: readonly string[]): string =>
  `${ids.length}|${[...ids].sort().map(field).join('|')}`;

/** One check value (22 characters) per day over the ids of its envelopes. */
export function dayChecks(appId: string, mailbox: Mailbox): Record<string, string> {
  const m = marker(appId, 'postday', FORMAT_VERSION);
  const groups = new Map<string, string[]>();
  for (const e of mailbox.items) {
    const list = groups.get(e.day);
    if (list) list.push(e.id);
    else groups.set(e.day, [e.id]);
  }
  const out = Object.create(null) as Record<string, string>;
  for (const day of [...groups.keys()].sort()) {
    out[day] = base64url(
      sha256Text(`${m}|${field(day)}|${idsText(groups.get(day) as string[])}`).slice(0, 16),
    );
  }
  return out;
}

/** One check value for the whole mailbox (22 characters). */
export function mailboxCheck(appId: string, mailbox: Mailbox): string {
  const m = marker(appId, 'postbox', FORMAT_VERSION);
  return base64url(sha256Text(`${m}|${idsText(mailbox.items.map((e) => e.id))}`).slice(0, 16));
}

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

/**
 * What a device announces so that others meet it again when it got an envelope: the fingerprint of
 * the shared data as it is, or, with envelopes, 32 hex digits over fingerprint and mailbox check.
 */
export function announcedStand(appId: string, fingerprint: string, mailbox: Mailbox): string {
  if (mailbox.items.length === 0) return fingerprint;
  const m = marker(appId, 'poststand', FORMAT_VERSION);
  return hex(
    sha256Text(`${m}|${field(fingerprint)}|${field(mailboxCheck(appId, mailbox))}`).slice(0, 16),
  );
}

// ---- stored state --------------------------------------------------------------------------

/**
 * A mailbox from stored JSON (what `JSON.stringify(mailbox)` wrote), strictly: every envelope is read
 * again, no member is unknown, nothing is over a limit; fresh copies. Else undefined.
 */
export function readMailbox(
  appId: string,
  raw: unknown,
  limits?: Partial<PostLimits>,
): Mailbox | undefined {
  marker(appId, 'post', FORMAT_VERSION);
  const lim = resolvePostLimits(limits);
  if (!isPlain(raw) || !Object.hasOwn(raw, 'items')) return undefined;
  if (!Object.keys(raw).every((key) => ['items', 'delivered', 'acknowledged'].includes(key))) {
    return undefined;
  }
  const { items: rawItems, delivered: rawDelivered, acknowledged: rawAcks } = raw;
  if (!Array.isArray(rawItems) || rawItems.length > lim.maxEnvelopes) return undefined;
  const items: Envelope[] = [];
  const seen = new Set<string>();
  let chars = 0;
  for (const entry of rawItems as unknown[]) {
    if (!isPlain(entry) || !exactKeys(entry, ['id', 'day', 'text'])) return undefined;
    const envelope = readEnvelope(appId, entry.text, lim as EnvelopeLimits);
    if (!envelope || envelope.id !== entry.id || envelope.day !== entry.day) return undefined;
    if (seen.has(envelope.id)) return undefined;
    seen.add(envelope.id);
    chars += envelope.text.length;
    items.push(envelope);
  }
  if (chars > lim.maxChars) return undefined;
  let delivered: Delivered | undefined;
  if (rawDelivered !== undefined) {
    if (!isPlain(rawDelivered) || !exactKeys(rawDelivered, ['day', 'per'])) return undefined;
    const { day, per } = rawDelivered;
    if (!isDay(day) || !isPlain(per)) return undefined;
    const keys = Object.keys(per);
    if (keys.length > lim.maxSuppliers) return undefined;
    const copy = noRecord();
    for (const key of keys) {
      const count = per[key];
      if (!isDeviceText(key) || typeof count !== 'number' || !Number.isSafeInteger(count)) {
        return undefined;
      }
      if (count < 0 || count > lim.maxPerSupplier) return undefined;
      copy[key] = count;
    }
    delivered = { day, per: copy };
  }
  let acknowledged: Acknowledged[] | undefined;
  if (rawAcks !== undefined) {
    if (!Array.isArray(rawAcks) || rawAcks.length > lim.maxAcknowledged) return undefined;
    acknowledged = [];
    const ids = new Set<string>();
    for (const entry of rawAcks as unknown[]) {
      if (!isPlain(entry) || !exactKeys(entry, ['id', 'day'])) return undefined;
      const { id, day } = entry;
      if (!isId(id) || !isDay(day) || ids.has(id)) return undefined;
      ids.add(id);
      acknowledged.push({ id, day });
    }
  }
  return {
    items: Object.freeze(items),
    ...(delivered ? { delivered } : {}),
    ...(acknowledged ? { acknowledged: Object.freeze(acknowledged) } : {}),
  };
}
