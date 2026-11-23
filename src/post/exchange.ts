// The per-day exchange of two devices that meet: a check value per day, the ids of the days that
// differ, then the envelopes the other lacks. Messages are texts in exactly one spelling; the
// session is a value that every step replaces, bounded per message and per session.
// Wire details: docs/wire-format.md, "Mailbox".
import { isDay } from '../core/day.ts';
import { envelopeFromValue, type Envelope } from '../core/envelope.ts';
import { FORMAT_VERSION, marker } from '../core/markers.ts';
import { hasMembers, isDeviceText, isPlain, parseJson, readBytes } from '../core/secure.ts';
import { maxMessageChars, resolvePostLimits, type PostLimits } from './limits.ts';
import {
  addEnvelopes,
  dayChecks,
  pruneMailbox,
  type Mailbox,
  type MailboxRefusal,
} from './mailbox.ts';

export type PostMessage =
  | { readonly t: 'days'; readonly days: Readonly<Record<string, string>> }
  | { readonly t: 'ids'; readonly ids: readonly string[]; readonly last: boolean }
  | { readonly t: 'envelopes'; readonly envelopes: readonly Envelope[]; readonly last: boolean };

const isId = (value: unknown): value is string =>
  typeof value === 'string' && readBytes(value, 16, 16) !== undefined;

/** The wire text of a message: compact JSON, members in this order, days in calendar order. */
export function writePostMessage(appId: string, message: PostMessage): string {
  const head = `{"m":"${marker(appId, 'post', FORMAT_VERSION)}","t":"${message.t}",`;
  if (message.t === 'days') {
    const days = Object.keys(message.days).sort();
    return `${head}"days":{${days.map((d) => `"${d}":"${message.days[d]}"`).join(',')}}}`;
  }
  const last = `"last":${message.last ? 'true' : 'false'}}`;
  if (message.t === 'ids') {
    return `${head}"ids":[${message.ids.map((id) => `"${id}"`).join(',')}],${last}`;
  }
  return `${head}"envelopes":[${message.envelopes.map((e) => e.text).join(',')}],${last}`;
}

/** A message from its wire text, strictly (one spelling, bounded before parsing), else undefined. */
export function readPostMessage(
  appId: string,
  text: unknown,
  limits?: Partial<PostLimits>,
): PostMessage | undefined {
  const m = marker(appId, 'post', FORMAT_VERSION);
  const lim = resolvePostLimits(limits);
  if (typeof text !== 'string' || text.length > maxMessageChars(lim)) return undefined;
  if (!text.startsWith(`{"m":"${m}","t":"`)) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw)) return undefined;
  let message: PostMessage | undefined;
  if (raw.t === 'days' && hasMembers(raw, ['m', 't', 'days'])) {
    const { days } = raw;
    if (!isPlain(days) || Object.keys(days).length > lim.maxDays) return undefined;
    const out = Object.create(null) as Record<string, string>;
    for (const day of Object.keys(days)) {
      const check = days[day];
      if (!isDay(day) || typeof check !== 'string' || !readBytes(check, 16, 16)) return undefined;
      out[day] = check;
    }
    message = { t: 'days', days: out };
  } else if (raw.t === 'ids' && hasMembers(raw, ['m', 't', 'ids', 'last'])) {
    const { ids, last } = raw;
    if (!Array.isArray(ids) || ids.length > lim.maxPerMessage || typeof last !== 'boolean') {
      return undefined;
    }
    if (!(ids as unknown[]).every(isId)) return undefined;
    // only the last piece may be empty: an endless run of empty pieces would keep a session open
    if (ids.length === 0 && !last) return undefined;
    message = { t: 'ids', ids: [...(ids as string[])], last };
  } else if (raw.t === 'envelopes' && hasMembers(raw, ['m', 't', 'envelopes', 'last'])) {
    const { envelopes, last } = raw;
    if (!Array.isArray(envelopes) || envelopes.length > lim.maxPerMessage) return undefined;
    if (typeof last !== 'boolean' || (envelopes.length === 0 && !last)) return undefined;
    const read: Envelope[] = [];
    for (const value of envelopes as unknown[]) {
      const envelope = envelopeFromValue(appId, value, lim);
      if (!envelope) return undefined;
      read.push(envelope);
    }
    message = { t: 'envelopes', envelopes: read, last };
  }
  return message && writePostMessage(appId, message) === text ? message : undefined;
}

interface IdChain {
  readonly ids: readonly string[];
  readonly prev: IdChain | undefined;
}

/** The state of one exchange. Immutable: every step returns the next value. */
export interface PostSession {
  /** The days whose check values differ (known once the other's `days` came). */
  readonly differing: ReadonlySet<string> | undefined;
  readonly theirIds: IdChain | undefined;
  readonly theirCount: number;
  /** The other's last `ids` message came. */
  readonly idsDone: boolean;
  /** This side sent what the other lacks. */
  readonly sent: boolean;
  /** The other's last `envelopes` message came. */
  readonly finished: boolean;
  /** Envelopes that arrived and stayed in the mailbox. */
  readonly taken: number;
  /** Envelopes refused over the other device's quota of the day. */
  readonly rejected: number;
  /** Envelopes offered in all (bounded by `maxEnvelopes`). */
  readonly offered: number;
}

/** Both sides sent what the other lacked and got the other's last piece. */
export const postDone = (session: PostSession): boolean => session.sent && session.finished;

/** Cut into messages of at most `pieceChars` and `maxPerMessage` items; always at least one. */
function cut<T>(items: readonly T[], size: (item: T) => number, lim: PostLimits): T[][] {
  const out: T[][] = [];
  let now: T[] = [];
  let chars = 0;
  for (const item of items) {
    const more = size(item) + 1;
    if (now.length > 0 && (chars + more > lim.pieceChars || now.length >= lim.maxPerMessage)) {
      out.push(now);
      now = [];
      chars = 0;
    }
    now.push(item);
    chars += more;
  }
  out.push(now);
  return out;
}

export type PostStartResult =
  | {
      readonly ok: true;
      readonly session: PostSession;
      /** The mailbox after dropping what is too old (the same object when nothing went). */
      readonly mailbox: Mailbox;
      readonly send: readonly string[];
    }
  | { readonly ok: false; readonly reason: MailboxRefusal };

/** Begins an exchange: drops what is too old and announces a check value per day. */
export function postStart(params: {
  readonly appId: string;
  readonly mailbox: Mailbox;
  readonly today: string;
  readonly limits?: Partial<PostLimits>;
}): PostStartResult {
  const { appId, today } = params;
  const lim = resolvePostLimits(params.limits);
  const mailbox = pruneMailbox(appId, params.mailbox, today, lim);
  if (!mailbox) return { ok: false, reason: 'bad-day' };
  const session: PostSession = {
    differing: undefined,
    theirIds: undefined,
    theirCount: 0,
    idsDone: false,
    sent: false,
    finished: false,
    taken: 0,
    rejected: 0,
    offered: 0,
  };
  return {
    ok: true,
    session,
    mailbox,
    send: [writePostMessage(appId, { t: 'days', days: dayChecks(appId, mailbox) })],
  };
}

export type PostStepRefusal =
  'bad-message' | 'unexpected' | 'too-many-ids' | 'too-many-envelopes' | MailboxRefusal;

export type PostStepResult =
  | {
      readonly ok: true;
      readonly session: PostSession;
      readonly mailbox: Mailbox;
      /** Message texts to send to the other device, in order. */
      readonly send: readonly string[];
      /** Envelopes that arrived in this step and stayed. */
      readonly added: readonly Envelope[];
    }
  | { readonly ok: false; readonly reason: PostStepRefusal };

/**
 * One step: reads the other device's message (a text) and answers. Order is enforced (`days`, then
 * `ids` up to a last one, then `envelopes`, each once); a message out of order, unreadable or over
 * a session limit is a refusal that changes nothing, and the caller ends the session. `from` = the
 * other device (its quota of the day).
 */
export function postStep(params: {
  readonly appId: string;
  readonly session: PostSession;
  readonly mailbox: Mailbox;
  readonly message: string;
  readonly today: string;
  readonly from: string;
  readonly limits?: Partial<PostLimits>;
}): PostStepResult {
  const { appId, session, mailbox, today, from } = params;
  const lim = resolvePostLimits(params.limits);
  const refuse = (reason: PostStepRefusal): PostStepResult => ({ ok: false, reason });
  if (!isDeviceText(from)) return refuse('bad-supplier');
  const message = readPostMessage(appId, params.message, lim);
  if (!message) return refuse('bad-message');
  if (message.t === 'days') {
    if (session.differing) return refuse('unexpected');
    const mine = dayChecks(appId, mailbox);
    const differing = new Set<string>();
    for (const day of [...Object.keys(mine), ...Object.keys(message.days)]) {
      if (mine[day] !== message.days[day]) differing.add(day);
    }
    const ids = mailbox.items.filter((e) => differing.has(e.day)).map((e) => e.id);
    const pieces = cut(ids, () => 24, lim);
    return {
      ok: true,
      session: { ...session, differing },
      mailbox,
      send: pieces.map((piece, i) =>
        writePostMessage(appId, { t: 'ids', ids: piece, last: i === pieces.length - 1 }),
      ),
      added: [],
    };
  }
  if (message.t === 'ids') {
    if (!session.differing || session.idsDone) return refuse('unexpected');
    if (session.theirCount + message.ids.length > lim.maxTheirIds) return refuse('too-many-ids');
    const theirIds: IdChain | undefined =
      message.ids.length > 0 ? { ids: message.ids, prev: session.theirIds } : session.theirIds;
    const next: PostSession = {
      ...session,
      theirIds,
      theirCount: session.theirCount + message.ids.length,
    };
    if (!message.last) return { ok: true, session: next, mailbox, send: [], added: [] };
    const theirs = new Set<string>();
    for (let link = theirIds; link; link = link.prev) for (const id of link.ids) theirs.add(id);
    const lacking = mailbox.items.filter((e) => session.differing?.has(e.day) && !theirs.has(e.id));
    const pieces = cut(lacking, (e) => e.text.length, lim);
    return {
      ok: true,
      session: { ...next, idsDone: true, sent: true },
      mailbox,
      send: pieces.map((piece, i) =>
        writePostMessage(appId, {
          t: 'envelopes',
          envelopes: piece,
          last: i === pieces.length - 1,
        }),
      ),
      added: [],
    };
  }
  if (!session.idsDone || session.finished) return refuse('unexpected');
  if (session.offered + message.envelopes.length > lim.maxEnvelopes) {
    return refuse('too-many-envelopes');
  }
  const result = addEnvelopes(appId, mailbox, message.envelopes, today, { from, limits: lim });
  if (!result.ok) return refuse(result.reason);
  return {
    ok: true,
    session: {
      ...session,
      finished: message.last,
      taken: session.taken + result.added.length,
      rejected: session.rejected + result.rejected,
      offered: session.offered + message.envelopes.length,
    },
    mailbox: result.mailbox,
    send: [],
    added: result.added,
  };
}
