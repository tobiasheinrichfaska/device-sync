// The answer of a new device to an invitation, carried by the relay (docs/relay-protocol.md, "What the client
// does with it"). The new device has no trust yet: the message is CLEAR text (it holds the new device's
// public introduction and an HMAC proof that only the inviter can check; nothing secret), bounded, sent at
// a limited pace and repeated until its `until` (the invitation's end) or until the app says it arrived.
// A small module the sync driver can call: pure state and decisions, one step that drops, and a reader for
// the inviting device that picks the replies out of what it collected and limits them.
import { FORMAT_VERSION, marker } from '../core/index.ts';
import { RELAY_DEVICE_ID } from './strict.ts';
import type { CollectedMessage } from './readers.ts';
import type { RelayClient } from './client.ts';

export const INVITE_REPLY_LIMITS = {
  /** The reply text of the trust layer (base64url JSON) is at most this long. */
  maxTextChars: 2_000,
  /** A reply is sent at most this often (the relay holds a message 30 s, so one waits at a time). */
  intervalMs: 30_000,
  /** The inviting device takes at most this many replies from one sender in the window … */
  perSenderMax: 5,
  /** … of this length. */
  windowMs: 600_000,
  /** … and at most this many replies from one batch of collected messages. */
  perBatchMax: 20,
  /** Entries the inbox remembers. */
  maxRemembered: 500,
} as const;

const utf8 = new TextEncoder();
const kind = 'invitereply';
const TEXT = /^[A-Za-z0-9_-]+$/;

/** The message the new device drops at the inviter: `{"m":"<app>-invitereply:2","reply":"<text>"}`; undefined for a text that is not a reply text. */
export function encodeInviteReply(appId: string, replyText: string): Uint8Array | undefined {
  if (typeof replyText !== 'string' || replyText.length === 0) return undefined;
  if (replyText.length > INVITE_REPLY_LIMITS.maxTextChars || !TEXT.test(replyText))
    return undefined;
  try {
    return utf8.encode(
      JSON.stringify({ m: marker(appId, kind, FORMAT_VERSION), reply: replyText }),
    );
  } catch {
    return undefined;
  }
}

/** The reply text of a message, or undefined: one spelling only, nothing else is a reply. Never throws. */
export function readInviteReply(appId: string, bytes: Uint8Array): string | undefined {
  try {
    if (!(bytes instanceof Uint8Array) || bytes.length > INVITE_REPLY_LIMITS.maxTextChars + 100) {
      return undefined;
    }
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    const raw: unknown = JSON.parse(text);
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
    const o = raw as Record<string, unknown>;
    const keys = Object.keys(o);
    if (keys.length !== 2 || keys[0] !== 'm' || keys[1] !== 'reply') return undefined;
    if (o['m'] !== marker(appId, kind, FORMAT_VERSION)) return undefined;
    const reply = o['reply'];
    if (typeof reply !== 'string' || reply.length === 0) return undefined;
    if (reply.length > INVITE_REPLY_LIMITS.maxTextChars || !TEXT.test(reply)) return undefined;
    return text === JSON.stringify({ m: o['m'], reply }) ? reply : undefined;
  } catch {
    return undefined;
  }
}

// ── the sender: the new device ────────────────────────────────────────────────────────────────────

/** What the new device keeps while its reply is under way (plain data: the app may store it). */
export interface ReplyState {
  /** The inviter's relay id. */
  readonly to: string;
  /** The reply text of the trust layer. */
  readonly text: string;
  /** The invitation's end (ms since 1970): nothing is sent from then on. */
  readonly until: number;
  readonly sends: number;
  readonly lastSendMs?: number;
  /** The app said it arrived (the inviter took the new device in). */
  readonly acknowledged?: boolean;
}

/** A reply to send to `to` until `until`; undefined when an argument is not what the protocol takes. */
export function startReply(
  appId: string,
  o: { readonly to: string; readonly text: string; readonly until: number },
  nowMs: number,
): ReplyState | undefined {
  if (!RELAY_DEVICE_ID.test(o.to) || encodeInviteReply(appId, o.text) === undefined) {
    return undefined;
  }
  if (!Number.isSafeInteger(o.until) || !Number.isSafeInteger(nowMs) || o.until <= nowMs) {
    return undefined;
  }
  return { to: o.to, text: o.text, until: o.until, sends: 0 };
}

/** The app noticed the reply arrived (the inviter's answer came): no more sends. */
export const acknowledgeReply = (state: ReplyState): ReplyState => ({
  ...state,
  acknowledged: true,
});

export type ReplyAction =
  | { readonly do: 'send' }
  | { readonly do: 'wait'; readonly waitMs: number }
  | { readonly do: 'stop'; readonly reason: 'expired' | 'acknowledged' };

/** What to do now: send, wait this long, or stop. */
export function nextReplyAction(
  state: ReplyState,
  nowMs: number,
  intervalMs: number = INVITE_REPLY_LIMITS.intervalMs,
): ReplyAction {
  if (state.acknowledged === true) return { do: 'stop', reason: 'acknowledged' };
  if (nowMs >= state.until) return { do: 'stop', reason: 'expired' };
  if (state.lastSendMs === undefined || nowMs < state.lastSendMs) return { do: 'send' };
  const wait = state.lastSendMs + intervalMs - nowMs;
  return wait <= 0 ? { do: 'send' } : { do: 'wait', waitMs: wait };
}

export type ReplyStep =
  | { readonly state: ReplyState; readonly done: true; readonly reason: 'expired' | 'acknowledged' }
  | {
      readonly state: ReplyState;
      readonly done: false;
      /** Wait this long before the next step. */
      readonly waitMs: number;
      /** What happened: `sent`, `waited`, or the kind the relay (or the client) failed with. */
      readonly outcome: 'sent' | 'waited' | string;
      /** True when the failure cannot be mended by trying again (the app shows it). */
      readonly final?: true;
    };

/**
 * One step: drops the reply when it is time, at the inviter only. A failure of the net, a busy relay or a
 * rate limit waits (at least the kind's hint) and the next step tries again; a failure that cannot change
 * (the device is not enrolled, blocked, the id is refused) is reported with `final` and sends no more.
 * `sends` counts attempts that went out. Time is a parameter.
 */
export async function stepReply(
  client: Pick<RelayClient, 'drop'>,
  appId: string,
  state: ReplyState,
  nowMs: number,
  intervalMs: number = INVITE_REPLY_LIMITS.intervalMs,
): Promise<ReplyStep> {
  const action = nextReplyAction(state, nowMs, intervalMs);
  if (action.do === 'stop') return { state, done: true, reason: action.reason };
  if (action.do === 'wait') return { state, done: false, waitMs: action.waitMs, outcome: 'waited' };
  const content = encodeInviteReply(appId, state.text);
  if (!content)
    return { state, done: false, waitMs: intervalMs, outcome: 'bad-argument', final: true };
  const r = await client.drop([{ device: state.to, content }]);
  const next: ReplyState = { ...state, sends: state.sends + 1, lastSendMs: nowMs };
  if (!r.ok) {
    if (r.class === 'retry' || r.class === 'refused') {
      return {
        state: next,
        done: false,
        waitMs: Math.max(intervalMs, r.retryAfterMs ?? 0),
        outcome: r.kind,
      };
    }
    return { state: next, done: false, waitMs: intervalMs, outcome: r.kind, final: true };
  }
  const one = r.value.results[0];
  if (one && !one.ok && one.class === 'fatal') {
    return { state: next, done: false, waitMs: intervalMs, outcome: one.kind, final: true };
  }
  // Stored (or refused for now: full mailbox, full sender): the next copy goes after the interval.
  return {
    state: next,
    done: false,
    waitMs: Math.max(intervalMs, one && !one.ok ? (one.retryAfterMs ?? 0) : 0),
    outcome: one && !one.ok ? one.kind : 'sent',
  };
}

// ── the receiver: the inviting device ─────────────────────────────────────────────────────────────

/** What the inviting device remembers of the replies it took (plain data; the app may store it). */
export interface ReplyInbox {
  readonly taken: readonly {
    readonly from: string;
    readonly atMs: number;
    readonly text: string;
  }[];
}

export const emptyReplyInbox: ReplyInbox = { taken: [] };

/**
 * Picks the invitation replies out of collected messages. A reply is taken when it reads strictly, when the
 * sender has not already given `perSenderMax` in the last `windowMs`, when this exact text from this sender
 * is not already remembered, and while the batch has not already given `perBatchMax`; what is over a limit
 * is dropped (it is public, unauthenticated text: the sender can send it again). Messages that are not replies
 * come back in `rest`, in order and untouched, for the rest of the driver. The inbox is bounded and forgets
 * by time. Never throws.
 */
export function takeInviteReplies(
  appId: string,
  messages: readonly CollectedMessage[],
  nowMs: number,
  inbox: ReplyInbox = emptyReplyInbox,
): {
  readonly replies: readonly { readonly from: string; readonly text: string }[];
  readonly rest: readonly CollectedMessage[];
  readonly inbox: ReplyInbox;
} {
  let taken = inbox.taken.filter((t) => t.atMs > nowMs - INVITE_REPLY_LIMITS.windowMs);
  const replies: { from: string; text: string }[] = [];
  const rest: CollectedMessage[] = [];
  for (const m of messages) {
    const text = readInviteReply(appId, m.content);
    if (text === undefined) {
      rest.push(m);
      continue;
    }
    if (replies.length >= INVITE_REPLY_LIMITS.perBatchMax) continue;
    const mine = taken.filter((t) => t.from === m.from);
    if (mine.length >= INVITE_REPLY_LIMITS.perSenderMax) continue;
    if (mine.some((t) => t.text === text)) continue;
    replies.push({ from: m.from, text });
    taken = [...taken, { from: m.from, atMs: nowMs, text }].slice(
      -INVITE_REPLY_LIMITS.maxRemembered,
    );
  }
  return { replies, rest, inbox: { taken } };
}
