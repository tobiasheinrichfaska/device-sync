import { canonical, sha256Text } from '../core/index.ts';
import { resolveLimits } from './limits.ts';
import { merge } from './merge.ts';
import { parseSyncMessage, type ParseOptions, type SyncMessage } from './parse.ts';
import { missingFor } from './replica.ts';
import { readChanges, type JudgeOptions } from './signing.ts';
import type { Change, Replica, VersionVector } from './types.ts';

const utf8 = new TextEncoder();

/** The changes message of one piece. */
export type ChangesMessage = Extract<SyncMessage, { t: 'changes' }>;

/**
 * Changes cut into messages of at most `limits.pieceBytes` (UTF-8 bytes of the JSON) and
 * `limits.maxChanges` changes; always at least one, the last marked. One change larger than the
 * piece size travels alone.
 */
export function pieces(
  changes: readonly Change[],
  options: Pick<ParseOptions, 'limits'> = {},
): ChangesMessage[] {
  const limits = resolveLimits(options.limits);
  const out: ChangesMessage[] = [];
  let current: Change[] = [];
  let size = 0;
  for (const change of changes) {
    const bytes = utf8.encode(JSON.stringify(change)).length + 1;
    if (
      current.length > 0 &&
      (size + bytes > limits.pieceBytes || current.length >= limits.maxChanges)
    ) {
      out.push({ t: 'changes', changes: current, last: false });
      current = [];
      size = 0;
    }
    current.push(change);
    size += bytes;
  }
  out.push({ t: 'changes', changes: current, last: true });
  return out;
}

const byId = (a: { id: string }, b: { id: string }): number =>
  a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

/**
 * A short fingerprint (8 hex digits) of what a person would see: every collection, every record with
 * its current field values, and which records are deleted. Equal data give equal fingerprints
 * (values are compared in canonical form, so key order does not matter). Different data give
 * different ones except by chance: 32 bits, a consistency check and not a proof.
 */
export function fingerprint(replica: Replica): string {
  const view = Object.keys(replica.collections)
    .sort()
    .map((collection) => [
      collection,
      Object.values(replica.collections[collection] ?? {})
        .sort(byId)
        .map((r) =>
          r.deleted
            ? [r.id, 'deleted']
            : [
                r.id,
                Object.keys(r.fields)
                  .sort()
                  .map((field) => [field, r.fields[field]?.value]),
              ],
        ),
    ]);
  const digest = sha256Text(canonical(view));
  return Array.from(digest.subarray(0, 4), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Why a session ended without taking anything further. */
export type Refusal = 'unreadable' | 'forged' | 'too-large';

export interface Session {
  /** Changes this device handed to the other. */
  readonly sent: number;
  /** Changes this device took in. */
  readonly taken: number;
  /** Changes of the last piece that wait for a gap to be filled (not stored). */
  readonly waiting: number;
  /** The other's last piece arrived. */
  readonly allReceived: boolean;
  /** This device has sent its `done` message. */
  readonly ownDone: boolean;
  readonly peer?: { readonly vector: VersionVector; readonly fingerprint: string };
  /** Changes of earlier pieces that `receiveJudged` holds until the last piece arrives. */
  readonly buffered?: readonly Change[];
  /** Set when a message could not be read or a change was forged: nothing is taken any more. */
  readonly refusal?: Refusal;
}

export interface Step {
  readonly session: Session;
  readonly replica: Replica;
  /** Messages to send to the other device, in order. */
  readonly send: readonly SyncMessage[];
}

/** The session opens with this device's stand. */
export function startSession(replica: Replica): Step {
  return {
    session: { sent: 0, taken: 0, waiting: 0, allReceived: false, ownDone: false },
    replica,
    send: [{ t: 'stand', vector: replica.vector }],
  };
}

/**
 * What a received (already parsed) message changes, and what to send in return. A stand is answered
 * with the changes the other lacks; changes are merged, and after the last piece this device closes
 * with its stand and fingerprint; `done` is remembered for `outcome`. A refused session ignores
 * everything. This variant takes changes as they are: signatures are judged by `receiveJudged`.
 */
export function onSyncMessage(
  session: Session,
  replica: Replica,
  message: SyncMessage,
  options: Pick<ParseOptions, 'limits'> = {},
): Step {
  if (session.refusal) return { session, replica, send: [] };
  if (message.t === 'stand') {
    const missing = missingFor(replica, message.vector);
    return {
      session: { ...session, sent: session.sent + missing.length },
      replica,
      send: pieces(missing, options),
    };
  }
  if (message.t === 'changes') {
    const merged = merge(replica, message.changes);
    const next: Session = {
      ...session,
      taken: session.taken + merged.applied,
      waiting: merged.held.length,
      allReceived: message.last,
    };
    if (!message.last || session.ownDone)
      return { session: next, replica: merged.replica, send: [] };
    return {
      session: { ...next, ownDone: true },
      replica: merged.replica,
      send: [
        {
          t: 'done',
          vector: merged.replica.vector,
          fingerprint: fingerprint(merged.replica),
        },
      ],
    };
  }
  return {
    session: { ...session, peer: { vector: message.vector, fingerprint: message.fingerprint } },
    replica,
    send: [],
  };
}

const refused = (session: Session, replica: Replica, refusal: Refusal): Step => {
  const { buffered: _dropped, ...rest } = session;
  return { session: { ...rest, refusal }, replica, send: [] };
};

/**
 * A message as it arrived (any JSON value): read strictly, then `onSyncMessage`. Anything that is
 * not exactly a message, or contains one change that is not exactly a change, ends the session with
 * the refusal `unreadable` and takes NOTHING of it: a half-taken piece would leave a gap in a
 * device's numbering and the stream after it would hang.
 */
export function receive(
  session: Session,
  replica: Replica,
  raw: unknown,
  options: ParseOptions = {},
): Step {
  if (session.refusal) return { session, replica, send: [] };
  const message = parseSyncMessage(raw, options);
  if (!message) return refused(session, replica, 'unreadable');
  return onSyncMessage(session, replica, message, options);
}

/**
 * Like `receive`, but every change is also judged with `readChanges` (signature, check value,
 * rights; see "Signatures"). The pieces of the other's changes are collected first and judged
 * together when the last one arrives: an erased write and its final deletion may sit in different
 * pieces, and a redacted change only counts beside its deletion. One forged change ends the session
 * with the refusal `forged` and nothing is taken. Changes that cannot be checked yet (`pending`: the
 * author's key is unknown) are not taken and not stored; they count as `waiting` and must come
 * again in a later session. More than `limits.maxSessionChanges` collected changes: `too-large`.
 */
export async function receiveJudged(
  session: Session,
  replica: Replica,
  raw: unknown,
  judge: JudgeOptions,
  options: ParseOptions = {},
): Promise<Step> {
  if (session.refusal) return { session, replica, send: [] };
  const message = parseSyncMessage(raw, options);
  if (!message) return refused(session, replica, 'unreadable');
  if (message.t !== 'changes') return onSyncMessage(session, replica, message, options);
  const all = [...(session.buffered ?? []), ...message.changes];
  if (all.length > resolveLimits(options.limits).maxSessionChanges) {
    return refused(session, replica, 'too-large');
  }
  if (!message.last) return { session: { ...session, buffered: all }, replica, send: [] };
  const { buffered: _collected, ...open } = session;
  const read = await readChanges(replica, all, judge);
  if (read.rejected > 0) return refused(open, replica, 'forged');
  const step = onSyncMessage(
    open,
    replica,
    { t: 'changes', changes: read.accepted, last: true },
    options,
  );
  return read.pending.length === 0
    ? step
    : {
        ...step,
        session: { ...step.session, waiting: step.session.waiting + read.pending.length },
      };
}

export interface Outcome {
  /** Both ended with the same data (equal fingerprints). */
  readonly equal: boolean;
  readonly sent: number;
  readonly taken: number;
  readonly fingerprint: string;
  readonly peerFingerprint: string;
}

/** Once both sides closed: did they end with the same data? Undefined before that, and when refused. */
export function outcome(session: Session, replica: Replica): Outcome | undefined {
  if (session.refusal || !session.ownDone || !session.peer) return undefined;
  const own = fingerprint(replica);
  return {
    equal: own === session.peer.fingerprint,
    sent: session.sent,
    taken: session.taken,
    fingerprint: own,
    peerFingerprint: session.peer.fingerprint,
  };
}
