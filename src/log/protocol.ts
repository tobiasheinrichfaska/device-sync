import { base64url, canonical, sha256Text } from '../core/index.ts';
import { resolveLimits } from './limits.ts';
import { servableTo, tipConflict, tipsOf } from './chain.ts';
import { mergeApproved, type ApprovalOptions, type ApprovalReport } from './approval.ts';
import { merge } from './merge.ts';
import { parseSyncMessage, type ParseOptions, type SyncMessage } from './parse.ts';
import {
  admit,
  emptyJudging,
  settle,
  type Judging,
  type JudgeOptions,
  type Reason,
} from './signing.ts';
import type { Change, DeviceId, MergeResult, Replica, VersionVector } from './types.ts';
import { seen } from './vector.ts';

const utf8 = new TextEncoder();

/** The changes message of one piece. */
export type ChangesMessage = Extract<SyncMessage, { t: 'changes' }>;

/**
 * Changes cut into messages of at most `limits.pieceBytes` (UTF-8 bytes of the JSON) and
 * `limits.maxChanges` changes; always at least one, the last marked. One change larger than the
 * piece size travels alone. `more` marks the last message as a cut answer (more follows later).
 */
export function pieces(
  changes: readonly Change[],
  options: Pick<ParseOptions, 'limits'> = {},
  more = false,
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
  out.push({
    t: 'changes',
    changes: current,
    last: true,
    ...(more ? { more: true as const } : {}),
  });
  return out;
}

const byId = (a: { id: string }, b: { id: string }): number =>
  a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

/**
 * A short fingerprint (32 hex digits, 128 bits) of what a person would see: every collection, every record with
 * its current field values, and which records are deleted. Equal data give equal fingerprints
 * (values are compared in canonical form, so key order does not matter). Different data give
 * different ones except by chance (2^-128): a consistency check, not a proof against a peer that lies.
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
  return Array.from(digest.subarray(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Why a session ended without taking anything: a message that cannot be read, a change that is
 * false (the detail is in `Session.refusalReason`), a message the protocol does not allow at that
 * point (a DIFFERENT second `stand` or `done`; an identical repeat is ignored), or `diverged`: the
 * other's `stand` claims a history that differs from the one held (`tip-mismatch`). `diverged` blames
 * nobody: a tip is an unproven claim (see `proveEquivocation`). Only hostile input is a refusal: a
 * limit of the receiver (changes, size, quota, a stand over `maxStandDevices`) ends the reading
 * early instead (`Session.truncated`) and what was verified is taken.
 */
export type Refusal = 'unreadable' | 'forged' | 'unexpected' | 'diverged';

/**
 * The detail of a refusal: the reason a change was false, what was repeated, or `tip-mismatch` (a
 * stand names another version of a change than the one held; neutral, no culprit: read the notes on
 * `Session.subjectDevice`).
 */
export type RefusalReason =
  Reason | 'unparsable' | 'repeated-stand' | 'repeated-done' | 'tip-mismatch';

/** What a session needs beyond the parser's options. */
export interface SessionOptions extends ParseOptions {
  /**
   * Answer a `stand` only with changes that carry a signature (default true). A device's own
   * changes that are not signed yet would be judged forged by every receiver, and since numbering
   * is gapless the sender would block itself; they wait until signed (`Session.withheld` counts
   * them). Plain, unjudged test sessions pass `false`.
   */
  readonly signedOnly?: boolean;
  /**
   * Hold back until approved (`docs/approval.md`): the changes this session takes in pass through
   * the hook; held ones are kept in `Replica.approval`, not in the log, so the stand and `done` of
   * this device never claim them. Without it a session behaves as before. Pass the same options for
   * every message of a session.
   */
  readonly approval?: ApprovalOptions;
}

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
  /** Changes this device did not send because they carry no signature yet (see `signedOnly`). */
  readonly withheld: number;
  /** The other's `stand` arrived (one per session). */
  readonly standReceived?: boolean;
  /**
   * What `receiveJudged` holds until the last piece arrives: changes already verified (and those
   * waiting for a key or for their deletion). Everything held is bounded by `maxSessionChanges` and
   * `maxSessionChars` in all. A computed view (not copied per piece, not enumerable).
   */
  readonly buffered?: readonly Change[];
  /** JSON length of `buffered`. */
  readonly bufferedChars?: number;
  /**
   * Reading ended early at a limit of this device (changes, size, `quota`, or too many changes still
   * unverifiable): everything verified up to there was taken, the rest comes in a later session.
   */
  readonly truncated?: boolean;
  /** The other device cut its answer at its limit (`more`): another session is needed. */
  readonly peerMore?: boolean;
  /** This device cut its answer at its limit: another session is needed. */
  readonly sentMore?: boolean;
  /** What `receiveJudged` has decided of the pieces so far. */
  readonly judging?: Judging;
  /** Set when a message could not be read or a change was forged: nothing is taken any more. */
  readonly refusal?: Refusal;
  /** Why (see `RefusalReason`; for `own-history` and `equivocation` read the notes on `Reason`). */
  readonly refusalReason?: RefusalReason;
  /**
   * The author of the change that caused a refusal for a reason that comes with a change in hand
   * (`forged` and its reasons, as `equivocation` between two changes this device holds).
   */
  readonly refusalDevice?: DeviceId;
  /** With the reason `field-rules`: the code the app's `FieldRules` answered. */
  readonly refusalDetail?: string;
  /**
   * With the refusal `diverged` (`tip-mismatch`): the device whose HISTORY differs between the two
   * replicas. It does not say who lies: the other side may have invented the tip, or one of the two
   * holds one version of a double signature. An app must not remove or distrust a device because of
   * it; it retries, fetches the other version (`changeAt`) and calls `proveEquivocation`.
   */
  readonly subjectDevice?: DeviceId;
  /** Why the session ended early at a limit of this device (see `truncated`), where the reason is not in `judging`. */
  readonly limit?: 'stand-devices';
  /**
   * With `SessionOptions.approval`: what the hook did with this session's changes so far (held back
   * for approval, applied as erased changes after a rejection, not kept for want of room). Held
   * changes are why the two fingerprints can differ although nothing was cut: compare again after
   * they are decided.
   */
  readonly approvals?: ApprovalReport;
  /** Hash of the `stand` this session received (an identical repeat is ignored, a different one refused). */
  readonly standHash?: string;
  /** Hash of the `done` this session received (likewise). */
  readonly doneHash?: string;
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
    session: { sent: 0, taken: 0, waiting: 0, allReceived: false, ownDone: false, withheld: 0 },
    replica,
    send: [{ t: 'stand', vector: replica.vector, tips: tipsOf(replica) }],
  };
}

const recordKey = (c: Change): string => JSON.stringify([c.collection, c.id]);

/**
 * Leaves out what must not be sent, and with it everything later of the same device (numbering is
 * gapless, a later change could not be applied without it): a change without signature (when
 * `requireSig`), and an erased change whose record's deletion is in `deleteKeys` (a deletion that
 * exists) but is not among what is sent. Repeats until stable, as leaving out a deletion leaves out
 * the erased changes of its record, and with them the later changes of their authors.
 */
function prune(
  list: readonly Change[],
  requireSig: boolean,
  deleteKeys: ReadonlySet<string>,
  vector: VersionVector,
  unsendable: (change: Change) => boolean = () => false,
): Change[] {
  let sent = list;
  for (;;) {
    const present = new Set(sent.filter((c) => c.kind === 'delete').map(recordKey));
    const cut = new Set<DeviceId>();
    // The highest number of each device that is kept so far: what a receiver would hold by then.
    const reach = new Map<DeviceId, number>();
    const reachOf = (device: DeviceId): number =>
      Math.max(seen(vector, device), reach.get(device) ?? 0);
    const out: Change[] = [];
    for (const change of list) {
      if (cut.has(change.device)) continue;
      const key = recordKey(change);
      // A change whose `knew` names something that is not sent could not be applied: the receiver
      // would hold it and nothing would be taken.
      if (
        (requireSig && !change.sig) ||
        unsendable(change) ||
        (change.kind === 'redacted' && deleteKeys.has(key) && !present.has(key)) ||
        Object.entries(change.knew ?? {}).some(([device, n]) => n > reachOf(device))
      ) {
        cut.add(change.device);
        continue;
      }
      out.push(change);
      reach.set(change.device, change.seq);
    }
    if (out.length === sent.length) return out;
    sent = out;
  }
}

/** An erased change whose record is not (finally) deleted here: only an approval rejection makes one. */
function rejectedHere(replica: Replica): (change: Change) => boolean {
  return (change) =>
    change.kind === 'redacted' &&
    replica.collections[change.collection]?.[change.id]?.deleted !== true;
}

/**
 * What the other lacks, in the order of this device's log (so any prefix is applicable: whatever a
 * change depends on was applied here before it): with `signedOnly` (default) only changes that carry
 * a signature; an erased change goes only with its record's deletion (else the receiver would
 * refuse the session and blame the erased change's author); `withheld` counts what was left out for
 * that (and a change whose `knew` names something that is not sent: it could not be applied). The
 * answer is then cut at the receiver-independent session budget (`maxSessionChanges` changes and
 * `maxSessionChars` characters): `more` is true when something that could be sent was not, and the
 * other device asks again in its next session. A cut keeps a gapless prefix of every device, and
 * never an erased change without its deletion.
 *
 * PROGRESS: an answer to a stand contains at least one applicable group of changes whenever any
 * exists, also when that group alone is larger than the budget (an erased change, its author's
 * earlier numbers and the deletion form one group; a single large change is a group of its own). A
 * budget that cut every applicable change away would repeat itself for ever: the other device would
 * ask again and get nothing again.
 */
function answerFor(
  replica: Replica,
  vector: VersionVector,
  options: SessionOptions,
): { readonly changes: Change[]; readonly withheld: number; readonly more: boolean } {
  const limits = resolveLimits(options.limits);
  const missing = replica.log.filter((c) => c.seq > seen(vector, c.device));
  const deleteKeys = new Set(missing.filter((c) => c.kind === 'delete').map(recordKey));
  // A replica that uses an approval hook may hold an erased change of a record that is not deleted
  // (a rejected one): peers would refuse it, so it and what follows it from its author stay here.
  const servable = servableTo(replica, vector);
  const rejected = replica.approval ? rejectedHere(replica) : undefined;
  // A replica that started from a snapshot cannot hand out what lies below its base (`Replica.base`).
  const unsendable =
    replica.base || rejected
      ? (change: Change): boolean => !servable(change) || rejected?.(change) === true
      : undefined;
  const sendable = prune(missing, options.signedOnly !== false, deleteKeys, vector, unsendable);
  const withheld = missing.length - sendable.length;
  let size = 0;
  let count = 0;
  for (const change of sendable) {
    size += JSON.stringify(change).length;
    if (count >= limits.maxSessionChanges || (count > 0 && size > limits.maxSessionChars)) break;
    count += 1;
  }
  if (count === sendable.length) return { changes: sendable, withheld, more: false };
  let cut = prune(sendable.slice(0, count), false, deleteKeys, vector, unsendable);
  if (cut.length === 0) {
    // The budget cut away every applicable change: take the shortest prefix that holds one (what an
    // applicable prefix holds only grows with its length, so a binary search finds it; `sendable`
    // itself is stable under `prune`, so the search ends).
    let low = count + 1;
    let high = sendable.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if (prune(sendable.slice(0, middle), false, deleteKeys, vector, unsendable).length > 0)
        high = middle;
      else low = middle + 1;
    }
    cut = prune(sendable.slice(0, low), false, deleteKeys, vector, unsendable);
  }
  return { changes: cut, withheld, more: cut.length < sendable.length };
}

/**
 * What a received (already parsed) message changes, and what to send in return. A stand is answered
 * with the changes the other lacks (only signed ones, see `SessionOptions.signedOnly`); changes are
 * merged, and after the last piece this device closes with its stand and fingerprint; `done` is
 * remembered for `outcome`. An identical second `stand` or `done` is ignored (a transport duplicate); a
 * different one ends the session (refusal `unexpected`): every `stand` costs an answer. A stand whose
 * tips contradict the log ends it as `diverged` / `tip-mismatch` (no blame). A refused session ignores everything. This variant takes changes
 * as they are: signatures are judged by `receiveJudged`.
 */
export function onSyncMessage(
  session: Session,
  replica: Replica,
  message: SyncMessage,
  options: SessionOptions = {},
): Step {
  if (session.refusal) return { session, replica, send: [] };
  if (message.t === 'overflow') {
    // Well-formed but larger than this device reads: the session ends here, nothing is refused.
    return {
      session: { ...session, truncated: true, limit: 'stand-devices' },
      replica,
      send: [],
    };
  }
  if (message.t === 'stand') {
    const hash = hashOf({ vector: message.vector, tips: message.tips });
    if (session.standReceived) {
      // A transport may deliver a message twice: the same stand again is ignored, another one is not allowed.
      if (session.standHash === hash) return { session, replica, send: [] };
      return refused(session, replica, 'unexpected', 'repeated-stand');
    }
    // A tip that names another version than the one held means the two histories differ. It is a
    // claim, not a proof: it ends the session without naming a culprit (`proveEquivocation`).
    const conflict = tipConflict(replica, message.vector, message.tips);
    if (conflict !== undefined) {
      return refused(session, replica, 'diverged', 'tip-mismatch', undefined, conflict);
    }
    const { changes, withheld, more } = answerFor(replica, message.vector, options);
    return {
      session: {
        ...session,
        sent: session.sent + changes.length,
        withheld: session.withheld + withheld,
        standReceived: true,
        standHash: hash,
        ...(more ? { sentMore: true } : {}),
      },
      replica,
      send: pieces(changes, options, more),
    };
  }
  if (message.t === 'changes') {
    const merged: MergeResult & { readonly approval?: ApprovalReport } = options.approval
      ? mergeApproved(replica, message.changes, options.approval)
      : merge(replica, message.changes);
    const before = session.approvals;
    const next: Session = {
      ...session,
      ...(merged.approval
        ? {
            approvals: {
              held: (before?.held ?? 0) + merged.approval.held,
              rejected: (before?.rejected ?? 0) + merged.approval.rejected,
              dropped: (before?.dropped ?? 0) + merged.approval.dropped,
            },
          }
        : {}),
      taken: session.taken + merged.applied,
      waiting: merged.held.length,
      allReceived: message.last,
      ...(message.last && message.more ? { peerMore: true } : {}),
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
  const hash = hashOf({ vector: message.vector, fingerprint: message.fingerprint });
  if (session.peer) {
    if (session.doneHash === hash) return { session, replica, send: [] };
    return refused(session, replica, 'unexpected', 'repeated-done');
  }
  return {
    session: {
      ...session,
      peer: { vector: message.vector, fingerprint: message.fingerprint },
      doneHash: hash,
    },
    replica,
    send: [],
  };
}

/** A short hash of a message's content, to tell an identical repeat from a different message. */
const hashOf = (value: unknown): string => base64url(sha256Text(canonical(value)));

function refused(
  session: Session,
  replica: Replica,
  refusal: Refusal,
  refusalReason: RefusalReason,
  refusalDevice?: DeviceId,
  subjectDevice?: DeviceId,
  refusalDetail?: string,
): Step {
  const { judging: _j, ...rest } = session;
  return {
    session: {
      ...rest,
      refusal,
      refusalReason,
      ...(refusalDevice ? { refusalDevice } : {}),
      ...(subjectDevice ? { subjectDevice } : {}),
      ...(refusalDetail !== undefined ? { refusalDetail } : {}),
    },
    replica,
    send: [],
  };
}

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
  options: SessionOptions = {},
): Step {
  if (session.refusal) return { session, replica, send: [] };
  const message = parseSyncMessage(raw, options);
  if (!message) return refused(session, replica, 'unreadable', 'unparsable');
  return onSyncMessage(session, replica, message, options);
}

/**
 * Like `receive`, but every change is also judged (signature, check value, rights; see
 * "Signatures"), AS ITS PIECE ARRIVES: whatever can be decided at once is (a change that is
 * unsigned, forged, from an unknown member, equivocating or not allowed ends the session with the
 * refusal `forged` and the reason in `Session.refusalReason`, at the first such piece). Only an
 * erased change waits for its final deletion, which may sit in a later piece, and a change whose
 * author's key is not known yet waits (it may become checkable by a change later in the batch, so
 * while the pieces arrive it is bounded only by the session budget). Nothing is taken before the
 * last piece, and one forged change anywhere means nothing is taken.
 *
 * Limits END THE READING instead of refusing: `maxSessionChanges`, `maxSessionChars` and the
 * `quota` hook cut the session where they are hit (`Session.truncated`), everything verified up to
 * there is taken after the last piece, and the next session continues (a sender cuts its own answers
 * at the same budget and says `more`). The log itself is not bounded (see the docs). Pending
 * changes are not taken and not stored: they count as `waiting` and must come again in a later
 * session; what is still unverifiable after the rounds is cut at `maxPendingChanges`.
 *
 * The judging state is private to the session and extended in place: feed the pieces of a session
 * one after the other, never from an older `Session` value again.
 */
export async function receiveJudged(
  session: Session,
  replica: Replica,
  raw: unknown,
  judge: JudgeOptions,
  options: SessionOptions = {},
): Promise<Step> {
  if (session.refusal) return { session, replica, send: [] };
  const message = parseSyncMessage(raw, options);
  if (!message) return refused(session, replica, 'unreadable', 'unparsable');
  if (message.t !== 'changes') return onSyncMessage(session, replica, message, options);
  if (options.fieldRules && !judge.fieldRules) judge = { ...judge, fieldRules: options.fieldRules };
  const limits = resolveLimits(options.limits);
  const admission = await admit(
    replica,
    session.judging ?? emptyJudging(),
    message.changes,
    judge,
    limits,
  );
  if (!admission.ok) {
    const first = admission.rejections[0];
    return refused(
      session,
      replica,
      'forged',
      first?.reason ?? 'not-allowed',
      first?.change.device,
      undefined,
      first?.detail,
    );
  }
  const judging = admission.judging;
  if (!message.last) return { session: buffering(session, judging), replica, send: [] };
  const { judging: _j, ...open } = session;
  const read = await settle(replica, judging, judge, {
    limits,
    ...(message.more ? { more: true } : {}),
  });
  if (read.rejected > 0) {
    const first = read.rejections[0];
    return refused(
      open,
      replica,
      'forged',
      first?.reason ?? 'not-allowed',
      first?.change.device,
      undefined,
      first?.detail,
    );
  }
  const step = onSyncMessage(
    open,
    replica,
    { t: 'changes', changes: read.accepted, last: true, ...(message.more ? { more: true } : {}) },
    options,
  );
  return {
    ...step,
    session: {
      ...step.session,
      waiting: step.session.waiting + read.pending.length,
      ...(read.truncated ? { truncated: true } : {}),
    },
  };
}

/** The session with its judging; `buffered` is a view of it (copying it per piece made a session quadratic). */
function buffering(session: Session, judging: Judging): Session {
  const next: Session = { ...session, judging };
  Object.defineProperty(next, 'buffered', {
    get: () => [...judging.accepted, ...judging.erased, ...judging.pending],
    configurable: true,
  });
  Object.defineProperty(next, 'bufferedChars', { get: () => judging.chars, configurable: true });
  return next;
}

export interface Outcome {
  /** Both ended with the same data (equal fingerprints). */
  readonly equal: boolean;
  /**
   * Nothing was cut: neither side ended reading early or answered partially. When false the
   * fingerprints are expected to differ and another session continues.
   */
  readonly complete: boolean;
  /**
   * Changes this replica holds back for approval right now (`Replica.approval`, `docs/approval.md`):
   * waiting for a decision, or decided and waiting to be applicable. They are outside the log and the
   * fingerprint, so while `held > 0` unequal fingerprints are expected although `complete` is true:
   * decide them (`approve`, `reject`, `decide`), then compare again; do not run session after session
   * on `!equal` alone. 0 without an approval hook. Only THIS side's holds are counted: the wire does
   * not carry the peer's, so a peer that holds changes can still make `!equal && complete && held === 0`.
   */
  readonly held: number;
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
    complete: !session.truncated && !session.peerMore && !session.sentMore,
    held: replica.approval?.entries.length ?? 0,
    sent: session.sent,
    taken: session.taken,
    fingerprint: own,
    peerFingerprint: session.peer.fingerprint,
  };
}
