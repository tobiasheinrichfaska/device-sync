import { FORMAT_VERSION, canonical, marker, signText, verifyText } from '../core/index.ts';
import { changeCheckValue } from './check.ts';
import { merge } from './merge.ts';
import type { Change, DeviceId, Replica } from './types.ts';
import { own } from './validate.ts';

/**
 * How a received change is judged: 'checked' (to be taken), 'pending' (its author cannot be checked
 * yet, or its deletion waits so: not taken, not passed on, it comes again), 'false' (see `judgeChange`).
 */
export type Verdict = 'checked' | 'pending' | 'false';

/**
 * Why a change was judged 'false'. What an app does:
 * - `own-history`: a change under THIS device's own id that this device does not hold: its own state
 *   is older than the world's (a restored backup, a cloned profile). It must stop writing and
 *   enrol again with a NEW device id; writing on would create equivocation.
 * - `equivocation`: the same device and number was signed twice with different content. The author
 *   (`Rejection.change.device`) is faulty or malicious; the app should stop trusting that device
 *   (remove it from the device list). It is only seen when two histories meet in one replica.
 * - the others name the rule that failed: `unsigned`, `bad-check`, `bad-signature`,
 *   `unknown-member` (a member of the change that the signature does not cover), `not-allowed`
 *   (`mayWrite` or `special`), `delete-not-allowed` (no `allowFinalDelete`, or it said no),
 *   `never-erase`, `redacted-without-deletion`.
 */
export type Reason =
  | 'unsigned'
  | 'bad-check'
  | 'bad-signature'
  | 'unknown-member'
  | 'not-allowed'
  | 'delete-not-allowed'
  | 'never-erase'
  | 'redacted-without-deletion'
  | 'equivocation'
  | 'own-history';

/** A verdict with the reason when it is 'false'. */
export interface Judgement {
  readonly verdict: Verdict;
  readonly reason?: Reason;
}

/** A change that was refused and why; `limit` rejections (session limits, quota) have no change reason. */
export interface Rejection {
  readonly change: Change;
  readonly reason: Reason;
}

/** Where the author's public signing key comes from; the trust layer will provide one. */
export interface KeySource {
  /**
   * The key of a device, or undefined when this device cannot check it yet. `acceptedSoFar` is the
   * replica as it would be with everything taken so far (the batch's earlier changes included), so
   * a change that introduces a device can make its later changes checkable.
   */
  keyFor(
    device: DeviceId,
    acceptedSoFar: Replica,
  ): CryptoKey | undefined | Promise<CryptoKey | undefined>;
}

export interface JudgeOptions {
  readonly appId: string;
  /** The data set the changes belong to; a signature names it, so it does not count in another. */
  readonly dataSet: string;
  readonly keys: KeySource;
  /** The receiving device: a change under its id that it does not hold is a forgery. */
  readonly ownDevice?: DeviceId;
  /** Collections whose records are never finally deleted (a 'delete' there is false). */
  readonly neverErase?: readonly string[];
  /**
   * Special case asked first: 'checked' / 'false' / 'pending' decides without a signature (e.g. start
   * data exactly as compiled in); undefined = judge as usual.
   */
  readonly special?: (change: Change) => Verdict | undefined;
  /**
   * Receiver-side right to write: `false` = this author may not write this change. Gets the replica
   * the change is judged against, so a rule can look at the data (e.g. who owns the record).
   */
  readonly mayWrite?: (author: DeviceId, change: Change, state: Replica) => boolean;
  /**
   * Whether this author may delete this record FOR GOOD. A final deletion is irreversible (the id
   * is dead forever, the content is erased on every device) and every member's signature makes one
   * valid, so the default is SAFE: without this hook every final deletion is judged false
   * (`delete-not-allowed`). An app that needs deletions passes a rule (e.g. only the creator, only
   * an administrator).
   */
  readonly allowFinalDelete?: (author: DeviceId, change: Change, state: Replica) => boolean;
  /**
   * The app's tool against a member flooding the log (the log itself is unbounded). Asked while
   * `receiveJudged` buffers a verified change: `count` is how many changes of this author the
   * session holds so far, this one included; `false` ends the session (refusal `too-large`, reason
   * `quota`). Default: unlimited. `mayWrite` bounds what an author may write at all.
   */
  readonly quota?: (author: DeviceId, count: number, state: Replica) => boolean;
}

/** `JudgeOptions` with the replica the changes are judged against (what is known, and for the keys). */
export interface JudgeContext extends JudgeOptions {
  readonly state: Replica;
}

/** A batch sorted out: what to take, what waits, how many are false (then nothing is taken). */
export interface ReadResult {
  readonly accepted: readonly Change[];
  readonly pending: readonly Change[];
  readonly rejected: number;
  /** Every refused change with its reason (empty when nothing was refused). */
  readonly rejections: readonly Rejection[];
}

const idOf = (c: Change): string => `${c.device}#${c.seq}`;

/**
 * The only members a change may have. Anything else is not covered by the signature (it signs the
 * head and the check value of fields, knew, time and by), so it would travel and be stored unchecked.
 */
const CHANGE_MEMBERS: ReadonlySet<string> = new Set([
  'device',
  'seq',
  'clock',
  'collection',
  'id',
  'kind',
  'fields',
  'knew',
  'time',
  'by',
  'check',
  'sig',
]);

/**
 * What is signed: the marker (app, kind 'change', format version), then the canonical form of
 * version, data set, head and the content's check value. A redacted change counts as 'set'. A
 * signature made for one app or data set therefore never verifies in another.
 */
export function changeSigningText(appId: string, change: Change, dataSet: string): string {
  if (typeof dataSet !== 'string' || dataSet.length === 0) {
    throw new TypeError('changeSigningText: the data set must be a non-empty string');
  }
  const { device, seq, clock, collection, id } = change;
  const kind = change.kind === 'redacted' ? 'set' : change.kind;
  const check = change.check ?? changeCheckValue(change);
  const body = canonical({
    v: FORMAT_VERSION,
    set: dataSet,
    device,
    seq,
    clock,
    collection,
    id,
    kind,
    check,
  });
  return `${marker(appId, 'change', FORMAT_VERSION)}|${body}`;
}

/**
 * Signs a change with the author's key and sets `check` (taken now from the content; an erased
 * change keeps the one taken before its content went; with none it cannot be signed and is
 * returned as it is).
 */
export async function signChange(
  appId: string,
  signingKey: CryptoKey,
  change: Change,
  dataSet: string,
): Promise<Change> {
  const check = change.kind === 'redacted' ? change.check : changeCheckValue(change);
  if (!check) return change;
  const withCheck = { ...change, check };
  const sig = await signText(signingKey, changeSigningText(appId, withCheck, dataSet));
  return { ...withCheck, sig };
}

/** This device's own changes without a signature, signed; `insertSignatures` puts them into a replica. */
export async function signOwnChanges(
  appId: string,
  signingKey: CryptoKey,
  replica: Replica,
  dataSet: string,
): Promise<Change[]> {
  const open = replica.log.filter((c) => c.device === replica.device && !c.sig);
  const signed = await Promise.all(open.map((c) => signChange(appId, signingKey, c, dataSet)));
  return signed.filter((c) => c.sig);
}

/**
 * Puts signatures into the log (by device and number), into whatever the replica is by now; also
 * into a write erased meanwhile, when its check value is the one signed.
 */
export function insertSignatures(replica: Replica, signed: readonly Change[]): Replica {
  if (signed.length === 0) return replica;
  const byId = new Map(signed.map((c) => [idOf(c), c]));
  let changed = false;
  const log = replica.log.map((c) => {
    const s = byId.get(idOf(c));
    if (!s?.sig || !s.check || c.sig) return c;
    if (c.kind === 'redacted' && c.check !== s.check) return c;
    changed = true;
    return { ...c, check: s.check, sig: s.sig };
  });
  return changed ? { ...replica, log } : replica;
}

const heldCache = new WeakMap<readonly Change[], Map<string, Change>>();

/** The changes of a log by device and number (kept per log array, which a merge never changes later). */
function heldIn(log: readonly Change[]): Map<string, Change> {
  let held = heldCache.get(log);
  if (!held) {
    held = new Map(log.map((c) => [idOf(c), c]));
    heldCache.set(log, held);
  }
  return held;
}

interface Judged extends Judgement {
  /** The signed text of a verified change: what two versions of one device and number are compared by. */
  readonly text?: string;
}

const no = (reason: Reason): Judged => ({ verdict: 'false', reason });

async function judgeOne(
  context: JudgeContext,
  held: ReadonlyMap<string, Change>,
  change: Change,
): Promise<Judged> {
  if (Object.keys(change).some((member) => !CHANGE_MEMBERS.has(member))) {
    return no('unknown-member');
  }
  const special = context.special?.(change);
  if (special) return special === 'false' ? no('not-allowed') : { verdict: special };
  const known = held.get(idOf(change));
  if (change.device === context.ownDevice && !known) return no('own-history');
  if (!change.sig || !change.check) return no('unsigned');
  if (change.kind === 'delete' && context.neverErase?.includes(change.collection)) {
    return no('never-erase');
  }
  if (change.kind !== 'redacted' && changeCheckValue(change) !== change.check) {
    return no('bad-check');
  }
  const key = await context.keys.keyFor(change.device, context.state);
  if (!key) return { verdict: 'pending' };
  const text = changeSigningText(context.appId, change, context.dataSet);
  if (!(await verifyText(key, text, change.sig))) return no('bad-signature');
  // The same device and number, signed twice with different content: only seen when both meet.
  if (known && changeSigningText(context.appId, known, context.dataSet) !== text) {
    return no('equivocation');
  }
  if (
    change.kind === 'delete' &&
    context.allowFinalDelete?.(change.device, change, context.state) !== true
  ) {
    return no('delete-not-allowed');
  }
  if (context.mayWrite && !context.mayWrite(change.device, change, context.state)) {
    return no('not-allowed');
  }
  return { verdict: 'checked', text };
}

/**
 * Judges each change on its own (see `judgeDetailed` for the order of the rules), and two different
 * versions of one device and number against each other (`seen` holds what the batch, or the
 * session, has verified so far; it is added to).
 */
async function judgeEach(
  context: JudgeContext,
  changes: readonly Change[],
  seen: Map<string, string>,
): Promise<Judged[]> {
  const held = heldIn(context.state.log);
  const judged = await Promise.all(changes.map((c) => judgeOne(context, held, c)));
  return judged.map((j, i) => {
    const change = changes[i] as Change;
    if (j.verdict !== 'checked' || j.text === undefined) return j;
    const before = seen.get(idOf(change));
    if (before !== undefined && before !== j.text) return no('equivocation');
    seen.set(idOf(change), j.text);
    return j;
  });
}

const recordKey = (c: Change): string => JSON.stringify([c.collection, c.id]);

const deletedCache = new WeakMap<readonly Change[], Set<string>>();

/** Whether the replica holds the record's final deletion: in its data or as a change in its log. */
function isDeletedIn(state: Replica, c: Change): boolean {
  if (own(own(state.collections, c.collection), c.id)?.deleted === true) return true;
  let keys = deletedCache.get(state.log);
  if (!keys) {
    keys = new Set(state.log.filter((x) => x.kind === 'delete').map(recordKey));
    deletedCache.set(state.log, keys);
  }
  return keys.has(recordKey(c));
}

const withoutText = ({ verdict, reason }: Judged): Judgement =>
  reason ? { verdict, reason } : { verdict };

/**
 * Judges the changes of one batch, in this order: a member the signature does not cover (false,
 * `unknown-member`); the special case; under the own id without being held here (false,
 * `own-history`); unsigned or without check value (false); final deletion in a `neverErase`
 * collection (false); content not matching its check value (false; an erased change has no content
 * to match); author's key unknown (pending); signature wrong (false); another version of the same
 * device and number, held or in the batch (false, `equivocation`); final deletion without
 * `allowFinalDelete` saying yes (false); not allowed by `mayWrite` (false); else checked. An erased
 * change then counts only beside its record's final deletion (already in the log, or in this batch
 * judged right; one that waits makes it wait), else a forwarder could erase any signed write.
 */
export async function judgeDetailed(
  context: JudgeContext,
  changes: readonly Change[],
): Promise<Judgement[]> {
  const judged = await judgeEach(context, changes, new Map());
  const deletions = new Map<string, Verdict>();
  changes.forEach((c, i) => {
    const v = judged[i]?.verdict;
    if (c.kind !== 'delete' || (v !== 'checked' && v !== 'pending')) return;
    if (deletions.get(recordKey(c)) !== 'checked') deletions.set(recordKey(c), v);
  });
  return judged.map((j, i) => {
    const c = changes[i] as Change;
    if (c.kind !== 'redacted' || j.verdict !== 'checked' || isDeletedIn(context.state, c)) {
      return withoutText(j);
    }
    const d = deletions.get(recordKey(c));
    if (d === 'checked') return withoutText(j);
    return d === 'pending' ? { verdict: 'pending' } : no('redacted-without-deletion');
  });
}

/** The verdicts of `judgeDetailed`. */
export async function judgeChanges(
  context: JudgeContext,
  changes: readonly Change[],
): Promise<Verdict[]> {
  return (await judgeDetailed(context, changes)).map((j) => j.verdict);
}

/**
 * Judges one change on its own: exactly the verdict `judgeChanges(context, [change])` gives it, so a
 * lone erased change counts only if its deletion is already in `context.state`.
 */
export async function judgeChange(context: JudgeContext, change: Change): Promise<Verdict> {
  return (await judgeChanges(context, [change]))[0] ?? 'false';
}

/**
 * What judging has collected of a batch that arrives in pieces: verified changes to take, verified
 * erased changes waiting for their deletion, changes whose author's key is not known yet, and what
 * is needed to keep judging deterministic whatever the order and piece structure.
 */
export interface Judging {
  readonly accepted: readonly Change[];
  readonly erased: readonly Change[];
  readonly pending: readonly Change[];
  /** Records of every verified final deletion so far: carried over all rounds and pieces. */
  readonly deletions: ReadonlySet<string>;
  /** The signed text of every verified change by device and number (to see equivocation). */
  readonly seen: ReadonlyMap<string, string>;
  /** Verified changes per author (for the quota). */
  readonly counts: Readonly<Record<string, number>>;
  /** JSON length of everything held. */
  readonly chars: number;
}

export const emptyJudging = (): Judging => ({
  accepted: [],
  erased: [],
  pending: [],
  deletions: new Set(),
  seen: new Map(),
  counts: {},
  chars: 0,
});

/** Why a piece could not be taken in without judging it any further. */
export type LimitReason = 'session-changes' | 'session-chars' | 'pending-changes' | 'quota';

export interface AdmitLimits {
  readonly maxSessionChanges: number;
  readonly maxSessionChars: number;
  readonly maxPendingChanges: number;
}

export type Admission =
  | { readonly ok: true; readonly judging: Judging }
  | {
      readonly ok: false;
      readonly rejections: readonly Rejection[];
      /** Set when a limit (not a judgement of a change) ended it. */
      readonly limit?: LimitReason;
      /** The author whose change hit the quota. */
      readonly device?: DeviceId;
    };

/** All changes judging holds. */
export const heldCount = (j: Judging): number =>
  j.accepted.length + j.erased.length + j.pending.length;

/**
 * Takes a piece of changes in at once: everything but "is there a deletion beside this erased
 * change" is decided now. A false change refuses the piece (nothing of it is kept); changes that
 * cannot be checked yet go to a small buffer, erased ones to another, verified ones to the third.
 * The limits (changes, JSON size) are checked before any signature work.
 */
export async function admit(
  state: Replica,
  before: Judging,
  changes: readonly Change[],
  options: JudgeOptions,
  limits?: AdmitLimits,
): Promise<Admission> {
  if (limits) {
    if (heldCount(before) + changes.length > limits.maxSessionChanges) {
      return { ok: false, rejections: [], limit: 'session-changes' };
    }
    const size = changes.reduce((sum, c) => sum + JSON.stringify(c).length, 0);
    if (before.chars + size > limits.maxSessionChars) {
      return { ok: false, rejections: [], limit: 'session-chars' };
    }
  }
  const seen = new Map(before.seen);
  const judged = await judgeEach({ ...options, state }, changes, seen);
  const rejections: Rejection[] = [];
  judged.forEach((j, i) => {
    if (j.verdict === 'false') {
      rejections.push({ change: changes[i] as Change, reason: j.reason ?? 'not-allowed' });
    }
  });
  if (rejections.length > 0) return { ok: false, rejections };
  const accepted = [...before.accepted];
  const erased = [...before.erased];
  const pending = [...before.pending];
  const deletions = new Set(before.deletions);
  const counts = { ...before.counts };
  let chars = before.chars;
  for (const [i, j] of judged.entries()) {
    const change = changes[i] as Change;
    chars += JSON.stringify(change).length;
    if (j.verdict === 'pending') {
      pending.push(change);
      if (limits && pending.length > limits.maxPendingChanges) {
        return { ok: false, rejections: [], limit: 'pending-changes' };
      }
      continue;
    }
    counts[change.device] = (counts[change.device] ?? 0) + 1;
    if (options.quota && !options.quota(change.device, counts[change.device] as number, state)) {
      return {
        ok: false,
        rejections: [{ change, reason: 'not-allowed' }],
        limit: 'quota',
        device: change.device,
      };
    }
    if (change.kind === 'redacted') erased.push(change);
    else accepted.push(change);
    if (change.kind === 'delete') deletions.add(recordKey(change));
  }
  return { ok: true, judging: { accepted, erased, pending, deletions, seen, counts, chars } };
}

const refusedResult = (rejections: readonly Rejection[]): ReadResult => ({
  accepted: [],
  pending: [],
  rejected: rejections.length,
  rejections,
});

/**
 * Closes a batch after its last piece: judges what waited for a key against the replica as it would
 * be with everything verified so far (what is taken may make further authors known), and lets an
 * erased change count beside a final deletion that is already in the replica or was verified in ANY
 * earlier round or piece (one that merge holds back for the moment still counts: it comes with the
 * batch). Repeats until nothing more can be decided. One false change and nothing is taken.
 */
export async function settle(
  state: Replica,
  judging: Judging,
  options: JudgeOptions,
): Promise<ReadResult> {
  const seen = new Map(judging.seen);
  const deletions = new Set(judging.deletions);
  const accepted = [...judging.accepted];
  let erased = [...judging.erased];
  let pending = [...judging.pending];
  const taken: Change[] = [];
  for (;;) {
    const now = merge(state, [...accepted, ...taken]).replica;
    let progress = false;
    if (pending.length > 0) {
      const judged = await judgeEach({ ...options, state: now }, pending, seen);
      const rejections: Rejection[] = [];
      judged.forEach((j, i) => {
        if (j.verdict === 'false') {
          rejections.push({ change: pending[i] as Change, reason: j.reason ?? 'not-allowed' });
        }
      });
      if (rejections.length > 0) return refusedResult(rejections);
      const rest: Change[] = [];
      for (const [i, j] of judged.entries()) {
        const change = pending[i] as Change;
        if (j.verdict === 'pending') {
          rest.push(change);
          continue;
        }
        progress = true;
        if (change.kind === 'redacted') erased.push(change);
        else accepted.push(change);
        if (change.kind === 'delete') deletions.add(recordKey(change));
      }
      pending = rest;
    }
    const waiting: Change[] = [];
    for (const change of erased) {
      if (deletions.has(recordKey(change)) || isDeletedIn(now, change)) {
        taken.push(change);
        progress = true;
      } else waiting.push(change);
    }
    erased = waiting;
    if (!progress) break;
  }
  const open = new Set(pending.filter((c) => c.kind === 'delete').map(recordKey));
  const lost = erased.filter((c) => !open.has(recordKey(c)));
  if (lost.length > 0) {
    return refusedResult(
      lost.map((change) => ({ change, reason: 'redacted-without-deletion' as const })),
    );
  }
  return {
    accepted: [...accepted, ...taken],
    pending: [...pending, ...erased],
    rejected: 0,
    rejections: [],
  };
}

/**
 * Judges a whole batch (`admit`, then `settle`): everything is decided from the batch itself, so the
 * verdict does not depend on how the batch was cut or in what order it came, and an honest batch is
 * never refused because of the rounds it takes to check it. One 'false' change and nothing is taken
 * (`rejected` counts them, `rejections` names them). Changes whose author cannot be checked yet are
 * `pending`: not taken, not stored, they must come again.
 */
export async function readChanges(
  replica: Replica,
  changes: readonly Change[],
  options: JudgeOptions,
): Promise<ReadResult> {
  const admission = await admit(replica, emptyJudging(), changes, options);
  if (!admission.ok) return refusedResult(admission.rejections);
  return settle(replica, admission.judging, options);
}
