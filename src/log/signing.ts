import { FORMAT_VERSION, canonical, marker, signText, verifyText } from '../core/index.ts';
import { changeCheckValue } from './check.ts';
import { LogCache } from './logCache.ts';
import { merge } from './merge.ts';
import type { Change, DeviceId, Replica } from './types.ts';
import { own } from './validate.ts';

/**
 * How a received change is judged: 'checked' (to be taken), 'pending' (its author cannot be checked
 * yet, or its deletion waits so: not taken, not passed on, it comes again), 'ignored' (its author
 * was removed and the change comes after the removal: not taken, not passed on, NOT a refusal, see
 * `KeySource.standing`) or 'false' (see `judgeChange`).
 */
export type Verdict = 'checked' | 'pending' | 'false' | 'ignored';

/**
 * Why a change was judged 'false' (or 'ignored'). What an app does:
 * - `own-history`: a change under THIS device's own id, correctly signed with its key, that this
 *   device does not hold: its own state is older than the world's (a restored backup, a cloned
 *   profile). It must stop writing and enrol again with a NEW device id; writing on would create
 *   equivocation. It is decided only after the signature verified: an unsigned or forged change
 *   under the own id is `unsigned` / `bad-signature` and says nothing about this device.
 * - `equivocation`: the same device and number was signed twice with different content. The author
 *   (`Rejection.change.device`) is faulty or malicious; the app should stop trusting that device
 *   (remove it from the device list). It is only seen when two histories meet in one replica.
 * - `after-removal` (verdict 'ignored', never a refusal): the change is from a device that was
 *   removed, with a number above the cutoff the key source names.
 * - the others name the rule that failed: `unsigned`, `bad-check`, `bad-signature`,
 *   `unknown-member` (a member of the change that the signature does not cover; an erased change
 *   may only have device, seq, clock, collection, id, kind, check and sig), `not-allowed`
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
  | 'own-history'
  | 'after-removal';

/** A verdict with the reason when it is 'false' (or 'ignored'). */
export interface Judgement {
  readonly verdict: Verdict;
  readonly reason?: Reason;
}

/** A change that was refused and why. */
export interface Rejection {
  readonly change: Change;
  readonly reason: Reason;
}

/** What a key source knows of one device: its key and, once it was removed, the last number still valid. */
export interface Standing {
  /** The device's public signing key; when absent `KeySource.keyFor` is asked. */
  readonly key?: CryptoKey | undefined;
  /**
   * When a number: changes of the device with `seq` above it are 'ignored' (reason `after-removal`):
   * not taken, not forwarded, not a refusal, the session goes on. The device's entry in the version
   * vector does not advance past the gap, so the sender offers them again in every session (they
   * cost the sender some bandwidth, nothing else). Changes up to the cutoff are judged as usual.
   */
  readonly cutoff?: number | undefined;
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
  /**
   * Optional: the device's key and removal cutoff (see `Standing`), for the replica as it would be
   * with everything taken so far. Without it only `keyFor` is used.
   */
  standing?(device: DeviceId, acceptedSoFar: Replica): Standing | Promise<Standing>;
  /**
   * Optional: collections whose records are never finally deleted (e.g. the device list itself);
   * merged into `JudgeOptions.neverErase`.
   */
  readonly neverErase?: readonly string[];
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
   * session holds so far, this one included; `false` ENDS THE READING of the session (it is
   * `truncated`, everything verified so far is taken, the next session continues; not a refusal).
   * Default: unlimited. `mayWrite` bounds what an author may write at all.
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
  /** Changes of removed devices after their cutoff (verdict 'ignored'): not taken, no refusal. */
  readonly ignored: number;
  /** Reading ended early at a limit, or what is still unverifiable was cut at `maxPendingChanges`. */
  readonly truncated: boolean;
}

const idOf = (c: Change): string => `${c.device}#${c.seq}`;

const COMMON_MEMBERS = ['device', 'seq', 'clock', 'collection', 'id', 'kind', 'check', 'sig'];

/**
 * The only members a change may have. Anything else is not covered by the signature (it signs the
 * head and the check value of fields, knew, time and by), so it would travel and be stored unchecked.
 */
const CHANGE_MEMBERS: ReadonlySet<string> = new Set([
  ...COMMON_MEMBERS,
  'fields',
  'knew',
  'time',
  'by',
]);

/**
 * An erased change keeps only the head, the check value and the signature (what `merge` makes of
 * it): `time`, `by` and `knew` are not covered by the signature and would be stored and forwarded.
 */
const REDACTED_MEMBERS: ReadonlySet<string> = new Set(COMMON_MEMBERS);

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

const heldCache = new LogCache<Map<string, Change>>();

/** The changes of a log by device and number (kept per log array, which a merge never changes later). */
function heldIn(log: readonly Change[]): Map<string, Change> {
  return heldCache.getOrBuild(log, () => new Map(log.map((c) => [idOf(c), c])));
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
  const members = change.kind === 'redacted' ? REDACTED_MEMBERS : CHANGE_MEMBERS;
  if (Object.keys(change).some((member) => !members.has(member))) {
    return no('unknown-member');
  }
  const special = context.special?.(change);
  if (special) return special === 'false' ? no('not-allowed') : { verdict: special };
  const standing = await context.keys.standing?.(change.device, context.state);
  if (typeof standing?.cutoff === 'number' && change.seq > standing.cutoff) {
    return { verdict: 'ignored', reason: 'after-removal' };
  }
  const known = held.get(idOf(change));
  if (!change.sig || !change.check) return no('unsigned');
  if (
    change.kind === 'delete' &&
    (context.neverErase?.includes(change.collection) ||
      context.keys.neverErase?.includes(change.collection))
  ) {
    return no('never-erase');
  }
  if (change.kind !== 'redacted' && changeCheckValue(change) !== change.check) {
    return no('bad-check');
  }
  const key = standing?.key ?? (await context.keys.keyFor(change.device, context.state));
  if (!key) return { verdict: 'pending' };
  const text = changeSigningText(context.appId, change, context.dataSet);
  // The very change (same signed text, same signature) this replica holds was verified when it was
  // taken: a repeat costs no second signature check (a peer can only repeat what it was given).
  const repeat =
    known !== undefined &&
    known.sig === change.sig &&
    changeSigningText(context.appId, known, context.dataSet) === text;
  if (!repeat && !(await verifyText(key, text, change.sig))) return no('bad-signature');
  // Only a change that really carries this device's signature proves its own state is behind.
  if (change.device === context.ownDevice && !known) return no('own-history');
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

const deletedCache = new LogCache<Set<string>>();

/** Whether the replica holds the record's final deletion: in its data or as a change in its log. */
function isDeletedIn(state: Replica, c: Change): boolean {
  if (own(own(state.collections, c.collection), c.id)?.deleted === true) return true;
  const keys = deletedCache.getOrBuild(
    state.log,
    () => new Set(state.log.filter((x) => x.kind === 'delete').map(recordKey)),
  );
  return keys.has(recordKey(c));
}

/**
 * The erased changes of `candidates` that are really applied beside their record's final deletion
 * when `base` and they are merged into `state`: the greatest set that is consistent with itself.
 * An erased change fills the gap of its own number (so a deletion right after it applies), but one
 * whose deletion merge holds back (a gap, a missing `knew`, a clock jump) is left out, and so is
 * every deletion that only applied by the help of an erased change that was left out.
 */
function appliedErasures(
  state: Replica,
  base: readonly Change[],
  candidates: readonly Change[],
): Set<Change> {
  let erased = candidates;
  for (;;) {
    const now = merge(state, [...base, ...erased]).replica;
    const next = erased.filter((c) => isDeletedIn(now, c));
    if (next.length === erased.length) return new Set(erased);
    erased = next;
  }
}

const withoutText = ({ verdict, reason }: Judged): Judgement =>
  reason ? { verdict, reason } : { verdict };

/**
 * Judges the changes of one batch, in this order: a member the signature does not cover (false,
 * `unknown-member`); the special case; a device removed earlier and a number above its cutoff
 * (ignored, `after-removal`); unsigned or without check value (false); final deletion in a
 * `neverErase` collection (false); content not matching its check value (false; an erased change
 * has no content to match); author's key unknown (pending); signature wrong (false); under the own id
 * without being held here (false, `own-history`); another version of the same device and number,
 * held or in the batch (false, `equivocation`); final deletion without `allowFinalDelete` saying yes
 * (false); not allowed by `mayWrite` (false); else checked. An erased change then counts only
 * beside its record's final deletion that is, in the replica as it would be with the batch's
 * verified changes merged, REALLY APPLIED (or already in the log); a deletion that is judged right
 * but that `merge` holds back (a gap, a missing `knew`, a clock jump) or that waits for a key makes
 * the erased change wait, else a forwarder could erase a signed write and keep the deletion away.
 */
export async function judgeDetailed(
  context: JudgeContext,
  changes: readonly Change[],
): Promise<Judgement[]> {
  const judged = await judgeEach(context, changes, new Map());
  const deletions = new Set<string>();
  const erased = changes.filter(
    (c, i) => c.kind === 'redacted' && judged[i]?.verdict === 'checked',
  );
  changes.forEach((c, i) => {
    const v = judged[i]?.verdict;
    if (c.kind === 'delete' && v !== 'false') deletions.add(recordKey(c));
  });
  const applied =
    erased.length === 0
      ? new Set<Change>()
      : appliedErasures(
          context.state,
          changes.filter((c, i) => c.kind !== 'redacted' && judged[i]?.verdict === 'checked'),
          erased,
        );
  return judged.map((j, i) => {
    const c = changes[i] as Change;
    if (c.kind !== 'redacted' || j.verdict !== 'checked' || applied.has(c)) return withoutText(j);
    return deletions.has(recordKey(c)) ? { verdict: 'pending' } : no('redacted-without-deletion');
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

/** Why reading a session ended early. */
export type LimitReason = 'session-changes' | 'session-chars' | 'quota';

/**
 * What judging has collected of a batch that arrives in pieces: verified changes to take, verified
 * erased changes waiting for their deletion, changes whose author's key is not known yet, and what
 * is needed to keep judging deterministic whatever the order and piece structure.
 *
 * It is PRIVATE TO ITS SESSION: `admit` adds to these collections in place (copying them per piece
 * made a long session quadratic), so a `Judging` is fed one piece after the other and never forked.
 */
export interface Judging {
  readonly accepted: Change[];
  readonly erased: Change[];
  readonly pending: Change[];
  /** Records of every verified final deletion so far: carried over all rounds and pieces. */
  readonly deletions: Set<string>;
  /** Records whose final deletion was 'ignored' (after a removal): their erased changes wait, unblamed. */
  readonly ignoredDeletions: Set<string>;
  /** The signed text of every verified change by device and number (to see equivocation). */
  readonly seen: Map<string, string>;
  /** Verified changes per author (for the quota). A Map: any device id is an ordinary key. */
  readonly counts: Map<string, number>;
  /** JSON length of everything held. */
  chars: number;
  /** Changes judged 'ignored' so far. */
  ignored: number;
  /** Reading has ended at a limit: later pieces are skipped, what is held is settled and taken. */
  truncated: boolean;
  /** Which limit ended it. */
  limit?: LimitReason;
}

export const emptyJudging = (): Judging => ({
  accepted: [],
  erased: [],
  pending: [],
  deletions: new Set(),
  ignoredDeletions: new Set(),
  seen: new Map(),
  counts: new Map(),
  chars: 0,
  ignored: 0,
  truncated: false,
});

export interface AdmitLimits {
  readonly maxSessionChanges: number;
  readonly maxSessionChars: number;
  /** What may still be unverifiable AFTER the key-learning rounds (see `settle`). */
  readonly maxPendingChanges: number;
}

export type Admission =
  | { readonly ok: true; readonly judging: Judging }
  | { readonly ok: false; readonly rejections: readonly Rejection[] };

/** All changes judging holds. */
export const heldCount = (j: Judging): number =>
  j.accepted.length + j.erased.length + j.pending.length;

/**
 * Takes a piece of changes in at once: everything but "is there a deletion beside this erased
 * change" is decided now. A false change refuses the piece; changes that cannot be checked yet go
 * to a buffer (bounded only by the session's overall size: authors a later change of the batch
 * introduces must fit, the pending cap applies after the rounds, see `settle`), erased ones to
 * another, verified ones to the third.
 *
 * The session limits END THE READING instead of refusing: a piece is cut where `maxSessionChanges`
 * or `maxSessionChars` would be exceeded (before any signature work), or where the `quota` hook says
 * no; the judging is then `truncated`, the rest of the piece and every later piece are skipped, and
 * what was verified is taken. Only a hostile change (a false verdict) is a refusal.
 */
export async function admit(
  state: Replica,
  judging: Judging,
  changes: readonly Change[],
  options: JudgeOptions,
  limits?: AdmitLimits,
): Promise<Admission> {
  if (judging.truncated) return { ok: true, judging };
  const sizes: number[] = [];
  let cut: LimitReason | undefined;
  let chars = judging.chars;
  const room = limits ? limits.maxSessionChanges - heldCount(judging) : Infinity;
  for (const change of changes) {
    const size = JSON.stringify(change).length;
    if (sizes.length >= room) cut = 'session-changes';
    else if (limits && chars + size > limits.maxSessionChars) cut = 'session-chars';
    if (cut) break;
    sizes.push(size);
    chars += size;
  }
  const kept = sizes.length === changes.length ? changes : changes.slice(0, sizes.length);
  const judged = await judgeEach({ ...options, state }, kept, judging.seen);
  const rejections: Rejection[] = [];
  judged.forEach((j, i) => {
    if (j.verdict === 'false') {
      rejections.push({ change: kept[i] as Change, reason: j.reason ?? 'not-allowed' });
    }
  });
  if (rejections.length > 0) return { ok: false, rejections };
  for (const [i, j] of judged.entries()) {
    const change = kept[i] as Change;
    if (j.verdict === 'ignored') {
      judging.ignored += 1;
      if (change.kind === 'delete') judging.ignoredDeletions.add(recordKey(change));
      continue;
    }
    if (j.verdict === 'pending') {
      judging.pending.push(change);
    } else {
      const count = (judging.counts.get(change.device) ?? 0) + 1;
      if (options.quota && !options.quota(change.device, count, state)) {
        cut = 'quota';
        break;
      }
      judging.counts.set(change.device, count);
      if (change.kind === 'redacted') judging.erased.push(change);
      else judging.accepted.push(change);
      if (change.kind === 'delete') judging.deletions.add(recordKey(change));
    }
    judging.chars += sizes[i] as number;
  }
  if (cut) {
    judging.truncated = true;
    judging.limit = cut;
  }
  return { ok: true, judging };
}

const refusedResult = (rejections: readonly Rejection[]): ReadResult => ({
  accepted: [],
  pending: [],
  rejected: rejections.length,
  rejections,
  ignored: 0,
  truncated: false,
});

const byDeviceSeq = (a: Change, b: Change): number =>
  a.device < b.device ? -1 : a.device > b.device ? 1 : a.seq - b.seq;

export interface SettleOptions {
  /** `maxPendingChanges` caps what is still unverifiable once the rounds are over. */
  readonly limits?: AdmitLimits;
  /** The sender said more is to come (`more`): an erased change without its deletion may be a cut, not a forgery. */
  readonly more?: boolean;
}

/**
 * Closes a batch after its last piece: judges what waited for a key against the replica as it would
 * be with everything verified so far (what is taken may make further authors known), and lets an
 * erased change count only beside a final deletion that is REALLY APPLIED in that replica (a
 * deletion that merge holds back, for a gap, a missing `knew` or a clock jump, leaves the erased
 * change waiting). Repeats until nothing more can be decided. One false change and nothing is taken.
 *
 * What is still unverifiable at the end is capped at `limits.maxPendingChanges` (cut, and the result
 * `truncated`), not refused. A `quota` that says no for an author while pending changes become
 * verifiable stops taking that author's further changes (`truncated`). An erased change whose
 * deletion was never seen is a forgery (refusal `redacted-without-deletion`) unless the batch is
 * partial (`truncated`, or `more`), where it may be a cut and simply waits.
 */
export async function settle(
  state: Replica,
  judging: Judging,
  options: JudgeOptions,
  config: SettleOptions = {},
): Promise<ReadResult> {
  const seen = new Map(judging.seen);
  const counts = new Map(judging.counts);
  const deletions = new Set(judging.deletions);
  const ignoredDeletions = new Set(judging.ignoredDeletions);
  const accepted = [...judging.accepted];
  let erased = [...judging.erased];
  let pending = [...judging.pending];
  let ignored = judging.ignored;
  let truncated = judging.truncated;
  const blocked = new Set<DeviceId>();
  const dropped: Change[] = [];
  let taken: Change[] = [];
  for (;;) {
    const upTo = merge(state, [...accepted, ...taken]).replica;
    let progress = false;
    if (pending.length > 0) {
      const judged = await judgeEach({ ...options, state: upTo }, pending, seen);
      const rejections: Rejection[] = [];
      judged.forEach((j, i) => {
        if (j.verdict === 'false') {
          rejections.push({ change: pending[i] as Change, reason: j.reason ?? 'not-allowed' });
        }
      });
      if (rejections.length > 0) return refusedResult(rejections);
      const rest: Change[] = [];
      const verified: Change[] = [];
      for (const [i, j] of judged.entries()) {
        const change = pending[i] as Change;
        if (j.verdict === 'pending') {
          rest.push(change);
          continue;
        }
        progress = true;
        if (j.verdict === 'ignored') {
          ignored += 1;
          if (change.kind === 'delete') ignoredDeletions.add(recordKey(change));
        } else verified.push(change);
      }
      // By device and number, so a quota that ends one author keeps a gapless prefix of it.
      for (const change of verified.sort(byDeviceSeq)) {
        const count = (counts.get(change.device) ?? 0) + 1;
        if (
          blocked.has(change.device) ||
          (options.quota && !options.quota(change.device, count, state))
        ) {
          blocked.add(change.device);
          dropped.push(change);
          truncated = true;
          continue;
        }
        counts.set(change.device, count);
        if (change.kind === 'redacted') erased.push(change);
        else accepted.push(change);
        if (change.kind === 'delete') deletions.add(recordKey(change));
      }
      pending = rest;
    }
    // What was taken stays taken: more verified changes only make a deletion more likely to apply.
    const candidates = [...taken, ...erased];
    if (candidates.length > 0) {
      const applied = appliedErasures(state, accepted, candidates);
      const now = candidates.filter((c) => applied.has(c));
      if (now.length > taken.length) progress = true;
      taken = now;
      erased = candidates.filter((c) => !applied.has(c));
    }
    if (!progress) break;
  }
  const open = new Set(pending.filter((c) => c.kind === 'delete').map(recordKey));
  const lost = erased.filter(
    (c) =>
      !open.has(recordKey(c)) &&
      !deletions.has(recordKey(c)) &&
      !ignoredDeletions.has(recordKey(c)),
  );
  if (lost.length > 0 && !truncated && config.more !== true) {
    return refusedResult(
      lost.map((change) => ({ change, reason: 'redacted-without-deletion' as const })),
    );
  }
  let waitingChanges = [...pending, ...erased, ...dropped];
  const cap = config.limits?.maxPendingChanges;
  if (cap !== undefined && waitingChanges.length > cap) {
    waitingChanges = waitingChanges.slice(0, cap);
    truncated = true;
  }
  return {
    accepted: [...accepted, ...taken],
    pending: waitingChanges,
    rejected: 0,
    rejections: [],
    ignored,
    truncated,
  };
}

/**
 * Judges a whole batch (`admit`, then `settle`): everything is decided from the batch itself, so the
 * verdict does not depend on how the batch was cut or in what order it came, and an honest batch is
 * never refused because of the rounds it takes to check it. One 'false' change and nothing is taken
 * (`rejected` counts them, `rejections` names them). Changes whose author cannot be checked yet are
 * `pending`: not taken, not stored, they must come again. Without `limits` nothing is cut.
 */
export async function readChanges(
  replica: Replica,
  changes: readonly Change[],
  options: JudgeOptions,
  limits?: AdmitLimits,
): Promise<ReadResult> {
  const admission = await admit(replica, emptyJudging(), changes, options, limits);
  if (!admission.ok) return refusedResult(admission.rejections);
  return settle(replica, admission.judging, options, limits ? { limits } : {});
}
