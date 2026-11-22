import { FORMAT_VERSION, canonical, marker, signText, verifyText } from '../core/index.ts';
import { heldIn, idOf } from './chain.ts';
import { changeCheckValue, changeLink } from './check.ts';
import { LogCache } from './logCache.ts';
import { merge } from './merge.ts';
import { checkRights, type RightsOptions } from './rights.ts';
import type { Change, DeviceId, FieldRules, Replica } from './types.ts';
import { own, ruleAnswer } from './validate.ts';
import { seen as seenIn } from './vector.ts';

/**
 * How a received change is judged: 'checked' (to be taken), 'pending' (its author cannot be checked
 * yet, or its deletion waits so: not taken, not passed on, it comes again) or 'false' (see
 * `judgeChange`).
 */
export type Verdict = 'checked' | 'pending' | 'false';

/**
 * Why a change was judged 'false'. What an app does:
 * - `own-history`: a change under THIS device's own id, correctly signed with its key, that this
 *   device does not hold: its own state is older than the world's (a restored backup, a cloned
 *   profile). It must stop writing and enrol again with a NEW device id; writing on would create
 *   equivocation. It is decided only after the signature verified: an unsigned or forged change
 *   under the own id is `unsigned` / `bad-signature` and says nothing about this device.
 * - `equivocation`: two signed changes of one device are in hand that cannot both be true: the same
 *   device and number signed twice with different content or head, or a change whose `prev` does not
 *   name the (signed) predecessor that is held. The author (`Rejection.change.device`,
 *   `Session.refusalDevice`) is faulty or malicious; the app should stop trusting that device. A
 *   `stand` that names another version is NOT this verdict: it ends the session as `tip-mismatch`
 *   without a culprit (see `proveEquivocation`).
 * - `bad-prev`: the hash chain is not spelled right: no `prev` after the first change, or one on
 *   the first.
 * - the others name the rule that failed: `unsigned`, `bad-check`, `bad-signature`,
 *   `unknown-member` (a member of the change that the signature does not cover; an erased change
 *   may only have device, seq, clock, collection, id, kind, check, prev and sig), `not-allowed`
 *   (`mayWrite` or `special`), `delete-not-allowed` (no `allowFinalDelete`, or it said no),
 *   `never-erase`, `redacted-without-deletion`.
 */
export type Reason =
  | 'unsigned'
  | 'bad-check'
  | 'bad-signature'
  | 'bad-prev'
  | 'unknown-member'
  | 'not-allowed'
  | 'delete-not-allowed'
  | 'never-erase'
  | 'redacted-without-deletion'
  | 'equivocation'
  | 'own-history'
  | 'field-rules';

/** A verdict with the reason when it is 'false'. */
export interface Judgement {
  readonly verdict: Verdict;
  readonly reason?: Reason;
  /** With `field-rules`: the code the app's rule answered (see `FieldRules`). */
  readonly detail?: string;
}

/** A change that was refused and why. */
export interface Rejection {
  readonly change: Change;
  readonly reason: Reason;
  /** With `field-rules`: the code the app's rule answered. */
  readonly detail?: string;
}

/**
 * Where the author's public signing key comes from; the trust layer provides one. A key source says
 * who can be CHECKED, not who may write: a removed device stays checkable, and what it may still do
 * is the app's `mayWrite` (see docs/wire-format.md, "Trust derivation").
 */
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
   * Optional: collections whose records are never finally deleted (e.g. the device list itself);
   * merged into `JudgeOptions.neverErase`.
   */
  readonly neverErase?: readonly string[];
  /**
   * Optional: `keyFor` believes nothing in the replica it is given that it cannot verify itself (the
   * trust layer checks the signature of every entry it reads), so `settle` may hand it a replica that
   * also holds changes that are not taken yet. An author that such changes introduce is then known
   * at once: a chain of devices that each introduce the next is read in one round instead of one
   * round per link. A source that reads the device list without verifying it must not set this.
   */
  readonly selfVerifying?: boolean;
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
   * the change is judged against, so a rule can look at the data (e.g. who owns the record). This is
   * where an app restricts what a removed device may still do.
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
  /**
   * The app's validation of names, values and relations per collection (see `FieldRules`). Asked
   * last, after the signature and `mayWrite`, once per change that has content or is a final
   * deletion; an answer other than `undefined` judges the change false (`field-rules`).
   */
  readonly fieldRules?: FieldRules;
  /**
   * Rights that look at the batch and the author's role (`RightsOptions`, `docs/rights.md`). Asked once
   * per judged batch, after everything is verified, in addition to the hooks above. With
   * `rights.allowFinalDelete` a final deletion is no longer refused for want of `allowFinalDelete`.
   */
  readonly rights?: RightsOptions<any>;
}

/** `JudgeOptions` with the replica the changes are judged against (what is known, and for the keys). */
export interface JudgeContext extends JudgeOptions {
  readonly state: Replica;
  /** What `KeySource.keyFor` is asked against, when it is not `state` (see `KeySource.selfVerifying`). */
  readonly keyState?: Replica;
}

/** A batch sorted out: what to take, what waits, how many are false (then nothing is taken). */
export interface ReadResult {
  readonly accepted: readonly Change[];
  readonly pending: readonly Change[];
  readonly rejected: number;
  /** Every refused change with its reason (empty when nothing was refused). */
  readonly rejections: readonly Rejection[];
  /** Reading ended early at a limit, or what is still unverifiable was cut at `maxPendingChanges`. */
  readonly truncated: boolean;
}

const COMMON_MEMBERS = [
  'device',
  'seq',
  'clock',
  'collection',
  'id',
  'kind',
  'check',
  'sig',
  'prev',
];

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
 * version, data set, head (with `prev`, the link to the previous change, when there is one) and the
 * content's check value. A redacted change counts as 'set'. A signature made for one app or data set
 * therefore never verifies in another.
 */
export function changeSigningText(appId: string, change: Change, dataSet: string): string {
  if (typeof dataSet !== 'string' || dataSet.length === 0) {
    throw new TypeError('changeSigningText: the data set must be a non-empty string');
  }
  const { device, seq, clock, collection, id, prev } = change;
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
    ...(prev !== undefined ? { prev } : {}),
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

/**
 * The one proof of equivocation an app may act on: two changes with the same device and number and
 * different signed texts that BOTH carry a signature that verifies under the author's key (and, for a
 * change that still has its content, a check value that matches it). A `tip-mismatch` of a session
 * is only a claim about someone's history and proves nothing; fetch the other version
 * (`changeAt` on the device that holds it) and ask this function. False for one change twice, for
 * changes of different authors or numbers, and for anything unsigned or invalid; never throws.
 */
export async function proveEquivocation(
  a: Change,
  b: Change,
  publicKey: CryptoKey,
  appId: string,
  dataSet: string,
): Promise<boolean> {
  try {
    if (a.device !== b.device || a.seq !== b.seq) return false;
    for (const c of [a, b]) {
      if (!c.sig || !c.check) return false;
      if (c.kind !== 'redacted' && changeCheckValue(c) !== c.check) return false;
    }
    const first = changeSigningText(appId, a, dataSet);
    const second = changeSigningText(appId, b, dataSet);
    if (first === second) return false;
    return (
      (await verifyText(publicKey, first, a.sig as string)) &&
      (await verifyText(publicKey, second, b.sig as string))
    );
  } catch {
    return false;
  }
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

/** What judging remembers of a verified change: its signed text and its place in the hash chain. */
export interface SeenChange {
  /** The signed text: what two versions of one device and number are compared by. */
  readonly text: string;
  /** Its link (`changeLink`): what its successor's `prev` must name. */
  readonly link: string;
  readonly prev: string | undefined;
}

interface Judged extends Judgement {
  /** The signed text of a verified change. */
  readonly text?: string;
}

const no = (reason: Reason, detail?: string): Judged => ({
  verdict: 'false',
  reason,
  ...(detail !== undefined ? { detail } : {}),
});

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
  const known = held.get(idOf(change));
  if (!change.sig || !change.check) return no('unsigned');
  // The hash chain is spelled one way: the first change has no `prev`, every later one has it.
  if (change.seq > 1 !== (change.prev !== undefined)) return no('bad-prev');
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
  const key = await context.keys.keyFor(change.device, context.keyState ?? context.state);
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
  // The hash chain against the predecessor this replica holds (numbering is gapless: a replica never
  // holds a successor without it).
  const before = change.seq > 1 ? held.get(`${change.device}#${change.seq - 1}`) : undefined;
  const beforeLink = before && changeLink(before);
  if (beforeLink !== undefined && beforeLink !== change.prev) return no('equivocation');
  if (
    change.kind === 'delete' &&
    (context.allowFinalDelete
      ? context.allowFinalDelete(change.device, change, context.state) !== true
      : !context.rights?.allowFinalDelete)
  ) {
    return no('delete-not-allowed');
  }
  if (context.mayWrite && !context.mayWrite(change.device, change, context.state)) {
    return no('not-allowed');
  }
  if (context.fieldRules && change.kind !== 'redacted') {
    const answer = ruleAnswer(context.fieldRules, change, context.state);
    if (answer !== undefined) return no('field-rules', answer);
  }
  return { verdict: 'checked', text };
}

/**
 * Judges each change on its own (see `judgeDetailed` for the order of the rules), and two different
 * versions of one device and number, or a broken hash chain, against each other (`seen` holds what
 * the batch, or the session, has verified so far; it is added to).
 */
async function judgeEach(
  context: JudgeContext,
  changes: readonly Change[],
  seen: Map<string, SeenChange>,
): Promise<Judged[]> {
  const held = heldIn(context.state.log);
  const judged = await Promise.all(changes.map((c) => judgeOne(context, held, c)));
  return judged.map((j, i) => {
    const change = changes[i] as Change;
    if (j.verdict !== 'checked' || j.text === undefined) return j;
    const link = changeLink(change) as string;
    const before = seen.get(idOf(change));
    if (before !== undefined && before.text !== j.text) return no('equivocation');
    const lower = change.seq > 1 ? seen.get(`${change.device}#${change.seq - 1}`) : undefined;
    if (lower !== undefined && lower.link !== change.prev) return no('equivocation');
    const upper = seen.get(`${change.device}#${change.seq + 1}`);
    if (upper?.prev !== undefined && upper.prev !== link) return no('equivocation');
    seen.set(idOf(change), { text: j.text, link, prev: change.prev });
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
 * The erased changes that can NEVER be applied beside a deletion, found in one worklist pass (no
 * merge). A deletion applies only when its author's earlier numbers are all there (erased changes
 * fill gaps) and the numbers its `knew` names are reached. An erased change that is dropped (its
 * record has no deletion that can still apply) opens a gap at its number, which kills the later
 * deletions of that author and the deletions whose `knew` names a number past the gap, which in turn
 * leaves other erased changes without a deletion, and so on. This over-approximates what can apply
 * (clock jumps are not looked at), so it only ever names changes the exact fixpoint drops as well;
 * the exact check in `appliedErasures` then runs on the rest. Linear in the changes.
 */
function unsupportedErasures(
  state: Replica,
  base: readonly Change[],
  erased: readonly Change[],
): Set<Change> {
  const doomed = new Set<Change>();
  if (erased.length === 0) return doomed;
  const have = new Map<DeviceId, Set<number>>();
  for (const c of [...base, ...erased]) {
    let seqs = have.get(c.device);
    if (!seqs) have.set(c.device, (seqs = new Set()));
    seqs.add(c.seq);
  }
  const reach = new Map<DeviceId, number>();
  const reachOf = (device: DeviceId): number => {
    let r = reach.get(device);
    if (r === undefined) {
      r = seenIn(state.vector, device);
      const seqs = have.get(device);
      while (seqs?.has(r + 1)) r += 1;
      reach.set(device, r);
    }
    return r;
  };

  const byRecord = new Map<string, Change[]>();
  for (const c of erased) {
    if (isDeletedIn(state, c)) continue;
    const key = recordKey(c);
    const list = byRecord.get(key);
    if (list) list.push(c);
    else byRecord.set(key, [c]);
  }
  const queue: Change[] = [];
  const alive = new Set<Change>();
  const aliveCount = new Map<string, number>();
  const ofDevice = new Map<DeviceId, Change[]>();
  const byKnew = new Map<DeviceId, { readonly n: number; readonly del: Change }[]>();
  const ofDevicePos = new Map<DeviceId, number>();
  const byKnewPos = new Map<DeviceId, number>();

  const deletions = base
    .filter((c) => c.kind === 'delete' && c.seq > seenIn(state.vector, c.device))
    .sort((a, b) => a.seq - b.seq);
  for (const del of deletions) {
    if (!byRecord.has(recordKey(del))) continue;
    const named = Object.entries(del.knew ?? {});
    if (del.seq > reachOf(del.device) || named.some(([d, n]) => n > reachOf(d))) continue;
    alive.add(del);
    aliveCount.set(recordKey(del), (aliveCount.get(recordKey(del)) ?? 0) + 1);
    const list = ofDevice.get(del.device);
    if (list) list.push(del);
    else ofDevice.set(del.device, [del]);
    for (const [d, n] of named) {
      const entries = byKnew.get(d);
      if (entries) entries.push({ n, del });
      else byKnew.set(d, [{ n, del }]);
    }
  }
  for (const entries of byKnew.values()) entries.sort((a, b) => a.n - b.n);

  const kill = (del: Change): void => {
    if (!alive.delete(del)) return;
    const key = recordKey(del);
    const left = (aliveCount.get(key) ?? 1) - 1;
    aliveCount.set(key, left);
    if (left === 0) queue.push(...(byRecord.get(key) ?? []));
  };
  const lower = (device: DeviceId, to: number): void => {
    reach.set(device, to);
    const list = ofDevice.get(device);
    if (list) {
      let at = ofDevicePos.get(device) ?? list.length - 1;
      while (at >= 0 && (list[at] as Change).seq > to) kill(list[at--] as Change);
      ofDevicePos.set(device, at);
    }
    const entries = byKnew.get(device);
    if (entries) {
      let at = byKnewPos.get(device) ?? entries.length - 1;
      while (at >= 0 && (entries[at] as { n: number }).n > to) {
        kill((entries[at--] as { del: Change }).del);
      }
      byKnewPos.set(device, at);
    }
  };

  for (const [key, list] of byRecord) if ((aliveCount.get(key) ?? 0) === 0) queue.push(...list);
  while (queue.length > 0) {
    const c = queue.pop() as Change;
    if (doomed.has(c)) continue;
    doomed.add(c);
    if (c.seq > seenIn(state.vector, c.device) && c.seq - 1 < reachOf(c.device)) {
      lower(c.device, c.seq - 1);
    }
  }
  return doomed;
}

/**
 * The erased changes of `candidates` that are really applied beside their record's final deletion
 * when `base` and they are merged into `state`: the greatest set that is consistent with itself.
 * An erased change fills the gap of its own number (so a deletion right after it applies), but one
 * whose deletion merge holds back (a gap, a missing `knew`, a clock jump) is left out, and so is
 * every deletion that only applied by the help of an erased change that was left out. The cascade is
 * found by one linear pass over the dependencies (`unsupportedErasures`), the exact result by a few
 * merges: a chain of erased changes that each need the next one no longer costs one merge per link.
 */
function appliedErasures(
  state: Replica,
  base: readonly Change[],
  candidates: readonly Change[],
): Set<Change> {
  let erased = candidates;
  for (;;) {
    const doomed = unsupportedErasures(state, base, erased);
    const live = doomed.size === 0 ? erased : erased.filter((c) => !doomed.has(c));
    const now = merge(state, [...base, ...live]).replica;
    const next = live.filter((c) => isDeletedIn(now, c));
    if (next.length === erased.length) return new Set(erased);
    erased = next;
  }
}

const withoutText = ({ verdict, reason, detail }: Judged): Judgement =>
  reason ? { verdict, reason, ...(detail !== undefined ? { detail } : {}) } : { verdict };

/**
 * Judges the changes of one batch, in this order: a member the signature does not cover (false,
 * `unknown-member`); the special case; unsigned or without check value (false); a hash chain that is
 * not spelled right (false, `bad-prev`); final deletion in a `neverErase` collection (false); content
 * not matching its check value (false; an erased change has no content to match); author's key
 * unknown (pending); signature wrong (false); under the own id without being held here (false,
 * `own-history`); another version of the same device and number, or a `prev` that does not name
 * the held predecessor held or in the batch (false, `equivocation`); final deletion without `allowFinalDelete` saying yes (false); not allowed
 * by `mayWrite` (false); else checked. An erased change then counts only
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
  const final = judged.map((j, i): Judgement => {
    const c = changes[i] as Change;
    if (c.kind !== 'redacted' || j.verdict !== 'checked' || applied.has(c)) return withoutText(j);
    return deletions.has(recordKey(c)) ? { verdict: 'pending' } : no('redacted-without-deletion');
  });
  return context.rights ? withRights(context, changes, final, false) : final;
}

/** The judgements with the rights stage applied to the changes that are 'checked' (one batch, one call). */
function withRights(
  context: JudgeContext,
  changes: readonly Change[],
  judgements: Judgement[],
  sparse: boolean,
): Judgement[] {
  const rights = context.rights as RightsOptions<unknown>;
  const checked = changes.filter((_, i) => judgements[i]?.verdict === 'checked');
  const refused = new Map(
    checkRights(context.state, checked, rights, sparse).map((r) => [r.change, r]),
  );
  if (refused.size === 0) return judgements;
  return judgements.map((j, i) => {
    const r = refused.get(changes[i] as Change);
    return r ? no(r.reason, r.detail) : j;
  });
}

/**
 * Judges changes that are not a gapless run (the retained changes of a snapshot): each on its own,
 * and against each other and the replica for two versions of one number and for the hash chain, but
 * without the rule that an erased change needs its deletion to be applied beside it (the caller
 * checks that the snapshot holds the deletion). Verdicts are as `judgeDetailed` gives them.
 */
export async function judgeRetained(
  context: JudgeContext,
  changes: readonly Change[],
): Promise<Judgement[]> {
  const judged = (await judgeEach(context, changes, new Map())).map(withoutText);
  return context.rights ? withRights(context, changes, judged, true) : judged;
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
  /** Records of verified erased changes whose deletion has not arrived yet (the group is still open). */
  readonly open: Set<string>;
  /** Every verified change by device and number: to see equivocation and a broken hash chain. */
  readonly seen: Map<string, SeenChange>;
  /** Verified changes per author (for the quota). A Map: any device id is an ordinary key. */
  readonly counts: Map<string, number>;
  /** JSON length of everything held. */
  chars: number;
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
  open: new Set(),
  seen: new Map(),
  counts: new Map(),
  chars: 0,
  truncated: false,
});

export interface AdmitLimits {
  readonly maxSessionChanges: number;
  readonly maxSessionChars: number;
  /**
   * The budgets while an erased change waits for its deletion (`Limits.maxGroupChanges` and
   * `maxGroupChars`): the larger of the session budget and this one applies then. Missing: no
   * extension.
   */
  readonly maxGroupChanges?: number;
  readonly maxGroupChars?: number;
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
  const held = heldCount(judging);
  // While an erased change waits for its deletion the group is indivisible: the wider budget applies.
  const open = new Set(judging.open);
  const deleted = new Set<string>();
  for (const change of changes) {
    const size = JSON.stringify(change).length;
    if (limits) {
      const wide = open.size > 0;
      const maxChanges = wide
        ? Math.max(limits.maxSessionChanges, limits.maxGroupChanges ?? 0)
        : limits.maxSessionChanges;
      const maxChars = wide
        ? Math.max(limits.maxSessionChars, limits.maxGroupChars ?? 0)
        : limits.maxSessionChars;
      if (held + sizes.length >= maxChanges) cut = 'session-changes';
      // the first change always fits (it is bounded by the message limit): a budget smaller than one
      // change would otherwise make that change impossible to take
      else if (chars + size > maxChars && held + sizes.length > 0) cut = 'session-chars';
    }
    if (cut) break;
    sizes.push(size);
    chars += size;
    const key = recordKey(change);
    if (change.kind === 'delete') {
      open.delete(key);
      deleted.add(key);
    } else if (change.kind === 'redacted' && !deleted.has(key) && !judging.deletions.has(key)) {
      open.add(key);
    }
  }
  const kept = sizes.length === changes.length ? changes : changes.slice(0, sizes.length);
  const judged = await judgeEach({ ...options, state }, kept, judging.seen);
  const rejections: Rejection[] = [];
  judged.forEach((j, i) => {
    if (j.verdict === 'false') {
      rejections.push({
        change: kept[i] as Change,
        reason: j.reason ?? 'not-allowed',
        ...(j.detail !== undefined ? { detail: j.detail } : {}),
      });
    }
  });
  if (rejections.length > 0) return { ok: false, rejections };
  for (const [i, j] of judged.entries()) {
    const change = kept[i] as Change;
    if (j.verdict === 'pending') {
      judging.pending.push(change);
    } else {
      const count = (judging.counts.get(change.device) ?? 0) + 1;
      if (options.quota && !options.quota(change.device, count, state)) {
        cut = 'quota';
        break;
      }
      judging.counts.set(change.device, count);
      const key = recordKey(change);
      if (change.kind === 'redacted') {
        judging.erased.push(change);
        if (!judging.deletions.has(key)) judging.open.add(key);
      } else judging.accepted.push(change);
      if (change.kind === 'delete') {
        judging.deletions.add(key);
        judging.open.delete(key);
      }
    }
    judging.chars += sizes[i] as number;
  }
  if (cut) {
    judging.truncated = true;
    judging.limit = cut;
  }
  return { ok: true, judging };
}

const rejectionOf = (r: { change: Change; reason: Reason; detail?: string }): Rejection => ({
  change: r.change,
  reason: r.reason,
  ...(r.detail !== undefined ? { detail: r.detail } : {}),
});

const refusedResult = (rejections: readonly Rejection[]): ReadResult => ({
  accepted: [],
  pending: [],
  rejected: rejections.length,
  rejections,
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
 * Each round judges only the waiting changes whose author has become checkable (one key lookup per
 * waiting author, not one judgement per waiting change) and merges only what the round added to the
 * replica of the round before, so a chain of devices that each introduce the next, delivered in any
 * order, costs one cheap round per link instead of a re-merge and re-judgement of everything waiting.
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
  const accepted = [...judging.accepted];
  let erased = [...judging.erased];
  let pending = [...judging.pending];
  let truncated = judging.truncated;
  const blocked = new Set<DeviceId>();
  const dropped: Change[] = [];
  let taken: Change[] = [];
  // The replica as it would be with everything verified so far, extended round by round.
  let upTo = state;
  let carry: Change[] = [];
  let merged = 0;
  const mergedTaken = new Set<Change>();
  // Every round that goes on decided at least one waiting change, so this many rounds are enough;
  // the bound only guarantees the loop ends whatever a key source does.
  const maxRounds = pending.length + erased.length + 3;
  for (let round = 0; round < maxRounds; round += 1) {
    const fresh = [...accepted.slice(merged), ...taken.filter((c) => !mergedTaken.has(c))];
    merged = accepted.length;
    for (const c of taken) mergedTaken.add(c);
    if (fresh.length > 0 || carry.length > 0) {
      const result = merge(upTo, [...carry, ...fresh]);
      upTo = result.replica;
      carry = [...result.held];
    }
    let progress = false;
    if (pending.length > 0) {
      // A self-verifying key source may see what is waiting, too (never a change claiming this
      // device's own id: the derivation believes the own log without a signature check).
      // The verified changes that merge holds back (`carry`: a causal hold) belong to it too, so the
      // verdict does not depend on whether a change happens to be merged yet or held behind another.
      const keyState = options.keys.selfVerifying
        ? merge(upTo, [...carry, ...pending.filter((c) => c.device !== upTo.device)]).replica
        : upTo;
      // Without a special-case hook only the key decides pending: look at each waiting author once.
      let ready: Set<DeviceId> | undefined;
      if (!options.special) {
        ready = new Set();
        for (const author of new Set(pending.map((c) => c.device))) {
          if (await options.keys.keyFor(author, keyState)) ready.add(author);
        }
      }
      const todo = ready ? pending.filter((c) => ready.has(c.device)) : pending;
      const judged = await judgeEach({ ...options, state: upTo, keyState }, todo, seen);
      const rejections: Rejection[] = [];
      judged.forEach((j, i) => {
        if (j.verdict === 'false') {
          rejections.push({
            change: todo[i] as Change,
            reason: j.reason ?? 'not-allowed',
            ...(j.detail !== undefined ? { detail: j.detail } : {}),
          });
        }
      });
      if (rejections.length > 0) return refusedResult(rejections);
      const stillWaiting = new Set<Change>(
        ready ? pending.filter((c) => !ready.has(c.device)) : [],
      );
      const verified: Change[] = [];
      for (const [i, j] of judged.entries()) {
        const change = todo[i] as Change;
        if (j.verdict === 'pending') {
          stillWaiting.add(change);
          continue;
        }
        progress = true;
        verified.push(change);
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
      pending = pending.filter((c) => stillWaiting.has(c));
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
  const lost = erased.filter((c) => !open.has(recordKey(c)) && !deletions.has(recordKey(c)));
  if (lost.length > 0 && !truncated && config.more !== true) {
    return refusedResult(
      lost.map((change) => ({ change, reason: 'redacted-without-deletion' as const })),
    );
  }
  if (options.rights) {
    // The rights stage looks at the whole batch at once (never per piece: the verdict must not depend on
    // how the batch was cut), over what is about to be taken.
    const refused = checkRights(state, [...accepted, ...taken], options.rights);
    if (refused.length > 0) return refusedResult(refused.map(rejectionOf));
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
