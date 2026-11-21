import { FORMAT_VERSION, canonical, marker, signText, verifyText } from '../core/index.ts';
import { changeCheckValue } from './check.ts';
import { merge } from './merge.ts';
import type { Change, DeviceId, Replica } from './types.ts';

/**
 * How a received change is judged: 'checked' (to be taken), 'pending' (its author cannot be checked
 * yet, or its deletion waits so: not taken, not passed on, it comes again), 'false' (see `judgeChange`).
 */
export type Verdict = 'checked' | 'pending' | 'false';

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
  /** Receiver-side right to write: `false` = this author may not write this change. */
  readonly mayWrite?: (author: DeviceId, change: Change) => boolean;
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

async function judgeOne(
  context: JudgeContext,
  held: ReadonlySet<string>,
  change: Change,
): Promise<Verdict> {
  if (Object.keys(change).some((member) => !CHANGE_MEMBERS.has(member))) return 'false';
  const special = context.special?.(change);
  if (special) return special;
  if (change.device === context.ownDevice && !held.has(idOf(change))) return 'false';
  if (!change.sig || !change.check) return 'false';
  if (change.kind === 'delete' && context.neverErase?.includes(change.collection)) return 'false';
  if (change.kind !== 'redacted' && changeCheckValue(change) !== change.check) return 'false';
  const key = await context.keys.keyFor(change.device, context.state);
  if (!key) return 'pending';
  const text = changeSigningText(context.appId, change, context.dataSet);
  if (!(await verifyText(key, text, change.sig))) return 'false';
  if (context.mayWrite && !context.mayWrite(change.device, change)) return 'false';
  return 'checked';
}

/**
 * Judges one change on its own, in this order: a member the signature does not cover (false); the
 * special case; under the own id without being
 * held here (false); unsigned or without check value (false); final deletion in a `neverErase`
 * collection (false); content not matching its check value (false; an erased change has no content
 * to match); author's key unknown (pending); signature wrong (false); not allowed by `mayWrite`
 * (false); else checked. An erased change that must sit beside its deletion is judged in `judgeChanges`.
 */
export function judgeChange(context: JudgeContext, change: Change): Promise<Verdict> {
  return judgeOne(context, new Set(context.state.log.map(idOf)), change);
}

/**
 * Judges the changes of one batch: each as `judgeChange`, then an erased change counts only beside
 * its record's final deletion (already in the log, or in this batch judged right; one that waits
 * makes it wait), else a forwarder could erase any signed write.
 */
export async function judgeChanges(
  context: JudgeContext,
  changes: readonly Change[],
): Promise<Verdict[]> {
  const held = new Set(context.state.log.map(idOf));
  const verdicts = await Promise.all(changes.map((c) => judgeOne(context, held, c)));
  const deletions = new Map<string, Verdict>();
  const note = (c: Change, v: Verdict): void => {
    if (c.kind !== 'delete' || v === 'false') return;
    const key = JSON.stringify([c.collection, c.id]);
    if (deletions.get(key) !== 'checked') deletions.set(key, v);
  };
  for (const c of context.state.log) note(c, 'checked');
  changes.forEach((c, i) => note(c, verdicts[i] ?? 'false'));
  return verdicts.map((v, i) => {
    const c = changes[i];
    if (!c || c.kind !== 'redacted' || v !== 'checked') return v;
    return deletions.get(JSON.stringify([c.collection, c.id])) ?? 'false';
  });
}

/**
 * Judges a batch until nothing more becomes checkable: what it takes may make further authors
 * known, so the keys are asked again for the replica as it would be. One 'false' change and
 * nothing is taken (`rejected` counts them).
 */
export async function readChanges(
  replica: Replica,
  changes: readonly Change[],
  options: JudgeOptions,
): Promise<ReadResult> {
  const accepted: Change[] = [];
  let rest = [...changes];
  let now = replica;
  for (;;) {
    const verdicts = await judgeChanges({ ...options, state: now }, rest);
    const rejected = verdicts.filter((v) => v === 'false').length;
    if (rejected > 0) return { accepted: [], pending: [], rejected };
    const fresh = rest.filter((_, i) => verdicts[i] === 'checked');
    rest = rest.filter((_, i) => verdicts[i] === 'pending');
    accepted.push(...fresh);
    if (fresh.length === 0 || rest.length === 0) return { accepted, pending: rest, rejected: 0 };
    now = merge(now, fresh).replica;
  }
}
