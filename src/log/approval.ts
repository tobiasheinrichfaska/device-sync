import { byDeviceThenSeq, merge, redacted } from './merge.ts';
import { parseChange, type ParseOptions } from './parse.ts';
import type {
  ApprovalDecision,
  ApprovalEntry,
  ApprovalHook,
  ApprovalState,
  ApprovalStatus,
  Change,
  DeviceId,
  MergeResult,
  Replica,
} from './types.ts';
import { isPlain, own } from './validate.ts';
import { seen } from './vector.ts';

/**
 * Hold back until approved: an app hook decides per incoming change whether it is applied now, held
 * back or rejected. The design and its limits are in `docs/approval.md`; in short:
 *
 * - a held change is kept apart in `Replica.approval`, outside `log` and `vector`: no stand claims it,
 *   the gapless chain and the causal holds of merge stay exactly as they are, later changes of its
 *   author and changes that name it in `knew` wait as they wait for any gap;
 * - a rejected change is applied as an erased change (head, link, check value and signature stay, the
 *   content is gone): the number is counted, so the author's later changes are not blocked; the session
 *   never sends it on (nor what follows it from that author), as it is no erased change of a deleted record;
 * - the erased changes that come with a held final deletion are held with it and decided with it;
 * - everything is a pure function of the replica, the batch and the decisions: replicas that
 *   receive the same changes in any order and the same decisions end with the same data.
 */

/** Bounds of the approval state; an app may pass its own. */
export const APPROVAL_LIMITS = Object.freeze({
  /** Most entries the state holds; further ones are not kept (they come again in a later session). */
  maxPending: 2000,
  /** Most characters (UTF-16 units of the JSON) of the changes of all entries together. */
  maxChars: 8_000_000,
});

export interface ApprovalOptions {
  /** Asked for each new `set` and `delete`; without it nothing is held and only decided entries move. */
  readonly hook?: ApprovalHook;
  readonly maxPending?: number;
  readonly maxChars?: number;
}

/** What one approval-aware merge did with the hook. */
export interface ApprovalReport {
  /** Changes newly held back by this call (erased companions of a held deletion included). */
  readonly held: number;
  /** Changes of this call (hook or earlier decision) applied as erased changes. */
  readonly rejected: number;
  /** Changes that should have been kept but did not fit the bounds: they come again later. */
  readonly dropped: number;
}

export interface ApprovedMergeResult extends MergeResult {
  readonly approval: ApprovalReport;
}

const keyOf = (c: Change): string => `${c.device}#${c.seq}`;
const recordKey = (c: Change): string => JSON.stringify([c.collection, c.id]);

function isDeleted(replica: Replica, c: Change): boolean {
  return own(own(replica.collections, c.collection), c.id)?.deleted === true;
}

const sizes = new WeakMap<Change, number>();
function sizeOf(change: Change): number {
  let size = sizes.get(change);
  if (size === undefined) {
    size = JSON.stringify(change).length;
    sizes.set(change, size);
  }
  return size;
}

function ask(hook: ApprovalHook | undefined, change: Change, replica: Replica): ApprovalDecision {
  if (!hook) return 'apply';
  try {
    const answer = hook(change, replica) as unknown;
    if (answer === true || answer === 'apply') return 'apply';
    if (answer === 'reject') return 'reject';
  } catch {
    // a hook that fails holds: nothing is applied by accident
  }
  return 'hold';
}

function resolve(options: ApprovalOptions): { maxPending: number; maxChars: number } {
  const num = (v: unknown, fallback: number): number =>
    typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : fallback;
  return {
    maxPending: num(options.maxPending, APPROVAL_LIMITS.maxPending),
    maxChars: num(options.maxChars, APPROVAL_LIMITS.maxChars),
  };
}

/**
 * `merge`, with an approval hook. Changes that are new to the replica (not applied, not already
 * held) and that are `set` or `delete` are asked; erased changes are not (they follow their
 * record's deletion). Entries decided earlier (`approve`, `reject`) go through with the batch.
 * The result's replica carries the updated `approval` state. A replica that never uses this function
 * is untouched; `merge` itself never reads `Replica.approval`.
 */
export function mergeApproved(
  replica: Replica,
  incoming: readonly Change[],
  options: ApprovalOptions = {},
): ApprovedMergeResult {
  const { maxPending, maxChars } = resolve(options);
  const vector = replica.vector;
  const entries = new Map<string, ApprovalEntry>();
  let chars = 0;
  for (const entry of replica.approval?.entries ?? []) {
    if (entry.change.seq <= seen(vector, entry.change.device)) continue;
    entries.set(keyOf(entry.change), entry);
    chars += sizeOf(entry.change);
  }

  const fresh = new Map<string, Change>();
  for (const change of incoming) {
    const key = keyOf(change);
    if (change.seq > seen(vector, change.device) && !entries.has(key) && !fresh.has(key)) {
      fresh.set(key, change);
    }
  }
  const sorted = [...fresh.values()].sort(byDeviceThenSeq);

  const pass: Change[] = [];
  // Erased changes that came from outside (not made by a rejection): they apply only beside their deletion.
  const companions = new Set<Change>();
  const rejectedKeys: string[] = [];
  let held = 0;
  let dropped = 0;
  const park = (change: Change): void => {
    const size = sizeOf(change);
    if (entries.size >= maxPending || chars + size > maxChars) {
      dropped += 1;
      return;
    }
    entries.set(keyOf(change), { change, decision: 'hold' });
    chars += size;
    held += 1;
  };

  // Records whose final deletion is held (also one that did not fit): their erased changes wait with it.
  const heldDeletes = new Set<string>();
  for (const entry of entries.values()) {
    if (entry.decision === 'hold' && entry.change.kind === 'delete') {
      heldDeletes.add(recordKey(entry.change));
    }
  }
  for (const change of sorted) {
    if (change.kind === 'redacted') continue;
    // A write to a deleted record never keeps its content: merge erases it, nobody is asked.
    if (change.kind === 'set' && isDeleted(replica, change)) {
      pass.push(change);
      continue;
    }
    let decision = ask(options.hook, change, replica);
    // A final deletion cannot be rejected, only held (see `docs/approval.md`).
    if (decision === 'reject' && change.kind === 'delete') decision = 'hold';
    if (decision === 'apply') pass.push(change);
    else if (decision === 'reject') {
      pass.push(redacted(change));
      rejectedKeys.push(keyOf(change));
    } else {
      if (change.kind === 'delete') heldDeletes.add(recordKey(change));
      park(change);
    }
  }
  for (const change of sorted) {
    if (change.kind !== 'redacted') continue;
    if (heldDeletes.has(recordKey(change)) && !isDeleted(replica, change)) park(change);
    else {
      pass.push(change);
      companions.add(change);
    }
  }

  // Decided entries go through with the batch; a rejected one as an erased change.
  let feed = [...pass];
  for (const entry of entries.values()) {
    if (entry.change.kind === 'redacted') companions.add(entry.change);
    if (entry.decision === 'approved') feed.push(entry.change);
    else if (entry.decision === 'rejected') feed.push(redacted(entry.change));
  }

  // An erased change must not be applied without its deletion: if the deletion cannot be applied in
  // this merge (it waits behind a held change of its author, say), the erased change waits too. The
  // merge is tried; what it applied wrongly is left out and the merge is tried again (normally once).
  let result = merge(replica, feed);
  const lateOnes: Change[] = [];
  for (let round = 0; ; round += 1) {
    const vectorNow = result.replica.vector;
    const bad = new Set(
      feed.filter(
        (c) =>
          companions.has(c) && seen(vectorNow, c.device) >= c.seq && !isDeleted(result.replica, c),
      ),
    );
    if (bad.size === 0) break;
    lateOnes.push(...bad);
    feed = feed.filter((c) => !bad.has(c));
    // a long chain of such waits: leave every outside erased change of a live record for the next call
    if (round >= 16) feed = feed.filter((c) => !companions.has(c) || isDeleted(replica, c));
    result = merge(replica, feed);
    if (round >= 16) break;
  }
  if (lateOnes.length > 0) {
    result = {
      ...result,
      held: [...result.held, ...lateOnes.filter((c) => !entries.has(keyOf(c)))],
    };
  }
  let applied = result.applied;
  let live = [...entries.values()];

  // A record that was finally deleted takes the content of what is held for it: the entry becomes an
  // erased change and goes through at once (it is what merge makes of a write to a deleted record).
  let flow: ApprovalEntry[] = [];
  live = live.filter((e) => e.change.seq > seen(result.replica.vector, e.change.device));
  live = live.map((entry) => {
    if (entry.decision !== 'hold' || !isDeleted(result.replica, entry.change)) return entry;
    if (entry.change.kind === 'delete') return entry;
    const next: ApprovalEntry = { change: redacted(entry.change), decision: 'approved' };
    flow = [...flow, next];
    return next;
  });
  if (flow.length > 0) {
    const second = merge(
      result.replica,
      flow.map((e) => e.change),
    );
    result = {
      replica: second.replica,
      applied: result.applied + second.applied,
      held: result.held,
    };
    applied += second.applied;
    live = live.filter((e) => e.change.seq > seen(result.replica.vector, e.change.device));
  }

  // An erased change whose held deletion is gone (it did not fit): it comes again with its deletion.
  const stillHeldDeletes = new Set(
    live
      .filter((e) => e.decision === 'hold' && e.change.kind === 'delete')
      .map((e) => recordKey(e.change)),
  );
  live = live.filter((e) => {
    const orphan =
      e.decision === 'hold' &&
      e.change.kind === 'redacted' &&
      !stillHeldDeletes.has(recordKey(e.change)) &&
      !isDeleted(result.replica, e.change);
    if (orphan) {
      dropped += 1;
      held -= held > 0 ? 1 : 0;
    }
    return !orphan;
  });

  const inState = new Set(live.map((e) => keyOf(e.change)));
  const vectorNow = result.replica.vector;
  const rejected = rejectedKeys.filter((key) => {
    const at = key.lastIndexOf('#');
    return seen(vectorNow, key.slice(0, at)) >= Number(key.slice(at + 1));
  }).length;
  // Entries decided earlier and applied now count as rejected too, when they were rejections.
  let rejectedEntries = 0;
  for (const entry of entries.values()) {
    if (
      entry.decision === 'rejected' &&
      !inState.has(keyOf(entry.change)) &&
      seen(vectorNow, entry.change.device) >= entry.change.seq
    ) {
      rejectedEntries += 1;
    }
  }

  const state: ApprovalState = {
    entries: live.sort((a, b) => byDeviceThenSeq(a.change, b.change)),
  };
  return {
    replica: { ...result.replica, approval: state },
    applied,
    held: result.held.filter((c) => !inState.has(keyOf(c))),
    approval: { held, rejected: rejected + rejectedEntries, dropped },
  };
}

/** A reference to a change by author and number. */
export interface ChangeRef {
  readonly device: DeviceId;
  readonly seq: number;
}

/**
 * The changes that wait for a decision (held and not decided yet), by device and number. An erased
 * change listed here is the companion of a held final deletion of its record: decide the deletion.
 */
export function pendingApproval(replica: Replica): Change[] {
  return (replica.approval?.entries ?? [])
    .filter((e) => e.decision === 'hold')
    .map((e) => e.change);
}

/** Decided entries that cannot be applied yet (a gap before them, a missing `knew`): they wait, not stored elsewhere. */
export function decidedWaiting(replica: Replica): Change[] {
  return (replica.approval?.entries ?? [])
    .filter((e) => e.decision !== 'hold')
    .map((e) => e.change);
}

/**
 * Decides the held changes one by one: `choose` answers `'approve'`, `'reject'` or undefined (keep
 * holding). A decision is final: an approved or rejected entry is never asked again. Erased
 * companions of a held final deletion follow the decision on the deletion. Then everything decided is
 * merged: approved entries are applied in a correct order (merge's own: gapless, `knew`, clock), the
 * ones that cannot be applied yet stay decided and apply as soon as what they wait for arrives;
 * rejected ones are applied as erased changes.
 */
export function decide(
  replica: Replica,
  choose: (change: Change) => 'approve' | 'reject' | undefined,
  options: Pick<ApprovalOptions, 'maxPending' | 'maxChars'> = {},
): ApprovedMergeResult {
  const status = (answer: unknown): ApprovalStatus | undefined =>
    answer === 'approve' ? 'approved' : answer === 'reject' ? 'rejected' : undefined;
  const entries = replica.approval?.entries ?? [];
  const byRecord = new Map<string, ApprovalStatus>();
  const next: ApprovalEntry[] = entries.map((entry) => {
    if (entry.decision !== 'hold' || entry.change.kind === 'redacted') return entry;
    let answer: unknown;
    try {
      answer = choose(entry.change);
    } catch {
      answer = undefined;
    }
    let decided = status(answer);
    // a final deletion is held until it is approved: it cannot be rejected
    if (decided === 'rejected' && entry.change.kind === 'delete') decided = undefined;
    if (!decided) return entry;
    if (entry.change.kind === 'delete') byRecord.set(recordKey(entry.change), decided);
    return { change: entry.change, decision: decided };
  });
  const followed = next.map((entry) => {
    if (entry.decision !== 'hold' || entry.change.kind !== 'redacted') return entry;
    const decided = byRecord.get(recordKey(entry.change));
    return decided ? { change: entry.change, decision: decided } : entry;
  });
  return mergeApproved({ ...replica, approval: { entries: followed } }, [], options);
}

const refKey = (r: ChangeRef): string => `${r.device}#${r.seq}`;

/** Approves the held changes named (see `decide`); names that hold nothing are ignored. */
export function approve(
  replica: Replica,
  refs: readonly ChangeRef[],
  options: Pick<ApprovalOptions, 'maxPending' | 'maxChars'> = {},
): ApprovedMergeResult {
  const named = new Set(refs.map(refKey));
  return decide(replica, (c) => (named.has(keyOf(c)) ? 'approve' : undefined), options);
}

/** Rejects the held changes named: dropped for good (see `decide`); names that hold nothing are ignored. */
export function reject(
  replica: Replica,
  refs: readonly ChangeRef[],
  options: Pick<ApprovalOptions, 'maxPending' | 'maxChars'> = {},
): ApprovedMergeResult {
  const named = new Set(refs.map(refKey));
  return decide(replica, (c) => (named.has(keyOf(c)) ? 'reject' : undefined), options);
}

export type ApprovalReadFailure =
  | 'not-object'
  | 'unknown-member'
  | 'bad-entries'
  | 'too-many'
  | 'too-large'
  | 'bad-entry'
  | 'bad-decision'
  | 'bad-change'
  | 'duplicate';

export type ApprovalReadResult =
  | { readonly ok: true; readonly state: ApprovalState }
  | { readonly ok: false; readonly reason: ApprovalReadFailure };

const DECISIONS: ReadonlySet<unknown> = new Set(['hold', 'approved', 'rejected']);

/**
 * Reads a stored approval state strictly (any JSON value; never throws): exactly `{ entries }`,
 * every entry exactly `{ change, decision }` with a change the parser accepts, no number twice,
 * at most `maxPending` entries and `maxChars` characters. The result is sorted by device and number.
 * It is local state: nothing is verified again (signatures were judged before the change was held).
 */
export function readApprovalState(
  raw: unknown,
  options: ParseOptions & Pick<ApprovalOptions, 'maxPending' | 'maxChars'> = {},
): ApprovalReadResult {
  const fail = (reason: ApprovalReadFailure): ApprovalReadResult => ({ ok: false, reason });
  try {
    const { maxPending, maxChars } = resolve(options);
    if (!isPlain(raw)) return fail('not-object');
    if (Object.keys(raw).some((k) => k !== 'entries')) return fail('unknown-member');
    const list = Object.hasOwn(raw, 'entries') ? raw.entries : undefined;
    if (!Array.isArray(list)) return fail('bad-entries');
    if (list.length > maxPending) return fail('too-many');
    const seenKeys = new Set<string>();
    const out: ApprovalEntry[] = [];
    let chars = 0;
    for (const item of list as unknown[]) {
      if (!isPlain(item)) return fail('bad-entry');
      if (Object.keys(item).some((k) => k !== 'change' && k !== 'decision')) {
        return fail('bad-entry');
      }
      if (!Object.hasOwn(item, 'change') || !Object.hasOwn(item, 'decision')) {
        return fail('bad-entry');
      }
      if (!DECISIONS.has(item.decision)) return fail('bad-decision');
      const change = parseChange(item.change, options);
      if (!change) return fail('bad-change');
      // only a write can be rejected: a deletion is held or approved, an erased change follows its deletion
      if (item.decision === 'rejected' && change.kind !== 'set') return fail('bad-decision');
      const key = keyOf(change);
      if (seenKeys.has(key)) return fail('duplicate');
      seenKeys.add(key);
      chars += JSON.stringify(change).length;
      if (chars > maxChars) return fail('too-large');
      out.push({ change, decision: item.decision as ApprovalStatus });
    }
    out.sort((a, b) => byDeviceThenSeq(a.change, b.change));
    return { ok: true, state: { entries: out } };
  } catch {
    return fail('bad-entry');
  }
}
