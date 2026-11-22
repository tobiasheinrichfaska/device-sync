// Rights at the receiver that look at the batch (`JudgeOptions.rights`). The plain hooks
// (`mayWrite`, `allowFinalDelete`, `fieldRules`) see the replica as it was BEFORE the batch and the
// author's id only. A rule such as "a learning companion may change a row the office made for it" needs
// two things more: the author's ROLE, and the earlier changes of the same batch (the office made the row
// in the very file that carries the edit). This stage gives both, deterministically:
//
//  1. It runs once per judged batch (`settle` at the end of a session, `judgeChanges`, `judgeRetained`),
//     over the changes whose signatures verified, never per piece, so the verdict does not depend on how
//     the batch was cut into pieces.
//  2. `view(batch)` is built once, from the replica as it would be with EVERY verified change of the
//     batch merged (a device the batch introduces has its role). The trust layer provides one
//     (`rightsView`).
//  3. The changes are asked in ascending (`rank(author, view)`, device, number). The default rank is 0
//     for everybody (by device, then number), so one author's changes are asked in the order it wrote
//     them. An app puts the authors whose changes create what others may touch first.
//  4. Each hook gets the state as it stands with the changes asked EARLIER and allowed (their
//     `collections`; `log`, `vector` and `notices` are those before the batch). The object is one working
//     copy changed in place between calls: read it, never keep it.
//  5. Cost: one merge of the batch, one `view`, one sort, one fold per allowed change (a collection is
//     copied once, when first touched): linear in the batch.
import type { Change, Collection, DeviceId, Replica, StoredRecord } from './types.ts';
import { apply, merge, mergeSparse } from './merge.ts';
import { copyDict } from './validate.ts';

/** The answer of a rights hook: `true` allows, `false` refuses, a text (1 to 120 characters) refuses with that code. */
export type RightsAnswer = boolean | string;

/**
 * Receiver-side rights with a view of the author's standing. All members are optional except `view`;
 * a hook that is not given allows. Every hook is synchronous, must be a pure function of its arguments
 * and answers fail closed (a throw, or an answer that is not a boolean or a code, refuses with the code
 * `invalid-rule-answer`).
 */
export interface RightsOptions<V = unknown> {
  /** Built once per judged batch from the replica with every verified change of the batch merged. */
  readonly view: (batch: Replica) => V;
  /** The order key of an author's changes (default 0 for everybody); lower is asked first. A whole number. */
  readonly rank?: (author: DeviceId, view: V) => number;
  /** May this author make this change? A text refuses with that code as `Rejection.detail` (reason `not-allowed`). */
  readonly mayWrite?: (author: DeviceId, change: Change, state: Replica, view: V) => RightsAnswer;
  /** May this author delete this record for good? (reason `delete-not-allowed`; in addition to `JudgeOptions.allowFinalDelete`.) */
  readonly allowFinalDelete?: (
    author: DeviceId,
    change: Change,
    state: Replica,
    view: V,
  ) => RightsAnswer;
  /** The app's validation, like `JudgeOptions.fieldRules` but with the state and the view of the batch (reason `field-rules`). */
  readonly fieldRules?: (change: Change, state: Replica, view: V) => string | undefined;
}

/** A change the stage refused. */
export interface RightsRefusal {
  readonly change: Change;
  readonly reason: 'not-allowed' | 'delete-not-allowed' | 'field-rules';
  readonly detail?: string;
}

const INVALID = 'invalid-rule-answer';

function answerOf(call: () => unknown): { readonly ok: true } | { readonly detail?: string } {
  try {
    const answer = call();
    if (answer === true || answer === undefined) return { ok: true };
    if (answer === false) return {};
    if (typeof answer === 'string' && answer.length >= 1 && answer.length <= 120) {
      return { detail: answer };
    }
    return { detail: INVALID };
  } catch {
    return { detail: INVALID };
  }
}

/** The state the hooks see: the base with the allowed changes of the batch folded in, in place. */
class Fold {
  readonly state: Replica;
  private readonly collections: Record<string, Collection>;
  private readonly owned = new Set<string>();

  constructor(base: Replica) {
    this.collections = copyDict<Collection>(base.collections);
    this.state = { ...base, collections: this.collections };
  }

  add(change: Change): void {
    if (change.kind === 'redacted') return;
    const edit = (name: string): Record<string, StoredRecord> => {
      if (!this.owned.has(name)) {
        this.collections[name] = copyDict<StoredRecord>(this.collections[name] ?? {});
        this.owned.add(name);
      }
      return this.collections[name] as Record<string, StoredRecord>;
    };
    apply(this.collections, edit, change);
  }
}

const byRankDeviceSeq = (
  rank: ReadonlyMap<DeviceId, number>,
): ((a: Change, b: Change) => number) => {
  return (a, b) => {
    const ra = rank.get(a.device) as number;
    const rb = rank.get(b.device) as number;
    if (ra !== rb) return ra - rb;
    return a.device < b.device ? -1 : a.device > b.device ? 1 : a.seq - b.seq;
  };
};

/**
 * Runs the rights stage over verified `changes` of a batch against the replica `base` they arrive at
 * (`sparse`: the changes are not a gapless run, as in a snapshot or a removal notice). Returns every
 * refusal (empty when all are allowed). A view or rank that throws, or a rank that is not a whole
 * number, refuses every change with the code `invalid-rule-answer`.
 */
export function checkRights(
  base: Replica,
  changes: readonly Change[],
  rights: RightsOptions,
  sparse = false,
): RightsRefusal[] {
  if (changes.length === 0) return [];
  const whole = (): RightsRefusal[] =>
    changes.map((change) => ({ change, reason: 'not-allowed', detail: INVALID }));
  let view: unknown;
  const rank = new Map<DeviceId, number>();
  try {
    const batch = sparse ? mergeSparse(base, changes) : merge(base, changes).replica;
    view = rights.view(batch);
    for (const change of changes) {
      if (rank.has(change.device)) continue;
      const r = rights.rank ? rights.rank(change.device, view) : 0;
      if (!Number.isSafeInteger(r)) return whole();
      rank.set(change.device, r);
    }
  } catch {
    return whole();
  }
  const fold = new Fold(base);
  const refusals: RightsRefusal[] = [];
  for (const change of [...changes].sort(byRankDeviceSeq(rank))) {
    const refuse = (reason: RightsRefusal['reason'], detail: string | undefined): void => {
      refusals.push({ change, reason, ...(detail !== undefined ? { detail } : {}) });
    };
    const { state } = fold;
    if (change.kind === 'delete' && rights.allowFinalDelete) {
      const a = rights.allowFinalDelete;
      const answer = answerOf(() => a(change.device, change, state, view));
      if (!('ok' in answer)) {
        refuse('delete-not-allowed', answer.detail);
        continue;
      }
    }
    if (rights.mayWrite) {
      const m = rights.mayWrite;
      const answer = answerOf(() => m(change.device, change, state, view));
      if (!('ok' in answer)) {
        refuse('not-allowed', answer.detail);
        continue;
      }
    }
    if (rights.fieldRules && change.kind !== 'redacted') {
      const f = rights.fieldRules;
      try {
        const answer: unknown = f(change, state, view);
        if (answer !== undefined) {
          refuse(
            'field-rules',
            typeof answer === 'string' && answer.length >= 1 && answer.length <= 120
              ? answer
              : INVALID,
          );
          continue;
        }
      } catch {
        refuse('field-rules', INVALID);
        continue;
      }
    }
    fold.add(change);
  }
  return refusals;
}
