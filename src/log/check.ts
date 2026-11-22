import { checkValue } from '../core/index.ts';
import type { Change } from './types.ts';

/**
 * Check value of a change's content (fields, what it knew, when, who). It lives beside the log
 * because a final deletion erases the content: the value is taken first, so the head stays signable
 * and checkable.
 */
export function changeCheckValue(change: Change): string {
  const { fields, knew, time, by } = change;
  // Judging asks again for every round a change waits; the value is kept per change object, and is
  // computed again when any member of the content is another object (replicas are never edited in place).
  const known = memo.get(change);
  if (
    known &&
    known.fields === fields &&
    known.knew === knew &&
    known.time === time &&
    known.by === by
  ) {
    return known.value;
  }
  const value = checkValue({ fields, knew, time, by });
  memo.set(change, { fields, knew, time, by, value });
  return value;
}

/**
 * The link a successor of this change carries as `prev`: the check value it has or will have when it
 * is signed. An erased change keeps the one taken before its content went (undefined only for an
 * erased change that never had one).
 */
export function changeLink(change: Change): string | undefined {
  return change.check ?? (change.kind === 'redacted' ? undefined : changeCheckValue(change));
}

const memo = new WeakMap<
  Change,
  {
    fields: Change['fields'];
    knew: Change['knew'];
    time: number | undefined;
    by: string | undefined;
    value: string;
  }
>();
