import { checkValue } from '../core/index.ts';
import type { Change } from './types.ts';

/**
 * Check value of a change's content (fields, what it knew, when, who). It lives beside the log
 * because a final deletion erases the content: the value is taken first, so the head stays signable
 * and checkable.
 */
export function changeCheckValue(change: Change): string {
  const { fields, knew, time, by } = change;
  return checkValue({ fields, knew, time, by });
}
