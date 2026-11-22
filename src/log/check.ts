import { FORMAT_VERSION, base64url, canonical, checkValue, sha256Text } from '../core/index.ts';
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
 * The signed head of a change as an object: format version, device, number, clock, collection, record,
 * kind (an erased change counts as `set`), the check value of the content and, when there is one, the
 * link to the predecessor. `changeSigningText` adds the data set and the app marker; `changeLink`
 * hashes it as it is. Undefined for an erased change that never had a check value.
 */
export function changeHead(change: Change): Record<string, unknown> | undefined {
  const check = change.check ?? (change.kind === 'redacted' ? undefined : changeCheckValue(change));
  if (check === undefined) return undefined;
  const { device, seq, clock, collection, id, prev } = change;
  return {
    v: FORMAT_VERSION,
    device,
    seq,
    clock,
    collection,
    id,
    kind: change.kind === 'redacted' ? 'set' : change.kind,
    check,
    ...(prev !== undefined ? { prev } : {}),
  };
}

/**
 * The link a successor of this change carries as `prev` (and a `stand` names as a tip):
 * base64url(SHA-256(canonical(head))), where the head is what the author signs (`changeHead`: device,
 * number, clock, collection, record, kind, check value of the content and its own `prev`). The app
 * marker and the data set, which are the same for every change of a data set, are left out because a
 * replica does not know them. Two versions of one number that differ in ANY signed member have
 * different links, and so does every later number of the chain. An erased change keeps the link it
 * had; undefined only for an erased change that never had a check value.
 */
export function changeLink(change: Change): string | undefined {
  const head = changeHead(change);
  return head && base64url(sha256Text(canonical(head)));
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
