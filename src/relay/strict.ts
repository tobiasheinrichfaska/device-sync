// Shared strict-reading helpers of the relay layer: a JSON object from text (bounded, no duplicate
// key, plain), the member check, and the two scalar predicates every reader uses. Internal.
import { hasDuplicateKeys } from '../core/json.ts';
import { isPlain, parseJson } from '../core/secure.ts';

export const RELAY_DEVICE_ID = /^geraet-[0-9a-f]{32}$/;

/** A JSON object from text, once: bounded, no duplicate key, plain. */
export function object(text: unknown, maxChars: number): Record<string, unknown> | undefined {
  if (typeof text !== 'string' || text.length > maxChars) return undefined;
  const value = parseJson(text);
  if (!isPlain(value)) return undefined;
  try {
    if (hasDuplicateKeys(text)) return undefined;
  } catch {
    return undefined;
  }
  return value;
}

/** Every key is allowed, every required key is there. */
export function members(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value);
  return (
    keys.every((key) => required.includes(key) || optional.includes(key)) &&
    required.every((key) => keys.includes(key))
  );
}

export const isDevice = (v: unknown): v is string =>
  typeof v === 'string' && RELAY_DEVICE_ID.test(v);
export const isInt = (v: unknown, min: number, max: number): v is number =>
  typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** A calendar day `YYYY-MM-DD` that exists. */
export function isCalendarDay(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  const m = DAY.exec(v);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const date = new Date(Date.UTC(y, mo - 1, d));
  return date.getUTCFullYear() === y && date.getUTCMonth() === mo - 1 && date.getUTCDate() === d;
}
