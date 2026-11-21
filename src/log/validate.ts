import type { Limits } from './limits.ts';
import type { Origin } from './types.ts';

/** Why a change cannot be created or read; the same codes for local writing and for the parser. */
export type Problem =
  'invalid-name' | 'invalid-value' | 'too-large' | 'too-many-fields' | 'invalid-origin';

/** Keys that would reach the prototype of the object they are stored in. */
export const FORBIDDEN_NAMES: ReadonlySet<string> = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;

/** A surrogate without its partner: not text in UTF-8, and the encoder would turn it into U+FFFD. */
const LONE_SURROGATE = /\p{Cs}/u;

/** A new object without a prototype: any string is an ordinary key (`toString`, `__proto__`). */
export function dict<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

/** A shallow copy as a prototype-less object. */
export function copyDict<T>(source: Readonly<Record<string, T>>): Record<string, T> {
  const out = dict<T>();
  // for...in is about twice as fast as Object.assign on a large record; `hasOwn` skips anything
  // a foreign (non-null-prototype) source would inherit
  for (const key in source) if (Object.hasOwn(source, key)) out[key] = source[key] as T;
  return out;
}

/** The own entry of a record, never an inherited one. */
export function own<T>(
  record: Readonly<Record<string, T>> | undefined,
  key: string,
): T | undefined {
  return record !== undefined && Object.hasOwn(record, key) ? record[key] : undefined;
}

/** A plain data object (from JSON, or an object literal): no class instance, no Date, no Map. */
export function isPlain(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

/** Safe integers only: past 2^53 a clock no longer counts up. */
export const count = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

/** 1..max characters, no control or format character (bidi overrides, zero width, BOM), NFC form. */
export const label = (v: unknown, max: number): v is string =>
  typeof v === 'string' &&
  v.length >= 1 &&
  v.length <= max &&
  !CONTROL_OR_FORMAT.test(v) &&
  !LONE_SURROGATE.test(v) &&
  v.normalize('NFC') === v;

/** A label that is also safe as a key of an object. */
export const name = (v: unknown, max: number): v is string =>
  label(v, max) && !FORBIDDEN_NAMES.has(v);

interface Budget {
  nodes: number;
  problem?: Problem;
}

const FAIL = Symbol('fail');

function fail(budget: Budget, problem: Problem): typeof FAIL {
  budget.problem ??= problem;
  return FAIL;
}

/** A copy of a field value, or FAIL when it breaks a limit or is not plain JSON. */
function cleanValue(
  v: unknown,
  depth: number,
  limits: Limits,
  budget: Budget,
): unknown | typeof FAIL {
  // Every node is at least one character of JSON, so this also bounds the work on a huge value.
  if (++budget.nodes > limits.maxValueChars) return fail(budget, 'too-large');
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') return Number.isFinite(v) ? v : fail(budget, 'invalid-value');
  if (typeof v === 'string') {
    if (v.length > limits.maxText) return fail(budget, 'too-large');
    return LONE_SURROGATE.test(v) ? fail(budget, 'invalid-value') : v;
  }
  if (typeof v !== 'object') return fail(budget, 'invalid-value');
  if (depth >= limits.maxDepth) return fail(budget, 'too-large');
  if (Array.isArray(v)) {
    if (v.length > limits.maxEntries) return fail(budget, 'too-large');
    const out: unknown[] = [];
    for (let i = 0; i < v.length; i += 1) {
      if (!(i in v)) return fail(budget, 'invalid-value');
      const item = cleanValue(v[i], depth + 1, limits, budget);
      if (item === FAIL) return FAIL;
      out.push(item);
    }
    return out;
  }
  if (!isPlain(v)) return fail(budget, 'invalid-value');
  const keys = Object.keys(v);
  if (keys.length > limits.maxEntries) return fail(budget, 'too-large');
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    if (!name(key, limits.maxName)) return fail(budget, 'invalid-name');
    const item = cleanValue(v[key], depth + 1, limits, budget);
    if (item === FAIL) return FAIL;
    out[key] = item;
  }
  return out;
}

export type Checked<T> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly reason: Problem };

/**
 * The fields of a `set` change, strictly checked and copied: 1 to `maxFields` fields, names that are
 * safe keys, values that are plain JSON within the limits. The parser and local writing both use it,
 * so a change this device creates is never one a receiver would refuse.
 */
export function checkFields(raw: unknown, limits: Limits): Checked<Record<string, unknown>> {
  try {
    if (!isPlain(raw)) return { ok: false, reason: 'invalid-value' };
    const keys = Object.keys(raw);
    if (keys.length > limits.maxFields) return { ok: false, reason: 'too-many-fields' };
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      if (!name(key, limits.maxName)) return { ok: false, reason: 'invalid-name' };
      const budget: Budget = { nodes: 0 };
      const value = cleanValue(raw[key], 0, limits, budget);
      if (value === FAIL) return { ok: false, reason: budget.problem ?? 'invalid-value' };
      if (JSON.stringify(value).length > limits.maxValueChars) {
        return { ok: false, reason: 'too-large' };
      }
      out[key] = value;
    }
    return { ok: true, value: out };
  } catch {
    // a throwing getter or a revoked proxy
    return { ok: false, reason: 'invalid-value' };
  }
}

/** Collection name and record id of a change. */
export const validHead = (collection: unknown, id: unknown, limits: Limits): boolean =>
  name(collection, limits.maxId) && name(id, limits.maxId);

/** `time` and `by` of an origin as the parser reads them. */
export function validOrigin(origin: Origin, limits: Limits): boolean {
  const { time, by } = origin;
  if (time !== undefined && !count(time)) return false;
  return by === undefined || label(by, limits.maxName);
}
