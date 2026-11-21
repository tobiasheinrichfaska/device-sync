import { base64url, sha256Text } from './encoding.ts';

const MAX_DEPTH = 512;

/** A surrogate without its partner has no UTF-8 form (an encoder would write U+FFFD for it). */
const LONE_SURROGATE = /\p{Cs}/u;

function text(value: string): string {
  if (LONE_SURROGATE.test(value)) throw new TypeError('canonical: lone surrogate in a text');
  return JSON.stringify(value);
}

/**
 * JSON with sorted keys and no undefined object members: the same value always gives the same text.
 * Only plain JSON is canonical: null, booleans, finite numbers, strings, arrays and plain objects.
 * Anything else (Date, Map, Set, class instances, functions, symbols, bigint, NaN, Infinity,
 * `undefined` in an array, cycles, a lone surrogate in a text or key) throws a TypeError instead of being read as something else than
 * what a receiver gets from the JSON text. A top-level `undefined` is `null`.
 */
export function canonical(value: unknown): string {
  return value === undefined ? 'null' : write(value, new Set());
}

function write(value: unknown, parents: Set<object>): string {
  if (typeof value === 'string') return text(value);
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical: number is not finite');
    return JSON.stringify(value);
  }
  if (typeof value !== 'object') throw new TypeError(`canonical: ${typeof value} is not JSON`);
  if (parents.has(value)) throw new TypeError('canonical: cycle');
  if (parents.size >= MAX_DEPTH) throw new TypeError('canonical: nested too deep');
  parents.add(value);
  try {
    if (Array.isArray(value)) {
      const items: string[] = [];
      for (let i = 0; i < value.length; i += 1) {
        if (!(i in value) || value[i] === undefined) {
          throw new TypeError('canonical: undefined in an array');
        }
        items.push(write(value[i], parents));
      }
      return `[${items.join(',')}]`;
    }
    const proto = Object.getPrototypeOf(value) as unknown;
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError('canonical: not a plain object');
    }
    const record = value as Record<string, unknown>;
    const parts = Object.keys(record)
      .filter((k) => record[k] !== undefined)
      .sort()
      .map((k) => `${text(k)}:${write(record[k], parents)}`);
    return `{${parts.join(',')}}`;
  } finally {
    parents.delete(value);
  }
}

/** Check value of any value: base64url(SHA-256(canonical(value))). */
export function checkValue(value: unknown): string {
  return base64url(sha256Text(canonical(value)));
}
