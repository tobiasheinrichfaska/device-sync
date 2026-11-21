import { LIMITS, type Change, type SyncMessage, type VersionVector } from '../../src/log/index.ts';

export type Rng = () => number;

export const CHECK = 'c'.repeat(43);
export const SIG = 's'.repeat(86);

export const int = (rng: Rng, max: number): number => Math.floor(rng() * max);
export const pick = <T>(rng: Rng, items: readonly T[]): T => items[int(rng, items.length)] as T;

const WORDS = [
  'alpha',
  'Ä ö ü ß',
  'x',
  'emoji 😀',
  'line "quoted"',
  'a/b',
  '',
  ' ',
  'ключ',
  '日本語',
];
const NAMES = ['title', 'note', 'count', 'tags', 'a', 'b', 'item-1', 'Ünï', 'x.y'];
const DEVICES = ['a', 'b', 'c', 'dev-1', 'Device_2', 'd.e'];

/** A random JSON value that is valid for a field (within the default limits). */
export function randomValue(rng: Rng, depth = 0): unknown {
  const kind = int(rng, depth >= 3 ? 5 : 7);
  switch (kind) {
    case 0:
      return null;
    case 1:
      return rng() < 0.5;
    case 2:
      return int(rng, 2_000_000) - 1_000_000 + (rng() < 0.3 ? rng() : 0);
    case 3:
    case 4:
      return pick(rng, WORDS);
    case 5:
      return Array.from({ length: int(rng, 4) }, () => randomValue(rng, depth + 1));
    default:
      return Object.fromEntries(
        Array.from({ length: int(rng, 4) }, () => [pick(rng, NAMES), randomValue(rng, depth + 1)]),
      );
  }
}

export function randomVector(rng: Rng): VersionVector {
  return Object.fromEntries(
    Array.from({ length: int(rng, 4) }, () => [pick(rng, DEVICES), int(rng, 1000)]),
  );
}

/** A random change that must be accepted by the parser. */
export function randomChange(rng: Rng): Change {
  const kind = pick(rng, ['set', 'set', 'delete', 'redacted'] as const);
  const base = {
    device: pick(rng, DEVICES),
    seq: 1 + int(rng, 1000),
    clock: 1 + int(rng, 100000),
    collection: pick(rng, ['items', 'lists', 'x']),
    id: pick(rng, ['r1', 'record 2', 'ä']),
    kind,
  };
  const optional = {
    knew: randomVector(rng),
    ...(rng() < 0.5 ? { time: int(rng, 2 ** 40) } : {}),
    ...(rng() < 0.5
      ? {
          by: pick(
            rng,
            WORDS.filter((w) => w.trim()),
          ),
        }
      : {}),
    ...(rng() < 0.5 ? { check: CHECK, ...(rng() < 0.5 ? { sig: SIG } : {}) } : {}),
  };
  if (kind !== 'set') return { ...base, ...optional };
  const fields = Object.fromEntries(
    Array.from({ length: 1 + int(rng, 4) }, () => [pick(rng, NAMES), randomValue(rng)]),
  );
  return { ...base, ...optional, fields };
}

export function randomMessage(rng: Rng): SyncMessage {
  const t = pick(rng, ['stand', 'changes', 'done'] as const);
  if (t === 'stand') return { t, vector: randomVector(rng) };
  if (t === 'done') return { t, vector: randomVector(rng), fingerprint: '0123abcd'.repeat(4) };
  return {
    t,
    changes: Array.from({ length: int(rng, 4) }, () => randomChange(rng)),
    last: rng() < 0.5,
  };
}

/** Random JSON-like garbage, including things JSON cannot carry (NaN, functions, symbols, Dates ...). */
export function garbage(rng: Rng, depth = 0): unknown {
  const kind = int(rng, depth >= 3 ? 14 : 18);
  switch (kind) {
    case 0:
      return null;
    case 1:
      return undefined;
    case 2:
      return rng() < 0.5;
    case 3:
      return pick(rng, [Number.NaN, Infinity, -Infinity, -0, 2 ** 53, -1, 1.5, 1e308, 0, 1]);
    case 4:
      return int(rng, 100) - 10;
    case 5:
      return pick(rng, WORDS);
    case 6:
      return 'x'.repeat(int(rng, 4000));
    case 7:
      return () => 1;
    case 8:
      return Symbol('s');
    case 9:
      return BigInt(int(rng, 100));
    case 10:
      return new Date(int(rng, 1e12));
    case 11:
      return new Map();
    case 12:
      return pick(rng, ['stand', 'changes', 'done', 'set', 'delete', 'redacted', '__proto__']);
    case 13:
      return 'a\u0000b';
    case 14:
    case 15:
      return Array.from({ length: int(rng, 5) }, () => garbage(rng, depth + 1));
    default: {
      const keys = [
        't',
        'vector',
        'changes',
        'last',
        'device',
        'seq',
        'clock',
        'fields',
        'kind',
        'x',
      ];
      const entries = Array.from({ length: int(rng, 6) }, () => [
        rng() < 0.7 ? pick(rng, keys) : pick(rng, WORDS),
        garbage(rng, depth + 1),
      ]);
      return Object.fromEntries(entries);
    }
  }
}

/** A nested list `levels` deep, built without recursion. */
export function nestedList(levels: number, inner: unknown = 1): unknown {
  let v: unknown = inner;
  for (let i = 0; i < levels; i += 1) v = [v];
  return v;
}

export function nestedObject(levels: number, inner: unknown = 1): unknown {
  let v: unknown = inner;
  for (let i = 0; i < levels; i += 1) v = { k: v };
  return v;
}

function containers(root: unknown): (unknown[] | Record<string, unknown>)[] {
  const out: (unknown[] | Record<string, unknown>)[] = [];
  const seen = new Set<unknown>();
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v !== 'object' || v === null || seen.has(v)) continue;
    seen.add(v);
    out.push(v as never);
    stack.push(...Object.values(v));
  }
  return out;
}

const WEIRD_NUMBERS: unknown[] = [-1, 1.5, 2 ** 53, 2 ** 63, 1e308, 1e-9, '5', '', null, true];

/** Defines an own, enumerable key even when it is `__proto__`. */
function setOwn(o: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(o, key, { value, enumerable: true, configurable: true, writable: true });
}

/** One random mutation of a deep clone of `valid` (never touches `valid`). */
export function mutate(rng: Rng, valid: unknown): unknown {
  const root = structuredClone(valid);
  const all = containers(root);
  const target = pick(rng, all);
  const isList = Array.isArray(target);
  const keys = isList ? target.map((_, i) => String(i)) : Object.keys(target);
  const key = keys.length > 0 ? pick(rng, keys) : 'x';
  const rec = target as Record<string, unknown>;
  switch (int(rng, 10)) {
    case 0:
      if (isList) target.splice(Number(key), 1);
      else delete rec[key];
      break;
    case 1:
      if (!isList) setOwn(rec, key + '2', structuredClone(rec[key]));
      else target.push(structuredClone(target[Number(key)]));
      break;
    case 2:
      rec[key] = garbage(rng, 2);
      break;
    case 3:
      rec[key] = pick(rng, WEIRD_NUMBERS);
      break;
    case 4:
      if (!isList) setOwn(rec, pick(rng, ['unknown', 'extra', 'v', 'fields2']), garbage(rng, 2));
      break;
    case 5:
      if (!isList)
        setOwn(rec, pick(rng, ['__proto__', 'constructor', 'prototype']), garbage(rng, 2));
      break;
    case 6:
      rec[key] = nestedList(int(rng, 2) === 0 ? 7 : 20000, rng() < 0.5 ? 1 : {});
      break;
    case 7:
      rec[key] = Array.from(
        { length: pick(rng, [LIMITS.maxEntries, LIMITS.maxEntries + 1, LIMITS.maxChanges + 1]) },
        () => 1,
      );
      break;
    case 8:
      rec[key] = 'x'.repeat(pick(rng, [LIMITS.maxText, LIMITS.maxText + 1, LIMITS.maxName + 1]));
      break;
    default:
      if (!isList) setOwn(rec, 'k' + int(rng, 100), pick(rng, WEIRD_NUMBERS));
      else target.length = Math.max(0, target.length - 1);
  }
  return root;
}

/** All object/array references reachable from a value (for the aliasing check). */
export function references(root: unknown): Set<unknown> {
  return new Set(containers(root));
}
