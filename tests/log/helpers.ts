import {
  findRecord,
  merge,
  missingFor,
  valuesOf,
  write,
  type Replica,
  type WriteResult,
} from '../../src/log/index.ts';

export const COL = 'items';

export function ok(result: WriteResult): Replica {
  if (!result.ok) throw new Error(`refused: ${result.reason}`);
  return result.replica;
}

export const written = (
  replica: Replica,
  id: string,
  fields: Record<string, unknown>,
  origin: { time?: number; by?: string } = {},
): Replica => ok(write(replica, COL, id, fields, origin));

/** Hands over everything `to` lacks, as one exchange would. */
export const sync = (from: Replica, to: Replica): Replica =>
  merge(to, missingFor(from, to.vector)).replica;

export const values = (replica: Replica, id: string): Record<string, unknown> | undefined => {
  const record = findRecord(replica, COL, id);
  return record ? valuesOf(record) : undefined;
};

export function permutations<T>(items: readonly T[]): T[][] {
  if (items.length <= 1) return [[...items]];
  return items.flatMap((item, i) =>
    permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [item, ...rest]),
  );
}

/** Tiny seeded PRNG (mulberry32): same seed, same sequence. */
export function prng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
