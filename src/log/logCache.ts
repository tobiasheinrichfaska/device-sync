import type { Change } from './types.ts';

interface Entry<T> {
  readonly value: T;
  readonly length: number;
  readonly last: Change | undefined;
}

/**
 * Remembers something derived from a log array. Replicas are immutable values (a merge builds a new
 * log array); the cache is still checked against the array's length and last element, so a log
 * that was appended to or had its last entry replaced in place is derived again instead of served
 * stale. Changing a middle entry in place is not detected: do not mutate replicas.
 */
export class LogCache<T> {
  private readonly entries = new WeakMap<readonly Change[], Entry<T>>();

  get(log: readonly Change[]): T | undefined {
    const entry = this.entries.get(log);
    return entry && entry.length === log.length && entry.last === log[log.length - 1]
      ? entry.value
      : undefined;
  }

  set(log: readonly Change[], value: T): void {
    this.entries.set(log, { value, length: log.length, last: log[log.length - 1] });
  }

  /** The remembered value, or the one `build` makes (and remembers). */
  getOrBuild(log: readonly Change[], build: () => T): T {
    const known = this.get(log);
    if (known !== undefined) return known;
    const value = build();
    this.set(log, value);
    return value;
  }
}
