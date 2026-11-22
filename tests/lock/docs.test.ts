// docs/lock.md is held to the code: limits and codes.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  LOCK_LIMITS,
  MAX_ORDER_CHARS,
  type LockNotCounted,
  type LockReason,
  type LockRefusal,
  type OrderRefusal,
} from '../../src/lock/index.ts';

const DOC = readFileSync(new URL('../../docs/lock.md', import.meta.url), 'utf8');
const spaced = (n: number): string => n.toLocaleString('en').replace(/,/g, ' ');

const REFUSALS: Record<LockRefusal | OrderRefusal, true> = {
  'bad-input': true,
  'bad-config': true,
  'time-went-back': true,
  'too-many-sources': true,
  'not-a-state': true,
  'not-an-order': true,
  'wrong-device': true,
  'not-allowed': true,
  'unknown-key': true,
  'bad-signature': true,
  replayed: true,
};
const REASONS: Record<LockReason, true> = {
  removed: true,
  operator: true,
  clock: true,
  expired: true,
};
const NOT_COUNTED: Record<LockNotCounted, true> = {
  'other-source': true,
  removed: true,
  locked: true,
  'same-peer': true,
  old: true,
  'clock-differs': true,
};

describe('docs/lock.md', () => {
  it('names every code', () => {
    // `not-a-state` is reserved for callers; the reader answers undefined
    for (const c of Object.keys(REFUSALS)) {
      if (c === 'not-a-state') continue;
      expect(DOC, c).toContain(`\`${c}\``);
    }
    for (const c of [...Object.keys(REASONS), ...Object.keys(NOT_COUNTED)]) {
      expect(DOC, c).toContain(`\`${c}\``);
    }
  });
  it('states the limits', () => {
    expect(DOC).toContain(`| ${LOCK_LIMITS.maxDaysCeiling} `);
    expect(DOC).toContain(`at most ${spaced(LOCK_LIMITS.maxStateChars)} characters`);
    expect(DOC).toContain(`at most ${spaced(MAX_ORDER_CHARS)} characters`);
    expect(DOC).toContain(`${LOCK_LIMITS.maxSources - 1} (`);
    expect(DOC).toContain('86 400 000');
    expect(DOC).toContain('2 592 000 000');
  });
});
