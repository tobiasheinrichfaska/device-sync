// "The state at rest" in docs/group.md is held to the code.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  REST_IV_BYTES,
  REST_VERSION,
  type OpenStateRefusal,
  type SealStateRefusal,
} from '../../src/group/index.ts';

const DOC = readFileSync(new URL('../../docs/group.md', import.meta.url), 'utf8');
const SRC = readFileSync(new URL('../../src/group/rest.ts', import.meta.url), 'utf8');
const start = DOC.indexOf('\n## The state at rest');
const SECTION = DOC.slice(start, DOC.indexOf('\n## ', start + 4));

const SEAL: Record<SealStateRefusal, true> = {
  'bad-input': true,
  'bad-key': true,
  'bad-random': true,
  'too-large': true,
  'crypto-failure': true,
};
const OPEN: Record<OpenStateRefusal, true> = {
  'bad-input': true,
  'bad-key': true,
  'not-sealed': true,
  truncated: true,
  'unsupported-version': true,
  'wrong-data-set': true,
  'cannot-open': true,
  'bad-state': true,
};

describe('docs/group.md, the state at rest', () => {
  it('exists and says what the format is', () => {
    expect(start).toBeGreaterThan(-1);
    expect(REST_VERSION).toBe(1);
    expect(REST_IV_BYTES).toBe(12);
    expect(SECTION).toContain('{"m":"<appId>-grest:1","set":"<set>","iv":"<12 bytes>"');
    expect(SECTION).toContain('<appId>-grest:1|<byte length>:<set>');
    expect(SRC).toContain("'grest'");
  });

  it('every code is documented and every documented code is a code of the source', () => {
    for (const code of [...Object.keys(SEAL), ...Object.keys(OPEN)]) {
      expect(SECTION, code).toContain(`\`${code}\``);
      expect(SRC, code).toContain(`'${code}'`);
    }
  });

  it('says what it protects and what it does not', () => {
    for (const phrase of [
      '**What it protects.**',
      '**What it does NOT protect.**',
      'A script running in the origin',
      'A rollback.',
      'valid sealed text and opens fine',
      'Message budget',
    ])
      expect(SECTION, phrase).toContain(phrase);
  });
});
