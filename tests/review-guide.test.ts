// The review guide points a human reviewer at files. A path that does not exist wastes their time, so
// every repository path written in backticks in docs/review-guide.md must exist.
import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const ROOT = new URL('..', import.meta.url);
const GUIDE = readFileSync(new URL('docs/review-guide.md', ROOT), 'utf8');

const mentioned = [...GUIDE.matchAll(/`([^`\n]+)`/g)]
  .map((m) => (m[1] as string).replace(/:\d+$/, ''))
  .filter((text) => /^(src|tests|docs)\/[A-Za-z0-9_./-]+$/.test(text));

describe('docs/review-guide.md', () => {
  it('names a good number of paths', () => {
    expect(new Set(mentioned).size).toBeGreaterThan(60);
  });

  it('every path in backticks exists', () => {
    const missing = [...new Set(mentioned)].filter((p) => !existsSync(new URL(p, ROOT)));
    expect(missing).toEqual([]);
  });
});
