// docs/review.md is a promise to whoever builds a review screen. These tests hold the code to the codes
// and entry points written in it.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import * as log from '../../src/log/index.ts';

const DOC = readFileSync(new URL('../../docs/review.md', import.meta.url), 'utf8');
const SOURCE = readFileSync(new URL('../../src/log/review.ts', import.meta.url), 'utf8');

function section(title: string): string {
  const start = DOC.indexOf(`\n## ${title}`);
  expect(start, title).toBeGreaterThan(-1);
  const next = DOC.indexOf('\n## ', start + 4);
  return DOC.slice(start, next === -1 ? undefined : next);
}

describe('docs/review.md against the code', () => {
  it('every documented code is in the source, every code the source writes is documented', () => {
    const documented = new Set(
      [...section('Codes').matchAll(/^\| `([a-z-]+)`\s*\|/gm)].map((m) => m[1] as string),
    );
    const written = new Set(
      [...SOURCE.matchAll(/fail\('([a-z-]+)'\)/g)].map((m) => m[1] as string),
    );
    const kinds = new Set(
      [...SOURCE.matchAll(/^\s*\| '([a-z-]+)';?$/gm)]
        .map((m) => m[1] as string)
        .filter((k) => ['concurrent-requests', 'approval-not-known', 'approver-clash'].includes(k)),
    );
    expect(kinds.size).toBe(3);
    for (const code of documented) expect(SOURCE.includes(`'${code}'`), code).toBe(true);
    for (const code of [...written, ...kinds]) expect(documented.has(code), code).toBe(true);
    expect(documented.size).toBe(written.size + kinds.size);
  });

  it('names every entry point, and each is exported from the log layer', () => {
    for (const name of [
      'review',
      'reviewView',
      'reviewRequests',
      'reviewConflicts',
      'reviewSettlements',
      'approveChange',
      'keepValue',
      'correctValue',
      'approveAll',
      'takeApproverValue',
    ]) {
      expect(DOC, name).toContain(name);
      expect(SOURCE, name).toContain(`export function ${name}`);
      expect(typeof (log as Record<string, unknown>)[name], name).toBe('function');
    }
  });

  it('names the config members and the two models', () => {
    for (const word of [
      'isApprover',
      'reviewed',
      'hiddenField',
      'Replica.approval',
      'mergeApproved',
    ]) {
      expect(DOC, word).toContain(word);
    }
    for (const member of ['isApprover', 'reviewed', 'hiddenField']) {
      expect(SOURCE, member).toMatch(new RegExp(`readonly ${member}\\??:`));
    }
  });
});
