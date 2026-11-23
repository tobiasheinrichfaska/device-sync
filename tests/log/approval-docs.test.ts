// docs/approval.md is a promise to whoever writes the hook. These tests hold the code to the numbers
// and codes written in it.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { APPROVAL_LIMITS } from '../../src/log/index.ts';

const DOC = readFileSync(new URL('../../docs/approval.md', import.meta.url), 'utf8');
const SOURCE = readFileSync(new URL('../../src/log/approval.ts', import.meta.url), 'utf8');

function section(title: string): string {
  const start = DOC.indexOf(`\n## ${title}`);
  expect(start, title).toBeGreaterThan(-1);
  const next = DOC.indexOf('\n## ', start + 4);
  return DOC.slice(start, next === -1 ? undefined : next);
}

describe('docs/approval.md against the code', () => {
  it('the limits table lists exactly APPROVAL_LIMITS, with the same values', () => {
    const rows = [...section('Limits').matchAll(/^\| `(\w+)`\s*\|\s*([0-9_]+)\s*\|/gm)];
    const documented = Object.fromEntries(
      rows.map((m) => [m[1], Number((m[2] as string).replaceAll('_', ''))]),
    );
    expect(Object.keys(documented).sort()).toEqual(Object.keys(APPROVAL_LIMITS).sort());
    for (const [name, value] of Object.entries(APPROVAL_LIMITS)) {
      expect(documented[name], name).toBe(value);
    }
  });

  it('every documented code is in the source and every code the reader writes is documented', () => {
    const rows = [...section('Codes').matchAll(/^\| `([a-z-]+)`\s*\|/gm)];
    const documented = new Set(rows.map((m) => m[1] as string));
    const written = new Set(
      [...SOURCE.matchAll(/fail\('([a-z-]+)'\)/g)].map((m) => m[1] as string),
    );
    for (const code of documented) expect(SOURCE.includes(`'${code}'`), code).toBe(true);
    for (const code of written) expect(documented.has(code), code).toBe(true);
    expect(documented.size).toBeGreaterThanOrEqual(9);
  });

  it('names the decisions and the entry points the code has', () => {
    for (const word of ['apply', 'hold', 'reject']) expect(DOC).toContain(`\`${word}\``);
    for (const name of [
      'mergeApproved',
      'pendingApproval',
      'approve',
      'reject',
      'decide',
      'readApprovalState',
    ]) {
      expect(DOC, name).toContain(name);
      expect(SOURCE, name).toContain(`export function ${name}`);
    }
  });
});
