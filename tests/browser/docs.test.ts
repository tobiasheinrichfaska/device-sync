// docs/browser.md is a promise to anyone who builds on this layer. These tests hold the code to the numbers
// and codes written in it.
import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  BROWSER_LIMITS,
  LEADER_DEFAULTS,
  RECORD_NAMES,
  STORE_NAME,
  leaderConfigProblem,
} from '../../src/browser/index.ts';

const DOC = readFileSync(new URL('../../docs/browser.md', import.meta.url), 'utf8');
const SRC = new URL('../../src/browser/', import.meta.url);

function section(title: string): string {
  const start = DOC.indexOf(`\n## ${title}`);
  expect(start, title).toBeGreaterThan(-1);
  const next = DOC.indexOf('\n## ', start + 4);
  return DOC.slice(start, next === -1 ? undefined : next);
}

const table = (title: string): Record<string, number> => {
  const rows = [...section(title).matchAll(/^\| `(\w+)`\s*\|\s*([0-9_]+)\s*\|/gm)];
  return Object.fromEntries(rows.map((m) => [m[1], Number((m[2] as string).replaceAll('_', ''))]));
};

describe('docs/browser.md against the code', () => {
  it('the limits table lists exactly BROWSER_LIMITS, with the same values', () => {
    const documented = table('Limits');
    expect(Object.keys(documented).sort()).toEqual(Object.keys(BROWSER_LIMITS).sort());
    for (const [name, value] of Object.entries(BROWSER_LIMITS))
      expect(documented[name], name).toBe(value);
  });

  it('the leader defaults table lists exactly LEADER_DEFAULTS, and they satisfy the timing rules', () => {
    const documented = table('Leader defaults');
    expect(Object.keys(documented).sort()).toEqual(Object.keys(LEADER_DEFAULTS).sort());
    for (const [name, value] of Object.entries(LEADER_DEFAULTS))
      expect(documented[name], name).toBe(value);
    expect(leaderConfigProblem({ id: 'x', ...LEADER_DEFAULTS })).toBeUndefined();
    const d = LEADER_DEFAULTS;
    expect(d.timeoutMs).toBeGreaterThan(d.heartbeatMs + d.delayMs + d.lateMs);
    expect(d.timeoutMs).toBeGreaterThan(2 * d.delayMs + d.lateMs);
    expect(DOC).toContain('4 000 is above 3 000 for each');
  });

  it('the two timing conditions of the text are the ones the code enforces', () => {
    const c = { id: 'x', heartbeatMs: 100, delayMs: 100, lateMs: 100 };
    expect(leaderConfigProblem({ ...c, timeoutMs: 300 })).toBe('bad-config');
    expect(leaderConfigProblem({ ...c, timeoutMs: 301 })).toBeUndefined();
    const d = { id: 'x', heartbeatMs: 1, delayMs: 100, lateMs: 100 };
    expect(leaderConfigProblem({ ...d, timeoutMs: 300 })).toBe('bad-config');
    expect(leaderConfigProblem({ ...d, timeoutMs: 301 })).toBeUndefined();
    expect(DOC).toContain('`timeoutMs > heartbeatMs + delayMs + lateMs`');
    expect(DOC).toContain('`timeoutMs > 2 * delayMs + lateMs`');
  });

  it('every documented code is in the source, and every code the source writes is documented', () => {
    const rows = [...section('Codes').matchAll(/^\| [^|]+\|(.*)\|\s*$/gm)];
    const documented = new Set(
      rows.flatMap((m) =>
        [...(m[1] as string).matchAll(/`([a-z0-9-]+)`/g)].map((c) => c[1] as string),
      ),
    );
    expect(documented.size).toBeGreaterThan(15);
    const text = readdirSync(SRC)
      .filter((f) => f.endsWith('.ts'))
      .map((f) => readFileSync(new URL(f, SRC), 'utf8'))
      .join('\n');
    for (const code of documented) expect(text.includes(`'${code}'`), code).toBe(true);
    const written = new Set(
      [...text.matchAll(/fail\('([a-z0-9-]+)'\)/g)].map((m) => m[1] as string),
    );
    for (const code of written) expect(documented.has(code), code).toBe(true);
    // codes returned by tables and by `reasonOf`/`mediaErrorCode` rather than by `fail(...)`
    for (const code of ['quota', 'aborted', 'closed', 'bad-value', 'denied', 'not-found', 'in-use'])
      expect(documented.has(code), code).toBe(true);
  });

  it('the schema the text describes is the schema in the code', () => {
    expect(STORE_NAME).toBe('records');
    expect(DOC).toContain('one object store `records`');
    expect(DOC).toContain('schema version 1');
    expect(DOC).toContain("{ v: 1, kind: 'text', text }");
    for (const name of Object.values(RECORD_NAMES)) expect(DOC).toContain(`\`${name}\``);
    expect(DOC).toContain('at most 8 192 characters');
    expect(DOC).toContain('1 to 4 096');
    expect(DOC).toContain('1 to 1 048 576');
    expect(BROWSER_LIMITS.textMax).toBe(8192);
    expect(BROWSER_LIMITS.frameSideMax).toBe(4096);
    expect(BROWSER_LIMITS.samplesMax).toBe(1_048_576);
  });

  it('the message kinds and the lock name prefix of the text are the ones in the code', () => {
    const leader = readFileSync(new URL('leader.ts', SRC), 'utf8');
    for (const kind of ['beat', 'claim', 'bye']) {
      expect(DOC).toContain(`\`${kind}\``);
      expect(leader).toContain(`'${kind}'`);
    }
    expect(DOC).toContain('`device-sync:<name>`');
    expect(readFileSync(new URL('listener.ts', SRC), 'utf8')).toContain('`device-sync:${o.name}`');
  });

  it('the text says it was not run in a browser', () => {
    expect(DOC).toContain('never run in a real browser');
  });
});
