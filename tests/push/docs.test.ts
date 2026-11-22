// docs/push.md is a promise to anyone who implements the other side. These tests hold the code to the
// numbers and codes written in it.
import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PUSH_LIMITS } from '../../src/push/index.ts';
import { RELAY_LIMITS } from '../../src/relay/index.ts';

const DOC = readFileSync(new URL('../../docs/push.md', import.meta.url), 'utf8');
const SRC = new URL('../../src/push/', import.meta.url);

function section(title: string): string {
  const start = DOC.indexOf(`\n## ${title}`);
  expect(start, title).toBeGreaterThan(-1);
  const next = DOC.indexOf('\n## ', start + 4);
  return DOC.slice(start, next === -1 ? undefined : next);
}

describe('docs/push.md against the code', () => {
  it('the limits table lists exactly PUSH_LIMITS, with the same values', () => {
    const rows = [...section('Limits').matchAll(/^\| `(\w+)`\s*\|\s*([0-9_]+)\s*\|/gm)];
    const documented = Object.fromEntries(
      rows.map((m) => [m[1], Number((m[2] as string).replaceAll('_', ''))]),
    );
    expect(Object.keys(documented).sort()).toEqual(Object.keys(PUSH_LIMITS).sort());
    for (const [name, value] of Object.entries(PUSH_LIMITS))
      expect(documented[name], name).toBe(value);
  });

  it('the four ring limits are the relay limits', () => {
    expect(PUSH_LIMITS.ringEndpointMax).toBe(RELAY_LIMITS.ringEndpointMax);
    expect(PUSH_LIMITS.ringVapidMax).toBe(RELAY_LIMITS.ringVapidMax);
    expect(PUSH_LIMITS.ringContentMax).toBe(RELAY_LIMITS.ringContentMax);
    expect(PUSH_LIMITS.ringTtlMax).toBe(RELAY_LIMITS.ringTtlMax);
  });

  it('the header is 86 octets and the room for padding is the one the text states', () => {
    expect(PUSH_LIMITS.saltBytes + 4 + 1 + PUSH_LIMITS.pointBytes).toBe(PUSH_LIMITS.headerBytes);
    expect(PUSH_LIMITS.ringContentMax - PUSH_LIMITS.headerBytes - PUSH_LIMITS.recordOverhead).toBe(
      3993,
    );
    expect(DOC).toContain('room for 3993 octets of padding');
  });

  it('every documented code is in the source, and every code the source writes is documented', () => {
    const rows = [...section('Codes').matchAll(/^\| `\w+`\s*\|(.*)\|\s*$/gm)];
    const documented = new Set(
      rows.flatMap((m) =>
        [...(m[1] as string).matchAll(/`([a-z0-9-]+)`/g)].map((c) => c[1] as string),
      ),
    );
    const text = readdirSync(SRC)
      .filter((f) => f.endsWith('.ts'))
      .map((f) => readFileSync(new URL(f, SRC), 'utf8'))
      .join('\n');
    for (const code of documented) expect(text.includes(`'${code}'`), code).toBe(true);
    const written = new Set(
      [...text.matchAll(/fail\('([a-z0-9-]+)'\)/g)].map((m) => m[1] as string),
    );
    for (const code of written) expect(documented.has(code), code).toBe(true);
  });

  it('the RFC vectors the text cites are in the vector file', () => {
    const v = JSON.parse(
      readFileSync(new URL('../vectors/push.json', import.meta.url), 'utf8'),
    ) as Record<string, unknown>;
    expect(Object.keys(v)).toEqual(expect.arrayContaining(['rfc8291', 'rfc8292']));
    expect(DOC).toContain('tests/vectors/push.json');
  });
});
