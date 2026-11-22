// docs/sync.md is a promise to the app that wires the layers. These tests hold the code to the
// numbers and codes written in it.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SYNC_CODES, SYNC_LIMITS, syncMark, writePacket } from '../../src/sync/index.ts';

const DOC = readFileSync(new URL('../../docs/sync.md', import.meta.url), 'utf8');

function section(title: string): string {
  const start = DOC.indexOf(`\n## ${title}`);
  expect(start, title).toBeGreaterThan(-1);
  const next = DOC.indexOf('\n## ', start + 4);
  return DOC.slice(start, next === -1 ? undefined : next);
}

describe('docs/sync.md against the code', () => {
  it('the limits table lists exactly SYNC_LIMITS with the same values', () => {
    const rows = [...DOC.matchAll(/^\| `(\w+)`\s*\|\s*([0-9_]+)\s*\|/gm)];
    const documented = Object.fromEntries(
      rows.map((m) => [m[1], Number((m[2] as string).replaceAll('_', ''))]),
    );
    expect(Object.keys(documented).sort()).toEqual(Object.keys(SYNC_LIMITS).sort());
    for (const [name, value] of Object.entries(SYNC_LIMITS))
      expect(documented[name], name).toBe(value);
  });

  it('the code table lists exactly SYNC_CODES', () => {
    const rows = [...section('Codes').matchAll(/^\| `([a-z-]+)`\s*\|/gm)].map(
      (m) => m[1] as string,
    );
    expect([...rows].sort()).toEqual([...SYNC_CODES].sort());
  });

  it('every code is written by the source', () => {
    const src = ['step.ts', 'roster.ts'].map((f) =>
      readFileSync(new URL(`../../src/sync/${f}`, import.meta.url), 'utf8'),
    );
    const text = src.join('\n');
    for (const code of SYNC_CODES) expect(text.includes(`'${code}'`), code).toBe(true);
  });

  it('the packet text is the one written in the document', () => {
    expect(DOC).toContain('{"m":"<app>-sync:1","r":"<16 hex>","msg":{...}}');
    const text = new TextDecoder().decode(
      writePacket('demo', '0123456789abcdef', { t: 'stand', vector: {}, tips: {} }),
    );
    expect(text.startsWith(`{"m":"${syncMark('demo')}","r":"0123456789abcdef","msg":`)).toBe(true);
    expect(syncMark('demo')).toBe('demo-sync:1');
  });

  it('the figures quoted from the relay are the relay limits', () => {
    expect(DOC).toContain('65 536');
    expect(DOC).toContain('40 000 bytes');
  });
});
