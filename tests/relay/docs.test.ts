// The protocol document is a promise to anyone who implements a relay or a client elsewhere. These
// tests read it and hold the code to the words and numbers written in it.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  ENDPOINTS,
  FRAMING_LIMITS,
  RELAY_KINDS,
  RELAY_LIMITS,
  WIRE_MEMBERS,
} from '../../src/relay/index.ts';

const DOC = readFileSync(new URL('../../docs/relay-protocol.md', import.meta.url), 'utf8');

function section(title: string): string {
  const start = DOC.indexOf(`\n## ${title}`);
  expect(start, title).toBeGreaterThan(-1);
  const next = DOC.indexOf('\n## ', start + 4);
  return DOC.slice(start, next === -1 ? undefined : next);
}

const num = (text: string): number => Number(text.replaceAll('_', ''));

describe('docs/relay-protocol.md against the code', () => {
  it('the limits table lists exactly RELAY_LIMITS, with the same values', () => {
    const rows = [...section('Limits').matchAll(/^\| `(\w+)`\s*\|\s*([0-9_]+)\s*\|/gm)];
    const documented = Object.fromEntries(rows.map((m) => [m[1], num(m[2] as string)]));
    expect(Object.keys(documented).sort()).toEqual(Object.keys(RELAY_LIMITS).sort());
    for (const [name, value] of Object.entries(RELAY_LIMITS))
      expect(documented[name], name).toBe(value);
  });

  it('the framing table lists exactly FRAMING_LIMITS, with the same values', () => {
    const rows = [
      ...section('Message framing (a client convention, not part of the relay protocol)').matchAll(
        /^\| `(\w+)`\s*\|\s*([0-9_]+)\s*\|/gm,
      ),
    ];
    const documented = Object.fromEntries(rows.map((m) => [m[1], num(m[2] as string)]));
    expect(Object.keys(documented).sort()).toEqual(Object.keys(FRAMING_LIMITS).sort());
    for (const [name, value] of Object.entries(FRAMING_LIMITS)) {
      expect(documented[name], name).toBe(value);
    }
  });

  it('the endpoint and member tables are the mapping of the code', () => {
    const pairs = [
      ...section('English names in this package').matchAll(/^\| `(\w+)`\s*\| `(\w+)`\s*\|/gm),
    ].map((m) => [m[1], m[2]] as const);
    const code = { ...ENDPOINTS, ...WIRE_MEMBERS } as Record<string, string>;
    const documented = new Map(pairs);
    expect([...documented.keys()].sort()).toEqual(Object.keys(code).sort());
    for (const [api, wire] of Object.entries(code)) expect(documented.get(api), api).toBe(wire);
  });

  it('the error table has a row for every kind of the code and no other, with status and class', () => {
    const rows = [
      ...section('Error kinds').matchAll(
        /^\| `([a-z-]+)`\s*\| `([a-z-]+)`\s*\| (\d{3}|—)\s*\| (fatal|retry|reenrol|refused)\s*\|/gm,
      ),
    ];
    const documented = new Map(rows.map((m) => [m[1] as string, m]));
    expect([...documented.keys()].sort()).toEqual(RELAY_KINDS.map((k) => k.token).sort());
    for (const k of RELAY_KINDS) {
      const m = documented.get(k.token)!;
      expect(m[2], k.token).toBe(k.name);
      expect(m[3] === '—' ? null : Number(m[3]), k.token).toBe(k.status);
      expect(m[4], k.token).toBe(k.class);
    }
  });

  it('the token formats and lifetimes written in the document are the ones the limits say', () => {
    expect(DOC).toContain('7 776 000 s');
    expect(RELAY_LIMITS.accessDays * 86_400).toBe(7_776_000);
    expect(DOC).toContain('`now < bis <= now + 600`');
    expect(RELAY_LIMITS.invitationSeconds).toBe(600);
    expect(DOC).toContain('`now < bis <= now + 360`');
    expect(RELAY_LIMITS.proofMaxSeconds + RELAY_LIMITS.proofSkewSeconds).toBe(360);
    expect(DOC).toContain('Access-Control-Max-Age: 600');
  });

  it('there is a section of open points and a test interface section', () => {
    expect(DOC).toContain('## Open points of version 1');
    expect(DOC).toContain('## Test interface (optional for servers)');
    for (const op of [
      'reset()',
      'advanceTime(ms)',
      'setLimits(overrides)',
      'setPushResult(result)',
    ]) {
      expect(DOC).toContain(op);
    }
  });

  it('every wire word of the endpoints appears in the cases', () => {
    const cases = readFileSync(new URL('./conformance/cases.json', import.meta.url), 'utf8');
    for (const wire of Object.values(ENDPOINTS)) expect(cases, wire).toContain(wire);
  });
});
