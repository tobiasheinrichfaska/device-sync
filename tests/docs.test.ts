// The wire-format document is a promise to anyone who implements the format elsewhere. These tests
// read the document and hold the code to the numbers and examples written in it.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  FORMAT_VERSION,
  LIMITS,
  canonical,
  changeSigningText,
  checkCode,
  checkValue,
  emptyReplica,
  fingerprint,
  generateDeviceKeys,
  marker,
  publicKeys,
  type Change,
} from '../src/index.ts';

const DOC = readFileSync(new URL('../docs/wire-format.md', import.meta.url), 'utf8');

describe('docs/wire-format.md against the code', () => {
  it('the limits table lists exactly the limits, with their default values', () => {
    const rows = [...DOC.matchAll(/^\| `(\w+)`\s*\|\s*([0-9_]+)\s*\|/gm)].map(
      (m) => [m[1] as string, Number((m[2] as string).replaceAll('_', ''))] as const,
    );
    const documented = Object.fromEntries(rows);
    expect(Object.keys(documented).sort()).toEqual(Object.keys(LIMITS).sort());
    for (const [name, value] of Object.entries(LIMITS)) {
      expect(documented[name], name).toBe(value);
    }
  });

  it('the signed text example is exactly what changeSigningText produces', () => {
    const example = /Example: `(demo-change:2\|\{[^`]+\})`/.exec(DOC)?.[1];
    expect(example).toBeDefined();
    const change: Change = {
      device: 'a',
      seq: 1,
      clock: 3,
      collection: 'items',
      id: 'x',
      kind: 'set',
      check: 'c1',
    };
    expect(changeSigningText('demo', change, 'main')).toBe(example);
  });

  it('the signed text example with prev is exactly what changeSigningText produces', () => {
    const example = /Example with prev: `(demo-change:2\|\{[^`]+\})`/.exec(DOC)?.[1];
    expect(example).toBeDefined();
    const change: Change = {
      device: 'a',
      seq: 2,
      clock: 4,
      collection: 'items',
      id: 'x',
      kind: 'delete',
      check: 'c2',
      prev: 'c1',
    };
    expect(changeSigningText('demo', change, 'main')).toBe(example);
  });

  it('the format version and the marker rule are as documented', () => {
    expect(DOC).toContain(`version \`${FORMAT_VERSION}\``);
    expect(marker('demo', 'device', FORMAT_VERSION)).toBe(`demo-device:${FORMAT_VERSION}`);
    expect(DOC).toContain('^[a-z][a-z0-9]{1,15}$');
    expect(() => marker('Demo', 'device')).toThrow();
    expect(() => marker('a', 'device')).toThrow();
    expect(() => marker('a'.repeat(17), 'device')).toThrow();
  });

  it('the check value is 43 characters and the canonical rules hold (sorted keys, "10" before "9")', async () => {
    expect(DOC).toContain('always 43 characters');
    expect(checkValue({ a: 1 })).toHaveLength(43);
    expect(canonical({ 9: 'x', 10: 'y' })).toBe('{"10":"y","9":"x"}');
    expect(() => canonical([undefined])).toThrow(TypeError);
    expect(() => canonical(new Date(0))).toThrow(TypeError);
    expect(canonical({ a: undefined, b: 1 })).toBe('{"b":1}');
    expect(canonical(undefined)).toBe('null');
  });

  it('a public key is 87 characters and the check code has the documented shape', async () => {
    expect(DOC).toContain('exactly **87 characters**');
    expect(DOC).toContain('`dddd dddd dddd dddd dddd`');
    const keys = await publicKeys(await generateDeviceKeys());
    expect(keys.sig).toHaveLength(87);
    expect(keys.dh).toHaveLength(87);
    expect(await checkCode('demo', 'dev-1', keys)).toMatch(/^\d{4}( \d{4}){4}$/);
  });

  it('the fingerprint size in the document is what the code produces', () => {
    const m = /first (\d+) bytes as (\d+) hex digits/.exec(DOC);
    expect(m).not.toBeNull();
    const [bytes, digits] = [Number(m?.[1]), Number(m?.[2])];
    expect(digits).toBe(bytes * 2);
    expect(fingerprint(emptyReplica('a'))).toHaveLength(digits);
    expect(DOC).toContain(`consistency check of ${bytes * 8} bits`);
    expect(DOC).toContain(`${digits} lower-case hex`);
  });

  it('the check code text and its strength are as documented', () => {
    expect(DOC).toContain("${marker(appId, 'device', 2)}|${n}:${deviceId}|${n}:${sig}|${n}:${dh}");
    expect(DOC).toContain('about **66 bits**');
    expect(Math.round(5 * Math.log2(10000) * 10) / 10).toBe(66.4);
  });
});
