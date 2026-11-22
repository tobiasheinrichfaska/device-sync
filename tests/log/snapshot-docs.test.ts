// docs/snapshot.md and docs/field-rules.md are promises to whoever uses the hooks. These tests hold the
// code to the numbers, codes and names written in them.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import * as log from '../../src/log/index.ts';
import { LIMITS } from '../../src/log/index.ts';

const read = (name: string): string =>
  readFileSync(new URL(`../../docs/${name}`, import.meta.url), 'utf8');
const SNAPSHOT = read('snapshot.md');
const RULES = read('field-rules.md');
const SOURCE = readFileSync(new URL('../../src/log/snapshot.ts', import.meta.url), 'utf8');

function section(doc: string, title: string): string {
  const start = doc.indexOf(`\n## ${title}`);
  expect(start, title).toBeGreaterThan(-1);
  const next = doc.indexOf('\n## ', start + 4);
  return doc.slice(start, next === -1 ? undefined : next);
}

const codesIn = (text: string): Set<string> =>
  new Set([...text.matchAll(/^\| `([a-z-]+)`\s*\|/gm)].map((m) => m[1] as string));

/** The string literals of an exported union type in the source. */
function unionOf(name: string): Set<string> {
  const start = SOURCE.indexOf(`export type ${name}`);
  expect(start, name).toBeGreaterThan(-1);
  const end = SOURCE.indexOf(';', start);
  return new Set([...SOURCE.slice(start, end).matchAll(/'([a-z-]+)'/g)].map((m) => m[1] as string));
}

describe('docs/snapshot.md against the code', () => {
  it('the limits table lists the two snapshot limits with their defaults', () => {
    const rows = [...SNAPSHOT.matchAll(/^\| `(max\w+)`\s*\|\s*([0-9_]+)\s*\|/gm)];
    const documented = Object.fromEntries(rows.map((m) => [m[1], Number(m[2])]));
    expect(Object.keys(documented).sort()).toEqual(['maxSnapshotChanges', 'maxSnapshotChars']);
    for (const [name, value] of Object.entries(documented)) {
      expect(LIMITS[name as keyof typeof LIMITS], name).toBe(value);
    }
  });

  it('the code tables are exactly the failure codes of the code', () => {
    expect(codesIn(section(SNAPSHOT, 'Making one'))).toEqual(unionOf('SnapshotFailure'));
    expect(codesIn(section(SNAPSHOT, 'Starting from one'))).toEqual(unionOf('CatchUpFailure'));
  });

  it('names the entry points and members the code has', () => {
    for (const name of [
      'snapshot',
      'catchUp',
      'parseSnapshot',
      'parseSnapshotText',
      'needsSnapshot',
    ]) {
      expect(SNAPSHOT, name).toContain(name);
      expect(typeof (log as Record<string, unknown>)[name], name).toBe('function');
    }
    for (const word of [
      'trustProducer',
      'Replica.base',
      'selfVerifying',
      'own-history',
      'inconsistent',
    ]) {
      expect(SNAPSHOT, word).toContain(word);
    }
    expect(log.SNAPSHOT_VERSION).toBe(1);
    expect(SNAPSHOT).toContain('<app>-snapshot:1');
  });
});

describe('docs/field-rules.md against the code', () => {
  it('names the codes and entry points the code has', () => {
    for (const word of [
      'field-rules',
      'invalid-rule-answer',
      'refusalDetail',
      'Rejection.detail',
    ]) {
      expect(RULES, word).toContain(word);
    }
    const validate = readFileSync(new URL('../../src/log/validate.ts', import.meta.url), 'utf8');
    expect(validate).toContain("'invalid-rule-answer'");
    expect(validate).toContain('120');
    for (const name of [
      'write',
      'remove',
      'softDelete',
      'restore',
      'undo',
      'receiveJudged',
      'readChanges',
      'judgeChanges',
      'catchUp',
    ]) {
      expect(RULES, name).toContain(name);
      expect(typeof (log as Record<string, unknown>)[name], name).toBe('function');
    }
  });
});
