// docs/channel.md is a promise to the app that wires the channel glue. These tests hold the code
// tables of the document to the unions of codes written in the source.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string): string => readFileSync(new URL(path, import.meta.url), 'utf8');
const DOC = read('../../docs/channel.md');

function section(title: string): string {
  const start =
    DOC.indexOf(`\n### ${title}`) >= 0
      ? DOC.indexOf(`\n### ${title}`)
      : DOC.indexOf(`\n## ${title}`);
  expect(start, title).toBeGreaterThan(-1);
  const next = DOC.slice(start + 4).search(/\n##+ /);
  return DOC.slice(start, next === -1 ? undefined : start + 4 + next);
}
const tableCodes = (text: string): string[] =>
  [...text.matchAll(/^\| `([a-z-]+)`\s*\|/gm)].map((m) => m[1] as string).sort();
const unionOf = (file: string, name: string): string[] => {
  const src = read(file);
  const at = src.indexOf(`export type ${name} =`);
  expect(at, name).toBeGreaterThan(-1);
  const end = src.indexOf(';', at);
  return [...src.slice(at, end).matchAll(/'([a-z-]+)'/g)].map((m) => m[1] as string).sort();
};

describe('docs/channel.md against the code', () => {
  it('the sealing codes are the SealChannelRefusal union', () => {
    expect(tableCodes(section('`sealChannel`'))).toEqual(
      unionOf('../../src/channel/seal.ts', 'SealChannelRefusal'),
    );
  });

  it('the opening codes are the ChannelCode union', () => {
    expect(tableCodes(section('`openChannel`'))).toEqual(
      unionOf('../../src/channel/open.ts', 'ChannelCode'),
    );
  });

  it('the replica codes are the ReadReplicaFailure union', () => {
    expect(tableCodes(section('Replica at rest'))).toEqual(
      unionOf('../../src/log/readReplica.ts', 'ReadReplicaFailure'),
    );
  });

  it('the numbers quoted are the limits', async () => {
    const { REPLICA_AT_REST } = await import('../../src/log/index.ts');
    const { ENVELOPE_LIMITS } = await import('../../src/core/index.ts');
    expect(REPLICA_AT_REST.maxChanges).toBe(1_000_000);
    expect(REPLICA_AT_REST.maxChars).toBe(256_000_000);
    expect(ENVELOPE_LIMITS.maxFans).toBe(64);
    expect(DOC).toContain('1 000 000');
    expect(DOC).toContain('256 000 000');
  });

  it('the body shape is the one written in the document', async () => {
    const { writeChannelBody } = await import('../../src/channel/index.ts');
    expect(DOC).toContain('{"v":1,"stand":<vector>,"changes":[...]}');
    expect(new TextDecoder().decode(writeChannelBody({ a: 1 }, []))).toBe(
      '{"v":1,"stand":{"a":1},"changes":[]}',
    );
  });
});
