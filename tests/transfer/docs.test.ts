// docs/transfer.md is a promise to anyone who implements the other side. These tests hold the code to the
// numbers and codes written in it.
import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { TRANSFER_LIMITS as L } from '../../src/transfer/index.ts';
import { crc32 } from '../../src/transfer/check.ts';
import { createFountainSender } from '../../src/transfer/index.ts';
import { APP } from './helpers.ts';

const DOC = readFileSync(new URL('../../docs/transfer.md', import.meta.url), 'utf8');
const SRC = new URL('../../src/transfer/', import.meta.url);

function section(title: string): string {
  const start = DOC.indexOf(`\n## ${title}`);
  expect(start, title).toBeGreaterThan(-1);
  const next = DOC.indexOf('\n## ', start + 4);
  return DOC.slice(start, next === -1 ? undefined : next);
}

describe('docs/transfer.md against the code', () => {
  it('the limits table lists exactly TRANSFER_LIMITS, with the same values', () => {
    const rows = [...section('Limits').matchAll(/^\| `(\w+)`\s*\|\s*([0-9_]+)\s*\|/gm)];
    const documented = Object.fromEntries(
      rows.map((m) => [m[1], Number((m[2] as string).replaceAll('_', ''))]),
    );
    expect(Object.keys(documented).sort()).toEqual(Object.keys(L).sort());
    for (const [name, value] of Object.entries(L)) expect(documented[name], name).toBe(value);
  });

  it('the derived limits are the ones the arithmetic gives', () => {
    expect(L.frameBytesMax).toBe(L.frameHeaderBytes + L.blockBytesMax + L.frameCheckBytes);
    expect(L.frameCharsMax).toBe(Math.ceil((L.frameBytesMax * 4) / 3));
    expect(L.payloadMax).toBe(L.blocksMax * 1_024);
    expect(L.chunkBytes - L.chunkHeaderBytes).toBe(16_375);
    // the header the text describes: 1 + 4 + 4 + 2 + 4 + 4
    expect(1 + 4 + 4 + 2 + 4 + 4).toBe(L.frameHeaderBytes);
    expect(1 + 4 + 2 + 2).toBe(L.chunkHeaderBytes);
  });

  it('every documented code is in the source, and every code the source writes is documented', () => {
    const rows = [...section('Codes').matchAll(/^\| [^|]+\|(.*)\|\s*$/gm)];
    const documented = new Set(
      rows.flatMap((m) =>
        [...(m[1] as string).matchAll(/`([a-z0-9-]+)`/g)].map((c) => c[1] as string),
      ),
    );
    const text = readdirSync(SRC)
      .filter((f) => f.endsWith('.ts'))
      .map((f) => readFileSync(new URL(f, SRC), 'utf8'))
      .join('\n');
    const notCodes = new Set(['new', 'redundant', 'repeat', 'other-transfer', 'done']);
    for (const code of documented) expect(text.includes(`'${code}'`), code).toBe(true);
    for (const code of notCodes) expect(documented.has(code), code).toBe(true);
    const written = new Set(
      [...text.matchAll(/fail\('([a-z0-9-]+)'\)/g)].map((m) => m[1] as string),
    );
    for (const code of written) expect(documented.has(code), code).toBe(true);
    // handshake refusals and failures are written without `fail(`
    for (const m of text.matchAll(/(?:refuse|failed)\([^)]*?'([a-z-]+)'\)/g))
      expect(documented.has(m[1] as string), m[1]).toBe(true);
  });

  it('the frame layout the text gives is the one the sender writes', () => {
    const s = createFountainSender({
      appId: APP,
      payload: Uint8Array.of(1, 2, 3, 4, 5),
      transferId: 0x01020304,
      blockBytes: 4,
    });
    if (!s.ok) throw new Error(s.reason);
    const f = s.value.frame(7);
    if (!f.ok) throw new Error(f.reason);
    const v = new DataView(f.value.buffer);
    expect(v.getUint8(0)).toBe(1);
    expect(v.getUint32(1)).toBe(0x01020304);
    expect(v.getUint32(5)).toBe(7);
    expect(v.getUint16(9)).toBe(2);
    expect(v.getUint32(11)).toBe(5);
    expect(v.getUint32(15)).toBe(
      crc32([new TextEncoder().encode(`${APP}-qrdata:1`), Uint8Array.of(1, 2, 3, 4, 5)]),
    );
    const end = f.value.length - 4;
    expect(v.getUint32(end)).toBe(
      crc32([new TextEncoder().encode(`${APP}-qr:1`), f.value.subarray(0, end)]),
    );
    for (const marker of ['<appId>-qr:1', '<appId>-qrdata:1', '<appId>-tone:1', '<appId>-direct:1'])
      expect(DOC).toContain(marker);
  });

  it('the sentences with numbers match the plans', () => {
    expect(DOC).toContain('1 to 16 octets');
    expect(DOC).toContain('`repeats` times (2)');
    expect(DOC).toContain('about 5.1 s per copy');
    expect((1 + L.toneMessageMax + L.toneCheckBytes) * 3 * 90).toBe(5130);
    expect(DOC).toContain('4 MiB');
    expect(DOC).toContain('16 KiB');
    expect(DOC).toContain('`gatherWaitMs`, 5 s');
    expect(L.messageBytesMax).toBe(4 * 1024 * 1024);
    expect(L.chunkBytes).toBe(16 * 1024);
  });
});
