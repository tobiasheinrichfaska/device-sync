import { describe, expect, it } from 'vitest';
import { LIMITS, parseSyncMessageText } from '../../src/log/index.ts';

const stand = JSON.stringify({ t: 'stand', vector: { a: 3 } });

describe('parseSyncMessageText', () => {
  it('reads a message from text', () => {
    expect(parseSyncMessageText(stand)).toEqual({ t: 'stand', vector: { a: 3 } });
    expect(parseSyncMessageText(` \n${stand}\n `)).toEqual({ t: 'stand', vector: { a: 3 } });
  });

  it('refuses what is not text, not JSON, or not a message; never throws', () => {
    for (const bad of [undefined, null, 5, {}, [], '', 'nope', '{', '[]', 'null', '{"t":"x"}']) {
      expect(parseSyncMessageText(bad), String(bad)).toBeUndefined();
    }
  });

  it('refuses text longer than twice maxMessageChars before reading it (limit from Limits)', () => {
    const limits = { maxMessageChars: 100 };
    const pad = (n: number): string => `{"t":"stand","vector":{"a":3}}${' '.repeat(n)}`;
    const base = pad(0).length;
    expect(parseSyncMessageText(pad(200 - base), { limits })).toBeDefined(); // exactly 200 chars
    expect(parseSyncMessageText(pad(201 - base), { limits })).toBeUndefined(); // one over
  });

  it('a huge text is refused without being parsed (a text that JSON.parse would take long on)', () => {
    const bomb = '['.repeat(LIMITS.maxMessageChars * 2 + 1);
    const started = Date.now();
    expect(parseSyncMessageText(bomb)).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(500);
  });

  it('a depth bomb within the size limit is refused and does not throw', () => {
    expect(parseSyncMessageText('['.repeat(100_000) + ']'.repeat(100_000))).toBeUndefined();
  });

  it('applies the same strictness as parseSyncMessage (unknown member)', () => {
    expect(parseSyncMessageText('{"t":"stand","vector":{"a":1},"extra":1}')).toBeUndefined();
  });
});
