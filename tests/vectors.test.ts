// Runs the committed test vectors (tests/vectors/*.json) against the code. The vectors are meant for
// other implementations too: see "Cross-language notes" in docs/wire-format.md.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  canonical,
  checkCode,
  checkValue,
  hasDuplicateKeys,
  importPublicKey,
  verifyText,
} from '../src/core/index.ts';
import {
  changeCheckValue,
  changeSigningText,
  emptyReplica,
  judgeChange,
  parseSyncMessageText,
  write,
  type Change,
} from '../src/log/index.ts';

const load = <T>(name: string): T =>
  JSON.parse(readFileSync(new URL(`./vectors/${name}.json`, import.meta.url), 'utf8')) as T;

/** A high surrogate without its partner, built at run time so no file holds one. */
const LONE = String.fromCharCode(0xd800);

interface CanonicalFile {
  cases: { name: string; input: string; canonical: string; check: string }[];
  refused: { name: string; input: string; reason: 'lone-surrogate' | 'duplicate-key' }[];
  notRefused: { name: string; input: string }[];
}

describe('vectors: canonical form', () => {
  const file = load<CanonicalFile>('canonical');

  it('has the cases the notes promise', () => {
    const names = file.cases.map((c) => c.name).join('\n');
    for (const word of ['numbers', 'UTF-16', 'escapes', 'nested']) expect(names).toContain(word);
  });

  for (const c of file.cases) {
    it(`canonical and check value: ${c.name}`, () => {
      expect(hasDuplicateKeys(c.input)).toBe(false);
      expect(canonical(JSON.parse(c.input))).toBe(c.canonical);
      expect(c.check).toHaveLength(43);
      expect(checkValue(JSON.parse(c.input))).toBe(c.check);
    });
  }

  for (const r of file.refused) {
    it(`refused (${r.reason}): ${r.name}`, () => {
      if (r.reason === 'duplicate-key') {
        expect(hasDuplicateKeys(r.input)).toBe(true);
        return;
      }
      // the canonical form (hence the check value) refuses it, and so do the strict readers
      const value: unknown = JSON.parse(r.input);
      expect(() => canonical(value)).toThrow(TypeError);
      const written = write(emptyReplica('a'), 'items', 'x', { f: value });
      expect(written.ok).toBe(false);
      expect(['invalid-value', 'invalid-name']).toContain(written.ok ? '' : written.reason);
    });
  }

  for (const r of file.notRefused) {
    it(`not refused: ${r.name}`, () => {
      expect(hasDuplicateKeys(r.input)).toBe(false);
    });
  }

  it('a text entry point refuses a text with a key twice, and reads the same text without', () => {
    expect(parseSyncMessageText('{"t":"stand","vector":{"a":1,"a":2}}')).toBeUndefined();
    expect(parseSyncMessageText('{"t":"stand","vector":{"a":1,"b":2}}')).toBeDefined();
  });

  it('a lone surrogate in a name is refused as a name, a surrogate pair is fine', () => {
    const empty = emptyReplica('a');
    expect(write(empty, 'items', `x${LONE}`, { f: 1 })).toEqual({
      ok: false,
      reason: 'invalid-name',
    });
    expect(write(empty, 'items', 'x', { [`f${LONE}`]: 1 }).ok).toBe(false);
    expect(write(empty, 'items', 'x', { f: String.fromCodePoint(0x1f600) }).ok).toBe(true);
  });
});

describe('vectors: signing text', () => {
  const file = load<{
    cases: { name: string; appId: string; dataSet: string; change: Change; text: string }[];
  }>('signing-text');
  for (const c of file.cases) {
    it(c.name, () => {
      expect(changeSigningText(c.appId, c.change, c.dataSet)).toBe(c.text);
    });
  }
});

describe('vectors: check code', () => {
  const file = load<{
    cases: { appId: string; deviceId: string; sig: string; dh: string; code: string }[];
    refused: { name: string; appId: string; deviceId: string; sig: string; dh: string }[];
  }>('check-code');
  for (const c of file.cases) {
    it(`${c.appId} ${c.deviceId}`, async () => {
      expect(await checkCode(c.appId, c.deviceId, { sig: c.sig, dh: c.dh })).toBe(c.code);
    });
  }
  for (const r of file.refused) {
    it(`refused: ${r.name}`, async () => {
      await expect(checkCode(r.appId, r.deviceId, { sig: r.sig, dh: r.dh })).rejects.toThrow(
        TypeError,
      );
    });
  }
});

describe('vectors: one signed change that every implementation must accept', () => {
  const file = load<{
    appId: string;
    dataSet: string;
    publicKey: string;
    contentCanonical: string;
    signedText: string;
    valid: Change;
    refused: { name: string; change: Change; appId?: string; dataSet?: string }[];
  }>('verification');

  const judge = async (change: Change, appId = file.appId, dataSet = file.dataSet) => {
    const key = await importPublicKey(file.publicKey, 'sig');
    return judgeChange(
      { appId, dataSet, keys: { keyFor: () => key }, state: emptyReplica('n') },
      change,
    );
  };

  it('the pieces fit: canonical content, check value, signed text, signature', async () => {
    const key = await importPublicKey(file.publicKey, 'sig');
    expect(key).toBeDefined();
    const { fields, knew, time, by } = file.valid;
    expect(canonical({ fields, knew, time, by })).toBe(file.contentCanonical);
    expect(changeCheckValue(file.valid)).toBe(file.valid.check);
    expect(changeSigningText(file.appId, file.valid, file.dataSet)).toBe(file.signedText);
    expect(await verifyText(key as CryptoKey, file.signedText, file.valid.sig as string)).toBe(
      true,
    );
  });

  it('the valid change is accepted', async () => {
    expect(await judge(file.valid)).toBe('checked');
  });

  for (const r of file.refused) {
    it(`refused: ${r.name}`, async () => {
      expect(await judge(r.change, r.appId, r.dataSet)).toBe('false');
    });
  }
});
