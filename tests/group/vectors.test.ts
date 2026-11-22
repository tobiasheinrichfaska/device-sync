// The committed vectors (tests/vectors/group.json): fixed key bytes, salts and ids; the code and the
// independent reference must both produce them. Regenerate with GROUP_VECTORS=write (reference only).
import { readFileSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  decryptGroup,
  emptyGroupState,
  encryptGroup,
  readGroupState,
  addGroupKey,
  storeGroupState,
  parseGrant,
  type GroupKey,
} from '../../src/group/index.ts';
import { refDecrypt, refEncrypt, refGrant, refKeyId, refState, type RefKey } from './reference.ts';

const FILE = new URL('../vectors/group.json', import.meta.url);
const APP = 'vecapp';
const SET = 'set-one';
const fill = (n: number, start: number): Uint8Array =>
  Uint8Array.from({ length: n }, (_, i) => (start + i * 7) & 255);
const A = 'device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const B = 'device-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const keys: RefKey[] = [
  { epoch: 1, author: A, key: fill(32, 1), audience: [A, B] },
  { epoch: 2, author: B, key: fill(32, 90), audience: [A, B] },
  { epoch: 2, author: A, key: fill(32, 170), audience: [A, B] },
];
const messages = [
  { epoch: 1, author: A, context: '', plaintext: '', salt: fill(16, 3) },
  { epoch: 1, author: A, context: 'record-1', plaintext: 'hello', salt: fill(16, 40) },
  { epoch: 2, author: A, context: 'ünï/çøde ✓', plaintext: 'a'.repeat(100), salt: fill(16, 77) },
];

function build() {
  const sorted = [...keys].sort((x, y) => x.epoch - y.epoch || (x.author < y.author ? -1 : 1));
  return {
    description:
      'Group layer vectors: key ids, encrypted messages, one grant payload and one stored state. All keys here are throw-away.',
    appId: APP,
    dataSet: SET,
    keys: keys.map((k) => ({
      epoch: k.epoch,
      author: k.author,
      key: Buffer.from(k.key).toString('base64url'),
      keyId: refKeyId(APP, SET, k.epoch, k.key),
      audience: k.audience,
      grant: refGrant(APP, SET, k),
    })),
    messages: messages.map((m) => {
      const k = keys.find((x) => x.epoch === m.epoch && x.author === m.author) as RefKey;
      return {
        epoch: m.epoch,
        author: m.author,
        context: m.context,
        plaintext: m.plaintext,
        salt: Buffer.from(m.salt).toString('base64url'),
        text: refEncrypt(APP, SET, m.epoch, k.key, m.salt, Buffer.from(m.plaintext), m.context),
      };
    }),
    state: { floor: 0, text: refState(APP, SET, 0, sorted) },
  };
}

if (process.env.GROUP_VECTORS === 'write') {
  writeFileSync(FILE, `${JSON.stringify(build(), null, 2)}\n`);
}

const vectors = JSON.parse(readFileSync(FILE, 'utf8')) as ReturnType<typeof build>;

describe('group vectors', () => {
  it('the reference derivation reproduces the file', () => {
    expect(JSON.parse(JSON.stringify(build()))).toEqual(vectors);
  });

  it('the stored state reads and writes back to the vector text; key ids match the reference', async () => {
    const state = await readGroupState(APP, vectors.state.text);
    expect(state).toBeDefined();
    expect(storeGroupState(APP, state!)).toBe(vectors.state.text);
    for (const k of state!.keys) {
      const ref = keys.find((x) => x.epoch === k.epoch && x.author === k.author)!;
      expect(k.kid).toBe(refKeyId(APP, SET, k.epoch, ref.key));
    }
    // the choice rule: highest epoch, lowest author id (A before B in UTF-8 order)
    const picked = await encryptGroup({
      appId: APP,
      state: state!,
      plaintext: new Uint8Array(),
      random: () => fill(16, 1),
    });
    expect(picked.ok && picked.epoch).toBe(2);
    expect(picked.ok && picked.kid).toBe(vectors.keys[2]!.keyId);
  });

  it('the grant payloads are read by the strict reader and written back exactly', () => {
    for (const k of vectors.keys) {
      const g = parseGrant(APP, k.grant);
      expect(g?.epoch).toBe(k.epoch);
      expect(g?.author).toBe(k.author);
    }
  });

  it('the code encrypts to the vector text and opens it; the reference opens the code', async () => {
    const state = (await readGroupState(APP, vectors.state.text))!;
    for (const m of vectors.messages) {
      const pinned = {
        ...state,
        keys: state.keys.filter((k) => k.epoch === m.epoch && k.author === m.author),
      };
      const enc = await encryptGroup({
        appId: APP,
        state: pinned,
        plaintext: new TextEncoder().encode(m.plaintext),
        context: m.context,
        random: () => Buffer.from(m.salt, 'base64url'),
      });
      expect(enc.ok && enc.text).toBe(m.text);
      const dec = await decryptGroup({ appId: APP, state, text: m.text, context: m.context });
      expect(dec.ok && new TextDecoder().decode(dec.plaintext)).toBe(m.plaintext);
      const k = keys.find((x) => x.epoch === m.epoch && x.author === m.author)!;
      expect(refDecrypt(APP, SET, m.epoch, k.key, m.text, m.context)?.toString()).toBe(m.plaintext);
      expect(refDecrypt(APP, SET, m.epoch, k.key, m.text, m.context + 'x')).toBeUndefined();
    }
  });

  it('adding the vector keys in any order gives the same state', async () => {
    const records: GroupKey[] = (await readGroupState(APP, vectors.state.text))!.keys.slice();
    for (const order of [
      [0, 1, 2],
      [2, 1, 0],
      [1, 2, 0],
    ]) {
      let s = emptyGroupState(SET);
      for (const i of order) {
        const r = addGroupKey(s, records[i]!);
        if (!r.ok) throw new Error(r.reason);
        s = r.state;
      }
      expect(storeGroupState(APP, s)).toBe(vectors.state.text);
    }
  });
});
