// The group state at rest: roundtrip, independent derivation, tamper sweeps, bounded work, fuzzing.
import { describe, expect, it, vi } from 'vitest';
import {
  REST_IV_BYTES,
  maxSealedStateChars,
  openGroupState,
  readGroupState,
  sealGroupState,
  storeGroupState,
  type GroupState,
  type OpenStateRefusal,
} from '../../src/group/index.ts';
import { generateWrapKey } from '../../src/browser/index.ts';
import { APP, DATA_SET, prng, seeded } from './helpers.ts';
import { refOpenState, refSealState } from './rest-reference.ts';

const KEY_BYTES = Uint8Array.from({ length: 32 }, (_, i) => i * 7 + 1);
const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64url');

const wrap = (bytes: Uint8Array = KEY_BYTES): Promise<CryptoKey> =>
  crypto.subtle.importKey('raw', new Uint8Array(bytes), 'AES-GCM', false, ['encrypt', 'decrypt']);

/** A state with three keys (two epochs), made through the strict reader so the key ids are right. */
async function sampleState(set = DATA_SET, seed = 1): Promise<GroupState> {
  const rnd = seeded(seed);
  const key = (epoch: number, author: string, audience: string[]) => ({
    epoch,
    author,
    key: b64(rnd(32)),
    audience,
  });
  const keys = [
    key(1, 'dev-a', ['dev-a', 'dev-b']),
    key(2, 'dev-a', ['dev-a', 'dev-b', 'dev-c']),
    key(2, 'dev-b', ['dev-b']),
  ];
  const text = storeGroupState(APP, {
    dataSet: set,
    floor: 1,
    keys: keys.map((k) => ({ ...k, kid: '' })),
  });
  const state = await readGroupState(APP, text);
  if (!state) throw new Error('sample state refused');
  return state;
}

const OPEN = { appId: APP } as const;
const sealOpts = (seed = 9) => ({ appId: APP, random: seeded(seed) });

async function sealed(state?: GroupState, key?: CryptoKey, seed = 9): Promise<string> {
  const r = await sealGroupState(
    state ?? (await sampleState()),
    key ?? (await wrap()),
    sealOpts(seed),
  );
  if (!r.ok) throw new Error(r.reason);
  return r.text;
}

describe('sealing and opening the state at rest', () => {
  it('roundtrips (generated non-extractable key)', async () => {
    const made = await generateWrapKey();
    if (!made.ok) throw new Error(made.reason);
    expect(made.value.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', made.value)).rejects.toThrow();
    const state = await sampleState();
    const r = await sealGroupState(state, made.value, sealOpts());
    if (!r.ok) throw new Error(r.reason);
    expect(await openGroupState(r.text, made.value, OPEN)).toEqual({ ok: true, state });
    expect(r.text).not.toContain(state.keys[0]!.key);
  });

  it('matches the independent node:crypto derivation byte for byte, both ways', async () => {
    for (const seed of [1, 2, 3]) {
      const state = await sampleState(seed === 3 ? 'set é中' : DATA_SET, seed);
      const iv = seeded(seed * 100)(REST_IV_BYTES);
      const ours = await sealGroupState(state, await wrap(), {
        appId: APP,
        random: (n) => (n === REST_IV_BYTES ? iv : seeded(0)(n)),
      });
      if (!ours.ok) throw new Error(ours.reason);
      const ref = refSealState(APP, state.dataSet, KEY_BYTES, iv, storeGroupState(APP, state));
      expect(ours.text).toBe(ref);
      expect(refOpenState(APP, KEY_BYTES, ours.text)).toBe(storeGroupState(APP, state));
      expect(await openGroupState(ref, await wrap(), OPEN)).toEqual({ ok: true, state });
    }
  });

  it('draws a fresh 12-byte IV per sealing and passes exactly that IV on', async () => {
    const spy = vi.spyOn(crypto.subtle, 'encrypt');
    try {
      const state = await sampleState();
      const key = await wrap();
      const rnd = seeded(5);
      const ivs = new Set<string>();
      for (let i = 0; i < 20; i += 1) {
        const r = await sealGroupState(state, key, { appId: APP, random: rnd });
        if (!r.ok) throw new Error(r.reason);
        ivs.add(JSON.parse(r.text).iv);
      }
      expect(ivs.size).toBe(20);
      const lastIv = spy.mock.calls.at(-1)![0] as unknown as { iv: Uint8Array };
      expect(lastIv.iv.length).toBe(12);
      expect(b64(lastIv.iv)).toBe([...ivs].at(-1));
    } finally {
      spy.mockRestore();
    }
  });

  it('refuses a bad random source, bad inputs and bad keys with codes, never throwing', async () => {
    const state = await sampleState();
    const key = await wrap();
    const seal = (s: unknown, k: unknown, o: unknown) =>
      sealGroupState(s as GroupState, k as CryptoKey, o as never);
    const cases: [unknown, Promise<unknown>][] = [
      ['bad-random', seal(state, key, { appId: APP, random: () => new Uint8Array(11) })],
      ['bad-random', seal(state, key, { appId: APP, random: () => new Uint8Array(13) })],
      ['bad-random', seal(state, key, { appId: APP, random: () => 'x' })],
      [
        'bad-random',
        seal(state, key, {
          appId: APP,
          random: () => {
            throw new Error('no entropy');
          },
        }),
      ],
      ['bad-input', seal(state, key, { appId: 'Bad App', random: seeded(1) })],
      ['bad-input', seal(state, key, { appId: APP })],
      ['bad-input', seal(null, key, sealOpts())],
      ['bad-input', seal({ ...state, dataSet: '' }, key, sealOpts())],
      ['bad-input', seal({ ...state, keys: [{ junk: 1 }] }, key, sealOpts())],
      ['bad-key', seal(state, null, sealOpts())],
      ['bad-key', seal(state, {}, sealOpts())],
    ];
    for (const [reason, p] of cases) expect(await p).toEqual({ ok: false, reason });
    // an extractable key, an AES-128 key, a key without decrypt, an HKDF key
    const extractable = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
      'encrypt',
      'decrypt',
    ]);
    const short = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, [
      'encrypt',
      'decrypt',
    ]);
    const encOnly = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(KEY_BYTES),
      'AES-GCM',
      false,
      ['encrypt'],
    );
    for (const k of [extractable, short, encOnly])
      expect(await seal(state, k, sealOpts())).toEqual({ ok: false, reason: 'bad-key' });
    const text = await sealed();
    expect(await openGroupState(text, extractable, OPEN)).toEqual({ ok: false, reason: 'bad-key' });
  });

  it('a wrong key, another app and another data set do not open it', async () => {
    const text = await sealed();
    const other = await wrap(Uint8Array.from(KEY_BYTES, (b) => b ^ 1));
    expect(await openGroupState(text, other, OPEN)).toEqual({ ok: false, reason: 'cannot-open' });
    expect(await openGroupState(text, await wrap(), { appId: 'otherapp' })).toEqual({
      ok: false,
      reason: 'not-sealed',
    });
    expect(await openGroupState(text, await wrap(), { ...OPEN, dataSet: 'elsewhere' })).toEqual({
      ok: false,
      reason: 'wrong-data-set',
    });
    // the data set is authenticated: a text relabelled for another set does not open either
    const relabelled = text.replace(`"set":"${DATA_SET}"`, '"set":"elsewhere"');
    expect(relabelled).not.toBe(text);
    expect(await openGroupState(relabelled, await wrap(), OPEN)).toEqual({
      ok: false,
      reason: 'cannot-open',
    });
  });

  it('unsupported version, truncation and foreign texts have their codes', async () => {
    const text = await sealed();
    const key = await wrap();
    const code = async (t: unknown): Promise<unknown> =>
      (await openGroupState(t as string, key, OPEN)) as unknown;
    expect(await code(text.replace('grest:1', 'grest:2'))).toEqual({
      ok: false,
      reason: 'unsupported-version',
    });
    expect(await code(text.replace('grest:1', 'grest:0'))).toEqual({
      ok: false,
      reason: 'not-sealed',
    });
    expect(await code(text.slice(0, text.length - 5))).toEqual({ ok: false, reason: 'truncated' });
    // a tag-less ciphertext
    const o = JSON.parse(text);
    o.ct = Buffer.from(o.ct, 'base64url').subarray(0, 8).toString('base64url');
    expect(await code(JSON.stringify(o))).toEqual({ ok: false, reason: 'truncated' });
    for (const t of [
      undefined,
      null,
      5,
      {},
      '',
      '{}',
      'null',
      storeGroupState(APP, await sampleState()),
    ])
      expect(await code(t)).toEqual({ ok: false, reason: 'not-sealed' });
    expect(await openGroupState(text, key, { appId: 'Bad' })).toEqual({
      ok: false,
      reason: 'bad-input',
    });
    expect(await openGroupState(text, key, { ...OPEN, dataSet: '' })).toEqual({
      ok: false,
      reason: 'bad-input',
    });
  });

  it('every character of the text is covered: no single change opens', async () => {
    const text = await sealed();
    const key = await wrap();
    const state = await sampleState();
    let refused = 0;
    for (let i = 0; i < text.length; i += 1) {
      const c = text[i] as string;
      for (const alt of c === 'A' ? ['B'] : ['A', c === '"' ? 'x' : '"']) {
        const t = text.slice(0, i) + alt + text.slice(i + 1);
        const r = await openGroupState(t, key, OPEN);
        expect(r.ok, `${i}:${alt}`).toBe(false);
        refused += 1;
      }
    }
    expect(refused).toBeGreaterThan(text.length);
    // every prefix is refused, and the one text that is exact still opens
    for (let n = 0; n < text.length; n += 7) {
      expect((await openGroupState(text.slice(0, n), key, OPEN)).ok, `cut ${n}`).toBe(false);
    }
    expect(await openGroupState(text, key, OPEN)).toEqual({ ok: true, state });
    // a trailing character, a leading space, a doubled member
    for (const t of [text + ' ', ' ' + text, text + '\n', text.replace('"set"', '"set":"x","set"')])
      expect((await openGroupState(t, key, OPEN)).ok).toBe(false);
  });

  it('the ciphertext bytes are covered one bit at a time (authenticated, not just well-formed)', async () => {
    const text = await sealed();
    const key = await wrap();
    const o = JSON.parse(text) as { ct: string; iv: string };
    const ct = Buffer.from(o.ct, 'base64url');
    for (let i = 0; i < ct.length; i += 1) {
      const flipped = Buffer.from(ct);
      flipped[i] = (flipped[i] as number) ^ (1 << (i % 8));
      const t = text.replace(o.ct, flipped.toString('base64url'));
      expect(await openGroupState(t, key, OPEN), `byte ${i}`).toEqual({
        ok: false,
        reason: 'cannot-open',
      });
    }
    const iv = Buffer.from(o.iv, 'base64url');
    for (let i = 0; i < iv.length; i += 1) {
      const flipped = Buffer.from(iv);
      flipped[i] = (flipped[i] as number) ^ 1;
      const t = text.replace(o.iv, flipped.toString('base64url'));
      expect((await openGroupState(t, key, OPEN)).ok).toBe(false);
    }
  });

  it('rollback is NOT detected: an older sealed state of the same data set is valid', async () => {
    const key = await wrap();
    const older = await sampleState(DATA_SET, 1);
    const newer = await sampleState(DATA_SET, 2);
    const a = await sealed(older, key, 1);
    const b = await sealed(newer, key, 2);
    // the store held b; an attacker who can write the store puts a back: it opens as a valid state
    expect(await openGroupState(b, key, OPEN)).toEqual({ ok: true, state: newer });
    expect(await openGroupState(a, key, OPEN)).toEqual({ ok: true, state: older });
  });

  it('a limit override that is lower than the sealed state refuses it', async () => {
    const text = await sealed();
    expect(await openGroupState(text, await wrap(), { ...OPEN, limits: { maxKeys: 1 } })).toEqual({
      ok: false,
      reason: 'bad-state',
    });
    expect(maxSealedStateChars({ maxKeys: 1 })).toBeLessThan(maxSealedStateChars());
  });
});

describe('work before decryption is bounded', () => {
  const names = [
    'encrypt',
    'decrypt',
    'importKey',
    'deriveBits',
    'deriveKey',
    'digest',
    'sign',
    'verify',
  ] as const;
  async function counted<T>(body: () => Promise<T>): Promise<[T, Record<string, number>]> {
    const spies = names.map((n) => vi.spyOn(crypto.subtle, n));
    try {
      const out = await body();
      return [out, Object.fromEntries(names.map((n, i) => [n, spies[i]!.mock.calls.length]))];
    } finally {
      spies.forEach((s) => s.mockRestore());
    }
  }

  it('cheap refusals touch WebCrypto zero times', async () => {
    const text = await sealed();
    const key = await wrap();
    const state = await sampleState();
    const huge = 'x'.repeat(maxSealedStateChars() + 1);
    const o = JSON.parse(text);
    const [, c] = await counted(async () => {
      const outs = [
        await openGroupState(huge, key, OPEN),
        await openGroupState('{"m":"x"}', key, OPEN),
        await openGroupState(text.replace('grest:1', 'grest:7'), key, OPEN),
        await openGroupState(text.slice(0, -3), key, OPEN),
        await openGroupState(text, key, { ...OPEN, dataSet: 'other' }),
        await openGroupState(text, null as never, OPEN),
        await openGroupState(text.replace(o.iv, 'AAAA'), key, OPEN),
        await sealGroupState(state, key, { appId: APP, random: () => new Uint8Array(3) }),
        await sealGroupState(state, null as never, sealOpts()),
        await sealGroupState(state, key, { appId: 'No', random: seeded(1) }),
        await sealGroupState(state, key, { ...sealOpts(), limits: { maxKeys: 1 } }),
      ];
      return outs.map((r) => r.ok);
    });
    expect(c).toEqual(Object.fromEntries(names.map((n) => [n, 0])));
  });

  it('one sealing is one encrypt; one opening is one decrypt', async () => {
    const state = await sampleState();
    const key = await wrap();
    const [t, s] = await counted(() => sealed(state, key));
    expect(s.encrypt).toBe(1);
    expect(s.decrypt).toBe(0);
    const [r, c] = await counted(() => openGroupState(t, key, OPEN));
    expect(r.ok).toBe(true);
    expect(c.decrypt).toBe(1);
    expect(c.encrypt).toBe(0);
    // a refusal after the one decrypt (wrong key) is still one decrypt and then nothing
    const other = await wrap(Uint8Array.from(KEY_BYTES, (b) => b ^ 5));
    const [w, cw] = await counted(() => openGroupState(t, other, OPEN));
    expect(w.ok).toBe(false);
    expect(cw.decrypt).toBe(1);
    expect((cw.digest ?? 0) + (cw.deriveBits ?? 0) + (cw.deriveKey ?? 0)).toBe(0);
  });
});

describe('fuzzing the reader', () => {
  it('3000 seeded damaged inputs: never throws, only the exact text opens', async () => {
    const text = await sealed();
    const key = await wrap();
    const next = prng(4242);
    const pick = (n: number): number => Math.floor(next() * n);
    const alphabet = '{}[]":,\\ -_AaZz09\u0000é\ud800\u{1f600}';
    const allowed = new Set<OpenStateRefusal>([
      'not-sealed',
      'truncated',
      'unsupported-version',
      'wrong-data-set',
      'cannot-open',
      'bad-state',
    ]);
    const mutate = (): unknown => {
      const kind = pick(9);
      const i = pick(text.length);
      const ch = [...alphabet][pick([...alphabet].length)] as string;
      switch (kind) {
        case 0:
          return text.slice(0, i) + ch + text.slice(i + 1);
        case 1:
          return text.slice(0, i) + ch + text.slice(i);
        case 2:
          return text.slice(0, i) + text.slice(i + 1 + pick(5));
        case 3:
          return text.slice(0, i);
        case 4:
          return text.slice(i);
        case 5: {
          const j = pick(text.length);
          const [a, b] = i < j ? [i, j] : [j, i];
          return text.slice(0, a) + text.slice(b) + text.slice(a, b);
        }
        case 6:
          return Array.from({ length: pick(60) }, () => [...alphabet][pick(alphabet.length)]).join(
            '',
          );
        case 7: {
          const o = JSON.parse(text) as Record<string, unknown>;
          const names = Object.keys(o);
          o[names[pick(names.length)] as string] = [null, 1, [], {}, '', 'x', true][pick(7)];
          return JSON.stringify(o);
        }
        default:
          return [null, undefined, 3, {}, [], Symbol('s'), () => 1, 'x'.repeat(pick(2000))][
            pick(8)
          ];
      }
    };
    for (let n = 0; n < 3000; n += 1) {
      const t = mutate();
      const r = await openGroupState(t as string, key, OPEN);
      if (r.ok) expect(t).toBe(text);
      else expect(allowed.has(r.reason) || r.reason === 'bad-input', `${n}:${r.reason}`).toBe(true);
    }
  });
});
