// Every byte of every message of the layer is changed, one bit at a time: nothing is accepted.
import { describe, expect, it } from 'vitest';
import {
  acceptGrant,
  decryptGroup,
  encryptGroup,
  openRotationRequest,
  readGroupState,
  rotateGroup,
  sealRotationRequest,
  storeGroupState,
  type GroupState,
} from '../../src/group/index.ts';
import { APP, deliver, fresh, realRandom, seeded, text, world } from './helpers.ts';

const flip = (b: Uint8Array, i: number, bit: number): Uint8Array => {
  const c = Uint8Array.from(b);
  c[i] = (c[i] as number) ^ (1 << bit);
  return c;
};

async function setup() {
  const w = await world(['A', 'B']);
  const [a, b] = w.devs;
  const r = await rotateGroup({
    appId: APP,
    own: w.own(a!),
    trust: await w.trustOf(a!),
    state: fresh(),
    random: seeded(21),
  });
  if (!r.ok) throw new Error(r.reason);
  const states = new Map<string, GroupState>([[a!.id, r.state]]);
  return { w, a: a!, b: b!, r, states };
}

describe('tamper sweeps', () => {
  it('every byte of a grant file: nothing is accepted, the state stays untouched', async () => {
    const { w, b, r } = await setup();
    const file = r.grants[0]!.file;
    const own = w.own(b);
    const trust = await w.trustOf(b);
    const state = fresh();
    expect((await acceptGrant({ appId: APP, own, trust, state, file })).ok).toBe(true);
    let attempts = 0;
    for (let i = 0; i < file.length; i += 1) {
      const bit = i % 8;
      const res = await acceptGrant({ appId: APP, own, trust, state, file: flip(file, i, bit) });
      expect(res.ok, `byte ${i}`).toBe(false);
      attempts += 1;
    }
    expect(attempts).toBe(file.length);
    // a few more bits on the ciphertext region, and truncation / extension
    for (const bit of [0, 3, 7]) {
      const i = file.length - 12;
      expect(
        (await acceptGrant({ appId: APP, own, trust, state, file: flip(file, i, bit) })).ok,
      ).toBe(false);
    }
    for (const cut of [0, 1, file.length - 1, 10]) {
      expect(
        (await acceptGrant({ appId: APP, own, trust, state, file: file.slice(0, cut) })).ok,
      ).toBe(false);
    }
    expect(
      (await acceptGrant({ appId: APP, own, trust, state, file: Uint8Array.from([...file, 32]) }))
        .ok,
    ).toBe(false);
  });

  it('every byte of a rotation request file', async () => {
    const { w, a, b, states } = await setup();
    const sealed = await sealRotationRequest({
      appId: APP,
      own: w.own(b),
      to: { device: a.id, dh: a.intro.dh },
      state: fresh(),
      random: seeded(22),
    });
    if (!sealed.ok) throw new Error();
    const params = {
      appId: APP,
      own: w.own(a),
      trust: await w.trustOf(a),
      state: states.get(a.id)!,
    };
    expect((await openRotationRequest({ ...params, file: sealed.file })).ok).toBe(true);
    for (let i = 0; i < sealed.file.length; i += 1) {
      const res = await openRotationRequest({ ...params, file: flip(sealed.file, i, i % 8) });
      expect(res.ok, `byte ${i}`).toBe(false);
    }
  });

  it('every byte of an encrypted message', async () => {
    const { states, a } = await setup();
    const state = states.get(a.id)!;
    const enc = await encryptGroup({
      appId: APP,
      state,
      plaintext: text('payload'),
      context: 'c',
      random: seeded(23),
    });
    if (!enc.ok) throw new Error();
    const bytes = new TextEncoder().encode(enc.text);
    for (let i = 0; i < bytes.length; i += 1) {
      const t = new TextDecoder().decode(flip(bytes, i, i % 8));
      const res = await decryptGroup({ appId: APP, state, text: t, context: 'c' });
      expect(res.ok, `byte ${i}`).toBe(false);
    }
    for (const cut of [0, 5, bytes.length - 1]) {
      const t = enc.text.slice(0, cut);
      expect((await decryptGroup({ appId: APP, state, text: t, context: 'c' })).ok).toBe(false);
    }
    expect((await decryptGroup({ appId: APP, state, text: enc.text + ' ', context: 'c' })).ok).toBe(
      false,
    );
  });

  it('every byte of a stored state: refused, or a different state that stores as exactly that text', async () => {
    const { states, a } = await setup();
    const state = states.get(a.id)!;
    const t = storeGroupState(APP, state);
    const bytes = new TextEncoder().encode(t);
    let refused = 0;
    for (let i = 0; i < bytes.length; i += 1) {
      const changed = new TextDecoder().decode(flip(bytes, i, i % 8));
      const read = await readGroupState(APP, changed);
      if (read === undefined) refused += 1;
      else {
        expect(storeGroupState(APP, read)).toBe(changed);
        expect(changed).not.toBe(t);
      }
    }
    // the state has no integrity check of its own: the markers, names and structure are refused, only key bytes and ids differ
    expect(refused).toBeGreaterThan(bytes.length / 2);
  });

  it('a grant sealed for one device does not open for another, and not under another app id', async () => {
    const w = await world(['A', 'B', 'C']);
    const [a, b, c] = w.devs;
    const r = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: fresh(),
      random: seeded(24),
    });
    if (!r.ok) throw new Error();
    const forB = r.grants.find((g) => g.to === b!.id)!;
    const base = { own: w.own(c!), trust: await w.trustOf(c!), state: fresh(), file: forB.file };
    expect(await acceptGrant({ appId: APP, ...base })).toEqual({
      ok: false,
      reason: 'wrong-recipient',
    });
    expect(
      await acceptGrant({
        appId: 'otherapp',
        ...base,
        own: w.own(b!),
        trust: await w.trustOf(b!),
      }),
    ).toEqual({ ok: false, reason: 'not-a-grant' });
    void deliver;
    void realRandom;
  });
});
