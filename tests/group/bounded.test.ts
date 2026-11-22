// Work before authentication is bounded: what is refused by the strict reader or by a cheap check
// costs no WebCrypto call at all, and the rest costs a fixed number.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { sealFile } from '../../src/core/index.ts';
import {
  GROUP_LIMITS,
  acceptGrant,
  decryptGroup,
  emptyGroupState,
  encryptGroup,
  readGroupState,
  rotateGroup,
  storeGroupState,
} from '../../src/group/index.ts';
import { grantText } from '../../src/group/wire.ts';
import { APP, fresh, realRandom, seeded, text, world } from './helpers.ts';

const names = [
  'importKey',
  'deriveBits',
  'deriveKey',
  'encrypt',
  'decrypt',
  'digest',
  'sign',
  'verify',
] as const;
function spy() {
  const spies = names.map((n) => vi.spyOn(crypto.subtle, n as 'digest'));
  return {
    calls: () => spies.reduce((sum, s) => sum + s.mock.calls.length, 0),
    of: (n: (typeof names)[number]) => spies[names.indexOf(n)]!.mock.calls.length,
  };
}
afterEach(() => vi.restoreAllMocks());

describe('no crypto before the cheap checks', () => {
  it('acceptGrant: garbage, oversize, another recipient, an untrusted or removed sender', async () => {
    const w = await world(['A', 'B', 'C']);
    const [a, b, c] = w.devs;
    const r = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: fresh(),
      random: seeded(41),
    });
    if (!r.ok) throw new Error();
    const forB = r.grants.find((g) => g.to === b!.id)!.file;
    const own = w.own(b!);
    const trust = await w.trustOf(b!);
    // a valid file from a device B does not trust
    const stranger = { trusted: [], removed: [] };
    const trustC = await w.trustOf(c!);
    const s = spy();
    const cases: [string, Uint8Array, typeof trust][] = [
      ['garbage', text('not a file'), trust],
      ['empty', new Uint8Array(), trust],
      ['big', new Uint8Array(5_000_000).fill(32), trust],
      ['untrusted sender', forB, stranger],
      ['removed sender', forB, { trusted: trust.trusted, removed: [a!.id] }],
    ];
    for (const [name, file, t] of cases) {
      const res = await acceptGrant({ appId: APP, own, trust: t, state: fresh(), file });
      expect(res.ok, name).toBe(false);
      expect(s.calls(), name).toBe(0);
    }
    // another recipient: C holds a file addressed to B
    const other = await acceptGrant({
      appId: APP,
      own: w.own(c!),
      trust: trustC,
      state: fresh(),
      file: forB,
    });
    expect(other).toEqual({ ok: false, reason: 'wrong-recipient' });
    expect(s.calls()).toBe(0);
  });

  it('a file whose payload is above the layer bound is refused unopened', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = w.devs;
    const big = await sealFile({
      appId: APP,
      own: w.own(a!),
      to: { device: b!.id, dh: b!.intro.dh },
      payload: new Uint8Array(600_000),
      random: realRandom(12),
    });
    if (!big.ok) throw new Error();
    const s = spy();
    const res = await acceptGrant({
      appId: APP,
      own: w.own(b!),
      trust: await w.trustOf(b!),
      state: fresh(),
      file: big.file,
    });
    expect(res).toEqual({ ok: false, reason: 'not-a-grant' });
    expect(s.calls()).toBe(0);
  });

  it('an accepted grant costs a fixed number of operations: one open and one key id', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = w.devs;
    const r = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: fresh(),
      random: seeded(42),
    });
    if (!r.ok) throw new Error();
    const trust = await w.trustOf(b!);
    const s = spy();
    const res = await acceptGrant({
      appId: APP,
      own: w.own(b!),
      trust,
      state: fresh(),
      file: r.grants[0]!.file,
    });
    expect(res.ok).toBe(true);
    const first = s.calls();
    expect(first).toBeLessThan(15);
    // a hostile sender cannot make the cost depend on the size of the claimed audience or the state
    const again = await acceptGrant({
      appId: APP,
      own: w.own(b!),
      trust,
      state: res.ok ? res.state : fresh(),
      file: r.grants[0]!.file,
    });
    expect(again.ok).toBe(true);
    expect(s.calls()).toBe(first * 2);
  });

  it('decryptGroup: not group data, wrong set, unknown key, oversize: no crypto', async () => {
    const w = await world(['A', 'B']);
    const r = await rotateGroup({
      appId: APP,
      own: w.own(w.devs[0]!),
      trust: await w.trustOf(w.devs[0]!),
      state: fresh(),
      random: seeded(43),
    });
    if (!r.ok) throw new Error();
    const enc = await encryptGroup({
      appId: APP,
      state: r.state,
      plaintext: text('x'),
      random: seeded(44),
    });
    if (!enc.ok) throw new Error();
    const s = spy();
    for (const t of ['x', '', 'a'.repeat(3_000_000), enc.text]) {
      const res = await decryptGroup({
        appId: APP,
        state: t === enc.text ? fresh() : r.state,
        text: t,
      });
      expect(res.ok).toBe(false);
    }
    expect(
      await decryptGroup({ appId: APP, state: { ...r.state, dataSet: 'z' }, text: enc.text }),
    ).toMatchObject({ reason: 'wrong-data-set' });
    expect(s.calls()).toBe(0);
  });

  it('readGroupState: oversize or malformed text costs nothing; a full state costs one key id per key', async () => {
    const s = spy();
    expect(await readGroupState(APP, 'x'.repeat(50_000_000))).toBeUndefined();
    expect(await readGroupState(APP, '{}')).toBeUndefined();
    expect(s.calls()).toBe(0);
    // a state at the key limit: derive once per key, no more
    const keys = Array.from({ length: GROUP_LIMITS.maxKeys }, (_, i) => ({
      epoch: i + 1,
      author: 'device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      kid: '',
      key: Buffer.alloc(32, i + 1).toString('base64url'),
      audience: ['device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
    }));
    const full = storeGroupState(APP, { ...emptyGroupState('main'), keys });
    const state = await readGroupState(APP, full);
    expect(state?.keys).toHaveLength(GROUP_LIMITS.maxKeys);
    expect(s.of('deriveBits')).toBe(GROUP_LIMITS.maxKeys);
    const over = storeGroupState(APP, {
      ...emptyGroupState('main'),
      keys: [...keys, { ...keys[0]!, epoch: 1000 }],
    });
    expect(await readGroupState(APP, over)).toBeUndefined();
    void grantText;
  });
});
