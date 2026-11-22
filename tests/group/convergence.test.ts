import { describe, expect, it } from 'vitest';
import {
  acceptGrant,
  addGroupKey,
  emptyGroupState,
  preferredKey,
  rotateGroup,
  storeGroupState,
  type GroupKey,
  type GroupState,
} from '../../src/group/index.ts';
import { APP, fresh, prng, seeded, world } from './helpers.ts';

const key = (epoch: number, author: string, n = 1): GroupKey => ({
  epoch,
  author,
  kid: `kid-${epoch}-${author}-${n}`,
  key: Buffer.alloc(32, n).toString('base64url'),
  audience: [author],
});

describe('concurrent rotations', () => {
  it('two devices rotate at once: whichever order the grants arrive in, the same key is chosen', async () => {
    const w = await world(['A', 'B', 'C']);
    const [a, b, c] = w.devs;
    const start = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: fresh(),
      random: seeded(1),
    });
    if (!start.ok) throw new Error();
    const take = async (d: typeof a, st: GroupState, file: Uint8Array) => {
      const r = await acceptGrant({
        appId: APP,
        own: w.own(d!),
        trust: await w.trustOf(d!),
        state: st,
        file,
      });
      if (!r.ok) throw new Error(r.reason);
      return r.state;
    };
    const base = new Map<string, GroupState>();
    for (const g of start.grants)
      base.set(
        g.to,
        await take(
          w.devs.find((d) => d.id === g.to),
          fresh(),
          g.file,
        ),
      );
    base.set(a!.id, start.state);
    const ra = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: base.get(a!.id)!,
      random: seeded(2),
    });
    const rb = await rotateGroup({
      appId: APP,
      own: w.own(b!),
      trust: await w.trustOf(b!),
      state: base.get(b!.id)!,
      random: seeded(3),
    });
    if (!ra.ok || !rb.ok) throw new Error();
    expect(ra.rotated?.epoch).toBe(2);
    expect(rb.rotated?.epoch).toBe(2);
    expect(ra.rotated?.kid).not.toBe(rb.rotated?.kid);
    const fromA = ra.grants.find((g) => g.to === c!.id)!.file;
    const fromB = rb.grants.find((g) => g.to === c!.id)!.file;
    const one = await take(c, await take(c, base.get(c!.id)!, fromA), fromB);
    const two = await take(c, await take(c, base.get(c!.id)!, fromB), fromA);
    expect(storeGroupState(APP, one)).toBe(storeGroupState(APP, two));
    // A and B each take the other's grant too
    const aAll = await take(a, ra.state, rb.grants.find((g) => g.to === a!.id)!.file);
    const bAll = await take(b, rb.state, ra.grants.find((g) => g.to === b!.id)!.file);
    const winner = [a!.id, b!.id].sort()[0];
    for (const s of [one, aAll, bAll]) {
      expect(preferredKey(s)?.epoch).toBe(2);
      expect(preferredKey(s)?.author).toBe(winner);
    }
    // both stay held: data under the losing key is still readable
    expect(one.keys.filter((k) => k.epoch === 2)).toHaveLength(2);
  });

  it('addGroupKey is order independent: 200 seeded permutations of 12 keys', () => {
    const next = prng(7);
    const authors = ['device-b', 'device-a', 'device-c', 'device-é', 'device-ab'];
    const keys: GroupKey[] = [];
    for (let e = 1; e <= 4; e += 1) {
      for (const [i, author] of authors.entries())
        if ((e + i) % 2 === 0 || e === 4) keys.push(key(e, author, e * 10 + i));
    }
    let reference: string | undefined;
    for (let run = 0; run < 200; run += 1) {
      const order = [...keys].sort(() => next() - 0.5);
      let s = emptyGroupState('main');
      for (const k of order) {
        const r = addGroupKey(s, k);
        if (!r.ok) throw new Error(r.reason);
        s = r.state;
      }
      const t = storeGroupState(APP, s);
      reference ??= t;
      expect(t).toBe(reference);
      expect(preferredKey(s)?.epoch).toBe(4);
    }
    // UTF-8 byte order, not UTF-16: 'device-a' < 'device-ab' < 'device-b' < 'device-c' < 'device-é'
    let s = emptyGroupState('main');
    for (const k of keys.filter((x) => x.epoch === 4))
      s = (addGroupKey(s, k) as { state: GroupState }).state;
    expect(s.keys.map((k) => k.author)).toEqual([
      'device-a',
      'device-ab',
      'device-b',
      'device-c',
      'device-é',
    ]);
  });

  it('a low id wins the choice but gains nothing else: every candidate is kept and only trusted devices author one', () => {
    let s = emptyGroupState('main');
    for (const author of ['z', 'm', 'a'])
      s = (addGroupKey(s, key(3, author)) as { state: GroupState }).state;
    expect(preferredKey(s)?.author).toBe('a');
    // a higher epoch beats any id
    s = (addGroupKey(s, key(4, 'zzz')) as { state: GroupState }).state;
    expect(preferredKey(s)?.author).toBe('zzz');
  });
});

describe('caps and refusals of the state', () => {
  it('a second key by the same author and epoch, a full epoch, a full state, audiences', () => {
    let s = emptyGroupState('main');
    s = (addGroupKey(s, key(1, 'a')) as { state: GroupState }).state;
    expect(addGroupKey(s, key(1, 'a', 2))).toEqual({ ok: false, reason: 'author-conflict' });
    expect(addGroupKey(s, key(1, 'a'))).toMatchObject({ ok: true, change: 'same' });
    expect(addGroupKey(s, { ...key(1, 'a'), audience: ['a', 'b'] })).toMatchObject({
      ok: true,
      change: 'audience',
    });
    const limits = { maxPerEpoch: 2, maxKeys: 4, maxAudience: 2 };
    expect(addGroupKey(s, { ...key(1, 'a'), audience: ['a', 'b', 'c'] }, limits)).toEqual({
      ok: false,
      reason: 'audience-full',
    });
    s = (addGroupKey(s, key(1, 'b'), limits) as { state: GroupState }).state;
    expect(addGroupKey(s, key(1, 'c'), limits)).toEqual({ ok: false, reason: 'epoch-full' });
    s = (addGroupKey(s, key(2, 'a'), limits) as { state: GroupState }).state;
    s = (addGroupKey(s, key(3, 'a'), limits) as { state: GroupState }).state;
    expect(addGroupKey(s, key(4, 'a'), limits)).toEqual({ ok: false, reason: 'too-many-keys' });
    expect(addGroupKey(s, key(2000, 'a'), { ...limits, maxKeys: 9 })).toEqual({
      ok: false,
      reason: 'epoch-jump',
    });
  });

  it('a rotation to more devices than the audience limit is refused; the epoch never overflows', async () => {
    const w = await world(['A', 'B', 'C']);
    const a = w.devs[0]!;
    const own = w.own(a);
    const trust = await w.trustOf(a);
    expect(
      await rotateGroup({
        appId: APP,
        own,
        trust,
        state: fresh(),
        random: seeded(1),
        limits: { maxAudience: 2 },
      }),
    ).toEqual({ ok: false, reason: 'too-many-devices' });
    const max = { dataSet: 'main', floor: 0, keys: [{ ...key(4_294_967_295, a.id) }] };
    expect(await rotateGroup({ appId: APP, own, trust, state: max, random: seeded(1) })).toEqual({
      ok: false,
      reason: 'epoch-exhausted',
    });
  });
});
