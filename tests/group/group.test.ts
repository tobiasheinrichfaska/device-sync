import { describe, expect, it } from 'vitest';
import {
  acceptGrant,
  decryptGroup,
  emptyGroupState,
  encryptGroup,
  highestEpoch,
  isRotationLead,
  issueGrants,
  needsRotation,
  openRotationRequest,
  preferredKey,
  pruneGroup,
  readGroupState,
  rotateGroup,
  sealRotationRequest,
  storeGroupState,
  type GroupState,
} from '../../src/group/index.ts';
import { APP, deliver, fresh, realRandom, seeded, show, text, world } from './helpers.ts';

async function started(names = ['A', 'B', 'C']) {
  const w = await world(names);
  const [a] = w.devs;
  const r = await rotateGroup({
    appId: APP,
    own: w.own(a!),
    trust: await w.trustOf(a!),
    state: fresh(),
    random: seeded(1),
  });
  if (!r.ok) throw new Error(r.reason);
  const states = new Map<string, GroupState>([[a!.id, r.state]]);
  await deliver(w, states, r.grants);
  return { w, states, r };
}

describe('start, distribute, encrypt, decrypt', () => {
  it('epoch 1 reaches every trusted device and all read what one writes', async () => {
    const { w, states, r } = await started();
    expect(r.ok && r.rotated?.epoch).toBe(1);
    expect(r.ok && r.grants.length).toBe(2);
    for (const d of w.devs) expect(highestEpoch(states.get(d.id)!)).toBe(1);
    const [a, b, c] = w.devs;
    const enc = await encryptGroup({
      appId: APP,
      state: states.get(b!.id)!,
      plaintext: text('hello'),
      random: seeded(2),
    });
    expect(enc.ok).toBe(true);
    for (const d of [a!, b!, c!]) {
      const dec = await decryptGroup({
        appId: APP,
        state: states.get(d.id)!,
        text: enc.ok ? enc.text : '',
      });
      expect(dec.ok && show(dec.plaintext)).toBe('hello');
      expect(dec.ok && dec.current).toBe(true);
    }
  });

  it('empty plaintext and a large one round-trip; the text is one compact spelling', async () => {
    const { states, w } = await started(['A', 'B']);
    const state = states.get(w.devs[0]!.id)!;
    for (const size of [0, 1, 65_536, 1_048_576]) {
      const plaintext = realRandom(size);
      const enc = await encryptGroup({ appId: APP, state, plaintext, random: realRandom });
      if (!enc.ok) throw new Error(enc.reason);
      expect(enc.text).toMatch(
        /^\{"m":"syncdemo-gdata:2","set":"main","epoch":1,"kid":"[\w-]{22}","salt":"[\w-]{22}","ct":"[\w-]+"\}$/,
      );
      const dec = await decryptGroup({ appId: APP, state, text: enc.text });
      expect(dec.ok && Buffer.from(dec.plaintext).equals(Buffer.from(plaintext))).toBe(true);
    }
    const big = await encryptGroup({
      appId: APP,
      state,
      plaintext: new Uint8Array(1_048_577),
      random: realRandom,
    });
    expect(big).toEqual({ ok: false, reason: 'too-large' });
  });

  it('the same plaintext gives a different text every time (fresh salt)', async () => {
    const { states, w } = await started(['A', 'B']);
    const state = states.get(w.devs[0]!.id)!;
    const x = await encryptGroup({ appId: APP, state, plaintext: text('x'), random: realRandom });
    const y = await encryptGroup({ appId: APP, state, plaintext: text('x'), random: realRandom });
    expect(x.ok && y.ok && x.text !== y.text).toBe(true);
  });

  it('refusals are codes: no key, bad random, bad input', async () => {
    const e = (over: object) =>
      encryptGroup({
        appId: APP,
        state: fresh(),
        plaintext: text('x'),
        random: realRandom,
        ...over,
      });
    expect(await e({})).toEqual({ ok: false, reason: 'no-key' });
    const { states, w } = await started(['A', 'B']);
    const state = states.get(w.devs[0]!.id)!;
    expect(await e({ state, random: () => new Uint8Array(3) })).toEqual({
      ok: false,
      reason: 'bad-random',
    });
    expect(
      await e({
        state,
        random: () => {
          throw new Error('x');
        },
      }),
    ).toEqual({ ok: false, reason: 'bad-random' });
    expect(await e({ state, plaintext: 'no' })).toEqual({ ok: false, reason: 'bad-input' });
    expect(await e({ state, context: 'a'.repeat(513) })).toEqual({
      ok: false,
      reason: 'bad-input',
    });
    expect(await e({ state, context: '\ud800' })).toEqual({ ok: false, reason: 'bad-input' });
  });
});

describe('what is bound into a message', () => {
  it('the context, the app, the data set and the epoch', async () => {
    const { states, w } = await started(['A', 'B']);
    const state = states.get(w.devs[0]!.id)!;
    const enc = await encryptGroup({
      appId: APP,
      state,
      plaintext: text('x'),
      context: 'record-1',
      random: realRandom,
    });
    if (!enc.ok) throw new Error();
    const ok = await decryptGroup({ appId: APP, state, text: enc.text, context: 'record-1' });
    expect(ok.ok).toBe(true);
    expect(await decryptGroup({ appId: APP, state, text: enc.text })).toMatchObject({
      reason: 'cannot-open',
    });
    expect(
      await decryptGroup({ appId: APP, state, text: enc.text, context: 'record-2' }),
    ).toMatchObject({ reason: 'cannot-open' });
    expect(await decryptGroup({ appId: 'other', state, text: enc.text })).toMatchObject({
      reason: 'not-group-data',
    });
    expect(
      await decryptGroup({ appId: APP, state: { ...state, dataSet: 'other' }, text: enc.text }),
    ).toMatchObject({ reason: 'wrong-data-set' });
  });

  it('epoch confusion: a message relabelled with another epoch or key id does not open', async () => {
    const { states, w } = await started(['A', 'B']);
    const [a, b] = w.devs;
    let state = states.get(a!.id)!;
    const e1 = await encryptGroup({
      appId: APP,
      state,
      plaintext: text('one'),
      random: realRandom,
    });
    // epoch 2 with another key, delivered to B as well
    const r2 = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state,
      random: seeded(9),
    });
    if (!r2.ok) throw new Error();
    state = r2.state;
    states.set(a!.id, state);
    await deliver(w, states, r2.grants);
    const stateB = states.get(b!.id)!;
    expect(highestEpoch(stateB)).toBe(2);
    if (!e1.ok) throw new Error();
    const e2 = await encryptGroup({
      appId: APP,
      state,
      plaintext: text('two'),
      random: realRandom,
    });
    if (!e2.ok) throw new Error();
    const k1 = stateB.keys[0]!;
    const k2 = stateB.keys[1]!;
    // relabel: epoch 1 text carrying epoch 2 / kid 2, and the other way round
    const relabel = (t: string, epoch: number, kid: string): string =>
      t.replace(/"epoch":\d+/, `"epoch":${epoch}`).replace(/"kid":"[^"]+"/, `"kid":"${kid}"`);
    expect(
      (await decryptGroup({ appId: APP, state: stateB, text: relabel(e1.text, 2, k2.kid) })).ok,
    ).toBe(false);
    expect(
      (await decryptGroup({ appId: APP, state: stateB, text: relabel(e2.text, 1, k1.kid) })).ok,
    ).toBe(false);
    // the right labels still open both; old data stays readable, only the new one is `current`
    const d1 = await decryptGroup({ appId: APP, state: stateB, text: e1.text });
    const d2 = await decryptGroup({ appId: APP, state: stateB, text: e2.text });
    expect(d1.ok && d1.current).toBe(false);
    expect(d2.ok && d2.current).toBe(true);
  });

  it('an unknown key names the epoch and key id so the app can ask for it', async () => {
    const { states, w } = await started(['A', 'B']);
    const enc = await encryptGroup({
      appId: APP,
      state: states.get(w.devs[0]!.id)!,
      plaintext: text('x'),
      random: realRandom,
    });
    if (!enc.ok) throw new Error();
    const dec = await decryptGroup({ appId: APP, state: fresh(), text: enc.text });
    expect(dec).toEqual({ ok: false, reason: 'unknown-key', epoch: 1, kid: enc.kid });
  });
});

describe('removal and rotation', () => {
  it('a removed device gets no grant for the new epoch and cannot read it, but keeps the old', async () => {
    const { w, states } = await started(['A', 'B', 'C']);
    const [a, b, c] = w.devs;
    const old = await encryptGroup({
      appId: APP,
      state: states.get(c!.id)!,
      plaintext: text('before'),
      random: realRandom,
    });
    await w.remove(c!);
    const trustA = await w.trustOf(a!);
    const need = needsRotation(states.get(a!.id)!, trustA);
    expect(need.needed).toBe(true);
    expect(need.removedHolders).toEqual([c!.id]);
    const r = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: trustA,
      state: states.get(a!.id)!,
      random: seeded(3),
    });
    if (!r.ok) throw new Error(r.reason);
    expect(r.grants.map((g) => g.to)).toEqual([b!.id]);
    states.set(a!.id, r.state);
    await deliver(w, states, r.grants);
    expect(needsRotation(r.state, trustA).needed).toBe(false);
    const fresher = await encryptGroup({
      appId: APP,
      state: r.state,
      plaintext: text('after'),
      random: realRandom,
    });
    if (!fresher.ok || !old.ok) throw new Error();
    const stateC = states.get(c!.id)!;
    expect(highestEpoch(stateC)).toBe(1);
    expect(await decryptGroup({ appId: APP, state: stateC, text: fresher.text })).toMatchObject({
      reason: 'unknown-key',
      epoch: 2,
    });
    expect((await decryptGroup({ appId: APP, state: stateC, text: old.text })).ok).toBe(true);
    // a grant made for B cannot be opened by C, and C has no standing to send one
    const forC = await acceptGrant({
      appId: APP,
      own: w.own(c!),
      trust: await w.trustOf(c!),
      state: stateC,
      file: r.grants[0]!.file,
    });
    expect(forC).toEqual({ ok: false, reason: 'wrong-recipient' });
    // B, who knows the removal, refuses a grant C makes later
    const evil = await rotateGroup({
      appId: APP,
      own: w.own(c!),
      trust: { trusted: (await w.trustOf(a!)).trusted, removed: [] },
      state: stateC,
      random: seeded(4),
    });
    if (!evil.ok) throw new Error(evil.reason);
    const toB = evil.grants.find((g) => g.to === b!.id)!;
    expect(
      await acceptGrant({
        appId: APP,
        own: w.own(b!),
        trust: await w.trustOf(b!),
        state: states.get(b!.id)!,
        file: toB.file,
      }),
    ).toEqual({ ok: false, reason: 'sender-not-trusted' });
  });

  it('a device that is not trusted cannot start a rotation for itself', async () => {
    const w = await world(['A', 'B']);
    const b = w.devs[1]!;
    await w.remove(b);
    const r = await rotateGroup({
      appId: APP,
      own: w.own(b),
      trust: await w.trustOf(b),
      state: fresh(),
      random: seeded(1),
    });
    expect(r).toEqual({ ok: false, reason: 'self-removed' });
  });

  it('a late removal: the removed device is in the audience, so the rotation is called for', async () => {
    const { w, states } = await started(['A', 'B', 'C']);
    const [a, b] = w.devs;
    await w.remove(w.devs[2]!);
    expect(needsRotation(states.get(b!.id)!, await w.trustOf(b!)).removedHolders).toHaveLength(1);
    expect(needsRotation(fresh(), await w.trustOf(a!))).toMatchObject({ needed: true });
  });

  it('a device that joined later gets the keys through issueGrants and reads old data only if given them', async () => {
    const { w, states } = await started(['A', 'B']);
    const a = w.devs[0]!;
    const old = await encryptGroup({
      appId: APP,
      state: states.get(a.id)!,
      plaintext: text('old'),
      random: realRandom,
    });
    // a second epoch, then D joins
    const r2 = await rotateGroup({
      appId: APP,
      own: w.own(a),
      trust: await w.trustOf(a),
      state: states.get(a.id)!,
      random: seeded(5),
    });
    if (!r2.ok) throw new Error();
    states.set(a.id, r2.state);
    const w2 = await world(['A', 'B']); // a separate small world is enough to get a third device
    void w2;
    const joiner = (await world(['J'])).devs[0]!;
    // enter the joiner into the first world by hand
    const { enter, opts } = await import('../trust/helpers.ts');
    w.replica = await enter(w.admin, w.replica, joiner, 'member', opts());
    const trustA = await w.trustOf(a);
    expect(needsRotation(r2.state, trustA).missing).toEqual([joiner.id]);
    const current = await issueGrants({
      appId: APP,
      own: w.own(a),
      trust: trustA,
      state: r2.state,
      to: [joiner.id],
      which: 'current',
      random: seeded(6),
    });
    if (!current.ok) throw new Error(current.reason);
    expect(current.grants).toHaveLength(1);
    expect(needsRotation(current.state, trustA).missing).toEqual([]);
    const all = await issueGrants({
      appId: APP,
      own: w.own(a),
      trust: trustA,
      state: r2.state,
      to: [joiner.id],
      which: 'all',
      random: seeded(7),
    });
    if (!all.ok) throw new Error();
    expect(all.grants).toHaveLength(2);
    const stJ = new Map<string, GroupState>();
    const joinerWorld = { ...w, devs: [...w.devs, joiner] } as typeof w;
    await deliver(joinerWorld, stJ, current.grants);
    expect(highestEpoch(stJ.get(joiner.id)!)).toBe(2);
    expect(
      await decryptGroup({ appId: APP, state: stJ.get(joiner.id)!, text: old.ok ? old.text : '' }),
    ).toMatchObject({ reason: 'unknown-key' });
    await deliver(joinerWorld, stJ, all.grants);
    expect(
      (await decryptGroup({ appId: APP, state: stJ.get(joiner.id)!, text: old.ok ? old.text : '' }))
        .ok,
    ).toBe(true);
    // issuing to a device that is not trusted, or to oneself, is refused
    expect(
      await issueGrants({
        appId: APP,
        own: w.own(a),
        trust: trustA,
        state: r2.state,
        to: ['nobody'],
        which: 'current',
        random: seeded(8),
      }),
    ).toEqual({ ok: false, reason: 'bad-recipient' });
    expect(
      await issueGrants({
        appId: APP,
        own: w.own(a),
        trust: trustA,
        state: fresh(),
        to: [joiner.id],
        which: 'current',
        random: seeded(8),
      }),
    ).toEqual({ ok: false, reason: 'no-key' });
  });

  it('rotation lead is the lowest id among the trusted holders', async () => {
    const { w, states } = await started(['A', 'B', 'C']);
    const ids = w.devs.map((d) => d.id).sort();
    const lead: string[] = [];
    for (const d of w.devs) {
      if (isRotationLead(states.get(d.id)!, await w.trustOf(d), d.id)) lead.push(d.id);
    }
    expect(lead).toEqual([ids[0]]);
    expect(isRotationLead(fresh(), await w.trustOf(w.admin), ids[0]!)).toBe(false);
  });
});

describe('replay and epoch jumps', () => {
  it('a replayed grant changes nothing; one below the floor is refused', async () => {
    const { w, states, r } = await started(['A', 'B']);
    const [a, b] = w.devs;
    const before = states.get(b!.id)!;
    const again = await acceptGrant({
      appId: APP,
      own: w.own(b!),
      trust: await w.trustOf(b!),
      state: before,
      file: r.grants[0]!.file,
    });
    expect(again.ok && again.change).toBe('same');
    expect(again.ok && again.state).toEqual(before);
    // epoch 2 arrives, the app prunes epoch 1, the old grant is refused for good
    const r2 = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: states.get(a!.id)!,
      random: seeded(11),
    });
    if (!r2.ok) throw new Error();
    const accepted = await acceptGrant({
      appId: APP,
      own: w.own(b!),
      trust: await w.trustOf(b!),
      state: before,
      file: r2.grants[0]!.file,
    });
    if (!accepted.ok) throw new Error(accepted.reason);
    const pruned = pruneGroup(accepted.state, 2);
    expect(pruned.floor).toBe(2);
    expect(pruned.keys.map((k) => k.epoch)).toEqual([2]);
    const replay = await acceptGrant({
      appId: APP,
      own: w.own(b!),
      trust: await w.trustOf(b!),
      state: pruned,
      file: r.grants[0]!.file,
    });
    expect(replay).toEqual({ ok: false, reason: 'below-floor' });
    // the highest epoch is never pruned
    expect(pruneGroup(pruned, 99).keys).toHaveLength(1);
  });

  it('a grant far above the epochs held is refused once a state holds any', async () => {
    const { w, states } = await started(['A', 'B']);
    const [a, b] = w.devs;
    let state = states.get(a!.id)!;
    const jump = { ...state, keys: [{ ...state.keys[0]!, epoch: 5000 }] };
    const r = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: jump,
      random: seeded(12),
    });
    if (!r.ok) throw new Error();
    state = states.get(b!.id)!;
    expect(
      await acceptGrant({
        appId: APP,
        own: w.own(b!),
        trust: await w.trustOf(b!),
        state,
        file: r.grants[0]!.file,
      }),
    ).toEqual({ ok: false, reason: 'epoch-jump' });
    // a device with an empty state takes any epoch (it joins late)
    expect(
      (
        await acceptGrant({
          appId: APP,
          own: w.own(b!),
          trust: await w.trustOf(b!),
          state: fresh(),
          file: r.grants[0]!.file,
        })
      ).ok,
    ).toBe(true);
  });
});

describe('rotation by request', () => {
  it('a trusted device asks, the answer sees whether the request is stale', async () => {
    const { w, states } = await started(['A', 'B']);
    const [a, b] = w.devs;
    const sealed = await sealRotationRequest({
      appId: APP,
      own: w.own(b!),
      to: { device: a!.id, dh: a!.intro.dh },
      state: states.get(b!.id)!,
      random: seeded(13),
    });
    if (!sealed.ok) throw new Error();
    const open = await openRotationRequest({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: states.get(a!.id)!,
      file: sealed.file,
    });
    expect(open).toEqual({ ok: true, from: b!.id, epoch: 1, stale: false });
    const r = await rotateGroup({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: states.get(a!.id)!,
      random: seeded(14),
    });
    if (!r.ok) throw new Error();
    const again = await openRotationRequest({
      appId: APP,
      own: w.own(a!),
      trust: await w.trustOf(a!),
      state: r.state,
      file: sealed.file,
    });
    expect(again).toMatchObject({ ok: true, stale: true });
    // a request is not a grant and a grant is not a request
    expect(
      await acceptGrant({
        appId: APP,
        own: w.own(a!),
        trust: await w.trustOf(a!),
        state: r.state,
        file: sealed.file,
      }),
    ).toEqual({ ok: false, reason: 'bad-payload' });
    expect(
      await openRotationRequest({
        appId: APP,
        own: w.own(b!),
        trust: await w.trustOf(b!),
        state: states.get(b!.id)!,
        file: r.grants[0]!.file,
      }),
    ).toEqual({ ok: false, reason: 'bad-payload' });
  });
});

describe('stored state', () => {
  it('round-trips as one spelling and derives the key ids again', async () => {
    const { w, states } = await started(['A', 'B']);
    const state = states.get(w.devs[0]!.id)!;
    const t = storeGroupState(APP, state);
    expect(
      t.startsWith('{"m":"syncdemo-gstate:2","set":"main","floor":0,"keys":[{"epoch":1,'),
    ).toBe(true);
    expect(await readGroupState(APP, t)).toEqual(state);
    expect(await readGroupState('other', t)).toBeUndefined();
    expect(await readGroupState(APP, t + ' ')).toBeUndefined();
    expect(await readGroupState(APP, 'x')).toBeUndefined();
    expect(await readGroupState(APP, storeGroupState(APP, emptyGroupState('x')))).toEqual(
      emptyGroupState('x'),
    );
    expect(preferredKey(state)?.epoch).toBe(1);
  });
});
