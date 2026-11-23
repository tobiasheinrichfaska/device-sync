// Grants and rotation requests are signed by the issuing device's signing key: a valid encrypted
// file alone (the static agreement keys) is not enough.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { openFile, sealFile } from '../../src/core/index.ts';
import { signText } from '../../src/core/signature.ts';
import {
  acceptGrant,
  issueGrants,
  openRotationRequest,
  rotateGroup,
  sealRotationRequest,
  type GroupState,
} from '../../src/group/index.ts';
import { grantSigText, parseGrant, parseRequest, requestSigText } from '../../src/group/wire.ts';
import { APP, fresh, realRandom, seeded, world, type World } from './helpers.ts';
import type { Dev } from '../trust/helpers.ts';

afterEach(() => vi.restoreAllMocks());

const utf8 = new TextEncoder();
const text = (b: Uint8Array): string => new TextDecoder().decode(b);

async function setup() {
  const w = await world(['A', 'B', 'C']);
  const [a, b, c] = w.devs as [Dev, Dev, Dev];
  const r = await rotateGroup({
    appId: APP,
    own: w.own(a),
    trust: await w.trustOf(a),
    state: fresh(),
    random: seeded(61),
  });
  if (!r.ok) throw new Error(r.reason);
  const fileFor = (d: Dev) => r.grants.find((g) => g.to === d.id)!.file;
  return { w, a, b, c, r, fileFor };
}

/** The plaintext payload of a file `from` sent to `to` (the test holds every key). */
async function payloadOf(w: World, from: Dev, to: Dev, file: Uint8Array): Promise<string> {
  const opened = await openFile({
    appId: APP,
    own: w.own(to),
    from: { device: from.id, dh: from.intro.dh },
    file,
  });
  if (!opened.ok) throw new Error(opened.reason);
  return text(opened.payload);
}

/** A file for `to` that really comes from `from`'s agreement key (a leaked key forges exactly this). */
async function forge(w: World, from: Dev, to: Dev, payload: string): Promise<Uint8Array> {
  const sealed = await sealFile({
    appId: APP,
    own: w.own(from),
    to: { device: to.id, dh: to.intro.dh },
    payload: utf8.encode(payload),
    random: realRandom(12),
  });
  if (!sealed.ok) throw new Error(sealed.reason);
  return sealed.file;
}

async function acceptAt(w: World, d: Dev, file: Uint8Array, state: GroupState = fresh()) {
  return acceptGrant({ appId: APP, own: w.own(d), trust: await w.trustOf(d), state, file });
}

describe('signed grants', () => {
  it('an honest grant is signed by its issuer and accepted', async () => {
    const { w, a, b, r, fileFor } = await setup();
    const g = parseGrant(APP, await payloadOf(w, a, b, fileFor(b)))!;
    expect(g).toMatchObject({ from: a.id, to: b.id, author: a.id, epoch: 1 });
    expect(g.kid).toBe(r.state.keys[0]!.kid);
    const res = await acceptAt(w, b, fileFor(b));
    expect(res.ok && res.key.kid).toBe(g.kid);
  });

  it('a valid file with an absent signature is refused', async () => {
    const { w, a, b, fileFor } = await setup();
    const payload = await payloadOf(w, a, b, fileFor(b));
    const without = payload.replace(/,"sig":"[^"]*"\}$/, '}');
    expect(without).not.toBe(payload);
    expect(await acceptAt(w, b, await forge(w, a, b, without))).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
    // the earlier, unsigned format (version 2) is not a grant any more
    const v2 = `{"m":"${APP}-gkey:2","set":"main","epoch":1,"author":"${a.id}","key":"${'A'.repeat(43)}","audience":["${a.id}"]}`;
    expect(await acceptAt(w, b, await forge(w, a, b, v2))).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
  });

  it('a valid file whose signature is wrong is refused (leaked agreement key, other signing key)', async () => {
    const { w, a, b, c, fileFor } = await setup();
    const g = parseGrant(APP, await payloadOf(w, a, b, fileFor(b)))!;
    // the attacker holds A's agreement key (the file is genuine) but signs with its own key
    const forged = parseGrant(
      APP,
      (await payloadOf(w, a, b, fileFor(b))).replace(
        g.sig,
        await signText(c.keys.signing.privateKey, grantSigText(APP, g)),
      ),
    )!;
    expect(forged.sig).not.toBe(g.sig);
    const text1 = (await payloadOf(w, a, b, fileFor(b))).replace(g.sig, forged.sig);
    expect(await acceptAt(w, b, await forge(w, a, b, text1))).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
    // a made-up signature
    const junk = Buffer.alloc(64, 9).toString('base64url');
    const text2 = (await payloadOf(w, a, b, fileFor(b))).replace(g.sig, junk);
    expect(await acceptAt(w, b, await forge(w, a, b, text2))).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('the attacker cannot hand out its own key "from" a trusted device', async () => {
    const { w, a, b, c } = await setup();
    // C (trusted) is not the attacker here: the attacker holds only A's agreement key and invents a key
    const key = Buffer.alloc(32, 7);
    const head = {
      set: 'main',
      epoch: 5,
      author: a.id,
      from: a.id,
      to: b.id,
      kid: '',
      audience: [a.id, b.id],
    };
    const { deriveKeyId } = await import('../../src/group/derive.ts');
    head.kid = await deriveKeyId(APP, 'main', 5, key);
    const sig = await signText(c.keys.signing.privateKey, grantSigText(APP, head));
    const { grantText } = await import('../../src/group/wire.ts');
    const payload = grantText(APP, { ...head, key: key.toString('base64url'), sig });
    expect(await acceptAt(w, b, await forge(w, a, b, payload))).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('a signature of a trusted device other than the sender does not count', async () => {
    const { w, a, b, c, fileFor } = await setup();
    // a genuine grant from A, re-sealed by C (trusted, holds its own keys): the issuer is A, the sender C
    const payload = await payloadOf(w, a, b, fileFor(b));
    expect(await acceptAt(w, b, await forge(w, c, b, payload))).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
  });

  it('the trust layer decides the signing key: a wrong key for the sender refuses', async () => {
    const { w, a, b, c, fileFor } = await setup();
    const trust = await w.trustOf(b);
    const swapped = {
      ...trust,
      trusted: trust.trusted.map((d) => (d.device === a.id ? { ...d, sig: c.intro.sig } : d)),
    };
    const res = await acceptGrant({
      appId: APP,
      own: w.own(b),
      trust: swapped,
      state: fresh(),
      file: fileFor(b),
    });
    expect(res).toEqual({ ok: false, reason: 'bad-signature' });
    const garbage = {
      ...trust,
      trusted: trust.trusted.map((d) => (d.device === a.id ? { ...d, sig: 'x' } : d)),
    };
    expect(
      await acceptGrant({
        appId: APP,
        own: w.own(b),
        trust: garbage,
        state: fresh(),
        file: fileFor(b),
      }),
    ).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('replay of a grant to another recipient is refused', async () => {
    const { w, a, b, c, fileFor } = await setup();
    const payload = await payloadOf(w, a, b, fileFor(b));
    // by a holder of A's agreement key: a genuine-looking file for C with B's payload
    expect(await acceptAt(w, c, await forge(w, a, c, payload))).toEqual({
      ok: false,
      reason: 'wrong-recipient',
    });
    // the same payload, with the recipient rewritten: the signature no longer holds
    const moved = payload.replace(`"to":"${b.id}"`, `"to":"${c.id}"`);
    expect(await acceptAt(w, c, await forge(w, a, c, moved))).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
    // the file itself, handed to C: the file header names B
    expect(await acceptAt(w, c, fileFor(b))).toEqual({ ok: false, reason: 'wrong-recipient' });
  });

  it('a replayed genuine grant changes nothing', async () => {
    const { w, b, fileFor } = await setup();
    const first = await acceptAt(w, b, fileFor(b));
    if (!first.ok) throw new Error();
    const again = await acceptAt(w, b, fileFor(b), first.state);
    expect(again.ok && again.change).toBe('same');
  });

  it('a grant for another data set or app signs over that: moved between sets it is refused', async () => {
    const { w, a, b, fileFor } = await setup();
    const payload = await payloadOf(w, a, b, fileFor(b));
    // the key id binds the data set, so the moved payload fails already at the key id
    const other = payload.replace('"set":"main"', '"set":"other"');
    expect(await acceptAt(w, b, await forge(w, a, b, other))).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
  });

  it('every byte of the signed payload: nothing is accepted, one verification at most', async () => {
    const { w, a, b, fileFor } = await setup();
    const payload = await payloadOf(w, a, b, fileFor(b));
    const bytes = utf8.encode(payload);
    expect((await acceptAt(w, b, await forge(w, a, b, payload))).ok).toBe(true);
    let refused = 0;
    for (let i = 0; i < bytes.length; i += 1) {
      const changed = Uint8Array.from(bytes);
      changed[i] = (changed[i] as number) ^ (1 << (i % 8));
      const res = await acceptAt(w, b, await forge(w, a, b, text(changed)));
      expect(res.ok, `byte ${i}`).toBe(false);
      refused += 1;
    }
    expect(refused).toBe(bytes.length);
  });

  it('a forged grant costs no signature check before the file opened, and one after', async () => {
    const { w, a, b, fileFor } = await setup();
    const payload = await payloadOf(w, a, b, fileFor(b));
    await w.trustOf(b); // derived (and cached) before counting
    const spyVerify = vi.spyOn(crypto.subtle, 'verify');
    // unsigned: the strict reader refuses, nothing is verified
    const without = payload.replace(/,"sig":"[^"]*"\}$/, '}');
    await acceptAt(w, b, await forge(w, a, b, without));
    expect(spyVerify).toHaveBeenCalledTimes(0);
    // another recipient inside the payload: refused before the signature check
    await acceptAt(w, b, await forge(w, a, b, payload.replace(`"to":"${b.id}"`, '"to":"x"')));
    expect(spyVerify).toHaveBeenCalledTimes(0);
    // a signature of the wrong content: exactly one verification
    await acceptAt(
      w,
      b,
      await forge(w, a, b, payload.replace(`"author":"${a.id}"`, `"author":"${b.id}"`)),
    );
    expect(spyVerify).toHaveBeenCalledTimes(1);
  });

  it('a key swapped under a valid signature is refused by the key id', async () => {
    const { w, a, b, fileFor } = await setup();
    const payload = await payloadOf(w, a, b, fileFor(b));
    const g = parseGrant(APP, payload)!;
    const swapped = payload.replace(g.key, Buffer.alloc(32, 3).toString('base64url'));
    expect(await acceptAt(w, b, await forge(w, a, b, swapped))).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
  });

  it('a forwarded key is signed by the forwarder, with the original author inside', async () => {
    const { w, a, b, c, r } = await setup();
    const states = new Map<string, GroupState>();
    const first = await acceptAt(w, b, r.grants.find((g) => g.to === b.id)!.file);
    if (!first.ok) throw new Error();
    states.set(b.id, first.state);
    const fwd = await issueGrants({
      appId: APP,
      own: w.own(b),
      trust: await w.trustOf(b),
      state: first.state,
      to: [c.id],
      which: 'current',
      random: seeded(62),
    });
    if (!fwd.ok) throw new Error(fwd.reason);
    const g = parseGrant(APP, await payloadOf(w, b, c, fwd.grants[0]!.file))!;
    expect(g).toMatchObject({ from: b.id, author: a.id, to: c.id });
    const got = await acceptAt(w, c, fwd.grants[0]!.file);
    expect(got.ok && got.from).toBe(b.id);
    // C holds B's grant but the author A did not sign it: swapping the issuer to A fails
    const claimed = (await payloadOf(w, b, c, fwd.grants[0]!.file)).replace(
      `"from":"${b.id}"`,
      `"from":"${a.id}"`,
    );
    expect(await acceptAt(w, c, await forge(w, a, c, claimed))).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });
});

describe('signed rotation requests', () => {
  async function request() {
    const s = await setup();
    const sealed = await sealRotationRequest({
      appId: APP,
      own: s.w.own(s.b),
      to: { device: s.a.id, dh: s.a.intro.dh },
      state: fresh(),
      random: seeded(63),
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    const open = async (file: Uint8Array, d: Dev = s.a) =>
      openRotationRequest({
        appId: APP,
        own: s.w.own(d),
        trust: await s.w.trustOf(d),
        state: s.r.state,
        file,
      });
    return { ...s, sealed, open };
  }

  it('an honest request is signed and opens', async () => {
    const { w, a, b, sealed, open } = await request();
    const req = parseRequest(APP, await payloadOf(w, b, a, sealed.file))!;
    expect(req).toMatchObject({ from: b.id, to: a.id, epoch: 0 });
    expect(await open(sealed.file)).toMatchObject({ ok: true, from: b.id, stale: true });
  });

  it('absent or wrong signature is refused', async () => {
    const { w, a, b, c, sealed, open } = await request();
    const payload = await payloadOf(w, b, a, sealed.file);
    const req = parseRequest(APP, payload)!;
    expect(await open(await forge(w, b, a, payload.replace(/,"sig":"[^"]*"\}$/, '}')))).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
    const other = await signText(c.keys.signing.privateKey, requestSigText(APP, req));
    expect(await open(await forge(w, b, a, payload.replace(req.sig, other)))).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('replay to another recipient is refused', async () => {
    const { w, a, b, c, sealed, open } = await request();
    const payload = await payloadOf(w, b, a, sealed.file);
    expect(await open(await forge(w, b, c, payload), c)).toEqual({
      ok: false,
      reason: 'wrong-recipient',
    });
    expect(
      await open(await forge(w, b, c, payload.replace(`"to":"${a.id}"`, `"to":"${c.id}"`)), c),
    ).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('every byte of the signed payload is refused', async () => {
    const { w, a, b, sealed, open } = await request();
    const payload = await payloadOf(w, b, a, sealed.file);
    const bytes = utf8.encode(payload);
    for (let i = 0; i < bytes.length; i += 1) {
      const changed = Uint8Array.from(bytes);
      changed[i] = (changed[i] as number) ^ (1 << (i % 8));
      expect((await open(await forge(w, b, a, text(changed)))).ok, `byte ${i}`).toBe(false);
    }
  });
});
