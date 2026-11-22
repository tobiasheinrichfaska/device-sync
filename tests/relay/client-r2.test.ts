// The relay client of revision 2 against the reference server (the earlier implementation's cases of
// enrolment, signed requests, refusals, renewal and the step to a certificate, invitation, device list,
// blocking and the blocked hook, re-expressed) and against deliberately old or hostile relays.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  RelayClient,
  readCertificate,
  type RelayClientOptions,
  type FetchLike,
  type RelayResult,
} from '../../src/relay/index.ts';
import { ALPHA, mintProof, serverFor, serverForR2 } from './helpers.ts';
import {
  DEV,
  memoryStore,
  mintFounder,
  newSigner,
  r2Harness,
  type R2Harness,
} from './helpers-r2.ts';

const DAY_MS = 86_400_000;
const MULTI = { app: 'multi', origin: 'https://multi.example' };
const STRICT = { app: 'strict', origin: 'https://strict.example' };

function fail<T>(r: RelayResult<T>) {
  if (r.ok) throw new Error('expected a failure, got a value');
  return r;
}
function value<T>(r: RelayResult<T>): T {
  if (!r.ok) throw new Error(`expected a value, got ${r.kind}`);
  return r.value;
}

const errorFetch =
  (status: number, art: string): FetchLike =>
  () =>
    Promise.resolve(
      new Response(JSON.stringify({ fehler: 'x', art }), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

const bodyOf = (c: { init: RequestInit }): Record<string, unknown> =>
  JSON.parse(c.init.body as string) as Record<string, unknown>;
const headerOf = (c: { init: RequestInit }, name: string): string | undefined =>
  (c.init.headers as Record<string, string>)[name];
const lastCall = (h: R2Harness) => h.calls[h.calls.length - 1] as R2Harness['calls'][number];

/** A store that holds an old access (version 1) of a fresh device. */
async function oldAccessStore(server: ReturnType<typeof serverForR2>) {
  const store = memoryStore();
  const plain = new RelayClient({
    baseUrl: 'https://relay.test',
    appId: 'alpha',
    origin: ALPHA.origin,
    fetch: server.fetch,
    store,
    clock: server.now,
  });
  value(await plain.enrol({ proof: await mintProof('alpha', server.now()) }));
  return store;
}

/** Enrols with a proof and a claimed role, as the old way allows. */
async function enrolWithProof(h: R2Harness, role?: string, app = ALPHA.app) {
  const r = await h.client.enrol({
    proof: await mintProof(app, h.server.now()),
    ...(role ? { role } : {}),
  });
  return value(r);
}

describe('enrolment (revision 2)', () => {
  it('with a proof: our public key and the claimed role go along, the answer is a certificate for exactly that key', async () => {
    const h = await r2Harness();
    const v = await enrolWithProof(h, 'lb:art');
    expect(v).toMatchObject({ group: '1', role: 'lb:art' });
    expect(v.info?.revision).toBe(2);
    const sent = bodyOf(h.calls[0]!);
    expect(sent['geraetSchluessel']).toBe(h.signer.publicKey);
    expect(sent['rolle']).toBe('lb:art');
    expect(Object.keys(sent).sort()).toEqual(['geraetSchluessel', 'nachweis', 'rolle']);
    const stored = JSON.parse(h.store.value as string);
    expect(stored.v).toBe(2);
    expect(readCertificate(stored.access)?.key).toBe(h.signer.publicKey);
    expect(await h.client.state()).toBe('ready');
    // the certificate does not appear in a result
    expect(JSON.stringify(v)).not.toContain(stored.access);
  });

  it('a device with no role claims none: no `rolle` member', async () => {
    const h = await r2Harness();
    await enrolWithProof(h);
    expect(Object.keys(bodyOf(h.calls[0]!)).sort()).toEqual(['geraetSchluessel', 'nachweis']);
  });

  it('a certificate for another key is not taken (the relay must have used ours)', async () => {
    const other = await newSigner();
    const h = await r2Harness({}, serverForR2(), (inner) => (url, init) => {
      // the request is changed on the way: the relay certifies another key
      const body = JSON.parse(init.body as string);
      if (body.geraetSchluessel) body.geraetSchluessel = other.signer.publicKey;
      return inner(url, { ...init, body: JSON.stringify(body) });
    });
    const r = fail(await h.client.enrol({ proof: await mintProof('alpha', h.server.now()) }));
    expect(r.kind).toBe('malformed');
    expect(h.store.value).toBeUndefined();
  });

  it('against a relay of version 1 (it does not know the key: unlesbar): once more without key and role, the old access; the proof is the same', async () => {
    const h = await r2Harness({}, serverFor({ revision: 1 }));
    const v = await enrolWithProof(h, 'lb:art');
    expect(v.group).toBeUndefined();
    expect(h.calls).toHaveLength(2);
    expect(bodyOf(h.calls[0]!)['nachweis']).toBe(bodyOf(h.calls[1]!)['nachweis']);
    expect(Object.keys(bodyOf(h.calls[1]!))).toEqual(['nachweis']);
    expect(JSON.parse(h.store.value as string).v).toBe(1);
    expect((await h.client.ping()).ok).toBe(true);
  });

  it('the old way is tried again only on `unreadable` and only for the old ways: a refused proof, an e2 or a founder ticket are not retried', async () => {
    const old = await r2Harness({}, serverForR2());
    const expired = await mintProof('alpha', old.server.now(), -5);
    expect(fail(await old.client.enrol({ proof: expired })).kind).toBe('proof-expired');
    expect(old.calls).toHaveLength(1);
    // a founder ticket is refused at once as `unreadable` by a relay of version 1: no second request
    const f = await r2Harness({}, serverFor({ revision: 1 }));
    const ticket = await mintFounder('alpha', '2', f.server.now());
    expect(fail(await f.client.enrol({ founder: ticket })).kind).toBe('unreadable');
    expect(f.calls).toHaveLength(1);
    // an e2 with no signer-free fallback either
    const e = await r2Harness({}, serverForR2());
    const inviter = await r2Harness({}, e.server);
    await enrolWithProof(inviter, 'buero');
    const inv = value(await inviter.client.invite());
    const used = await r2Harness({}, e.server);
    value(await used.client.enrol({ invitation: inv.invitation }));
    const again = await r2Harness({}, e.server);
    expect(fail(await again.client.enrol({ invitation: inv.invitation })).kind).toBe(
      'already-used',
    );
    expect(again.calls).toHaveLength(1);
  });

  it('an invitation e2, a founder ticket and a password: the body names exactly that and our key, and never a role (it comes from the relay)', async () => {
    const server = serverForR2();
    const founder = await mintFounder('multi', '2', server.now());
    const first = await r2Harness({}, server, undefined, MULTI);
    const v = value(await first.client.enrol({ founder }));
    expect(v).toMatchObject({ group: '2', role: 'buero' });
    expect(Object.keys(bodyOf(first.calls[0]!)).sort()).toEqual(['geraetSchluessel', 'gruender']);
    // the office device invites with the role of a member; the new device takes it
    const inv = value(await first.client.invite({ role: 'lb:art' }));
    expect(inv).toMatchObject({ group: '2', role: 'lb:art' });
    const joined = await r2Harness({}, server, undefined, MULTI);
    const j = value(await joined.client.enrol({ invitation: inv.invitation }));
    expect(j).toMatchObject({ group: '2', role: 'lb:art' });
    expect(Object.keys(bodyOf(joined.calls[0]!)).sort()).toEqual(['einladung', 'geraetSchluessel']);
    // a password makes the first device of another group
    const pw = await r2Harness({}, server, undefined, MULTI);
    const p = value(
      await pw.client
        .enrol({ password: 'correct horse', group: '2' })
        .then((r) => (r.ok ? r : pw.client.enrol({ password: 'repeat horse', group: '3' }))),
    );
    expect(p.role).toBe('buero');
    expect(Object.keys(bodyOf(pw.calls[0]!)).sort()).toEqual([
      'app',
      'geraetSchluessel',
      'mandant',
      'passwort',
    ]);
  });

  it('what the argument must look like is checked before anything is sent: a founder ticket and a password need a signer, a role needs the old ways', async () => {
    const server = serverForR2();
    const h = await r2Harness({}, server);
    const ticket = await mintFounder('alpha', '2', server.now());
    const noSigner = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      fetch: h.server.fetch,
      store: memoryStore(),
      clock: server.now,
    });
    for (const how of [{ founder: ticket }, { password: 'x', group: '2' }]) {
      expect(fail(await noSigner.enrol(how)).kind, JSON.stringify(how)).toBe('bad-argument');
    }
    for (const how of [
      { founder: 'g1.x' },
      { founder: await mintFounder('beta', '2', server.now()) }, // another app
      { password: '', group: '2' },
      { password: 'x'.repeat(201), group: '2' },
      { password: 'a\nb', group: '2' },
      { password: 'x', group: 'standard' },
      { password: 'x', group: 'Nord' },
      { invitation: 'e2.alpha.1.x' },
      { proof: 'n1.x.y' },
      { proof: await mintProof('alpha', server.now()), role: 'Buero' },
      { proof: await mintProof('alpha', server.now()), role: 'lb:' },
    ] as never[]) {
      expect(fail(await h.client.enrol(how)).kind, JSON.stringify(how)).toBe('bad-argument');
    }
    expect(h.calls).toHaveLength(0);
    // a role with an e2 is not a thing the argument can say
    const inviter = await r2Harness({}, server);
    await enrolWithProof(inviter, 'buero');
    const inv = value(await inviter.client.invite());
    expect(
      fail(await h.client.enrol({ invitation: inv.invitation, role: 'buero' } as never)).kind,
    ).toBe('bad-argument');
  });

  it('where only the new procedure holds the proof of the old way is closed (426): told as `client-update-needed`, nothing is stored', async () => {
    const h = await r2Harness({}, serverForR2(), undefined, STRICT);
    const r = fail(await h.client.enrol({ proof: await mintProof('strict', h.server.now()) }));
    expect(r).toMatchObject({
      kind: 'client-update-needed',
      token: 'neue-fassung-noetig',
      status: 426,
      class: 'fatal',
    });
    expect(h.store.value).toBeUndefined();
    expect(h.calls).toHaveLength(1); // 426 is not `unreadable`: no second request without the key
  });

  it('a developer password has its own refusals, told apart', async () => {
    const server = serverForR2();
    const a = await r2Harness({}, server, undefined, MULTI);
    value(await a.client.enrol({ password: 'correct horse', group: '2' }));
    const b = await r2Harness({}, server, undefined, MULTI);
    expect(fail(await b.client.enrol({ password: 'correct horse', group: '2' })).kind).toBe(
      'developer-group-taken',
    );
    expect(fail(await b.client.enrol({ password: 'wrong', group: '2' })).kind).toBe(
      'developer-invalid',
    );
    expect(fail(await b.client.enrol({ password: 'old horse', group: '4' })).kind).toBe(
      'developer-expired',
    );
    const old = await mintFounder('multi', '5', server.now(), -5);
    expect(fail(await b.client.enrol({ founder: old })).kind).toBe('developer-expired');
    const bad = await mintFounder('multi', '5', server.now(), 600, 'other');
    expect(fail(await b.client.enrol({ founder: bad })).kind).toBe('developer-invalid');
  });

  it('a blocked mark ends only by `forget()`: then enrolling works and the key stays the same', async () => {
    const h = await r2Harness();
    const first = await enrolWithProof(h);
    h.store.value = JSON.stringify({ v: 2, blocked: first.device, day: '2026-11-22' });
    expect(await h.client.state()).toBe('blocked');
    const calls = h.calls.length;
    const r = fail(await h.client.enrol({ proof: await mintProof('alpha', h.server.now()) }));
    expect(r.kind).toBe('blocked-mark');
    expect(h.calls).toHaveLength(calls); // nothing was sent
    expect((await h.client.forget()).ok).toBe(true);
    const again = value(await h.client.enrol({ proof: await mintProof('alpha', h.server.now()) }));
    expect(again.device).not.toBe(first.device);
    expect(readCertificate(JSON.parse(h.store.value as string).access)?.key).toBe(
      h.signer.publicKey,
    );
  });
});

describe('requests with a certificate carry the proof of possession; with an old access nothing more than before', () => {
  it('headers: Bearer, `<t>.<signature>` for exactly this path and body, the revision; the signature checks against our key (node:crypto)', async () => {
    const h = await r2Harness();
    await enrolWithProof(h);
    value(await h.client.collect());
    const call = lastCall(h);
    const cert = JSON.parse(h.store.value as string).access as string;
    expect(headerOf(call, 'Authorization')).toBe(`Bearer ${cert}`);
    expect(headerOf(call, 'x-relay-protocol')).toBe('2');
    const [t, sig] = (headerOf(call, 'x-relay-signature') as string).split('.');
    expect(Number(t)).toBe(Math.floor(h.server.now() / 1000));
    const text = `v1\nPOST\n/v1/abholen\n${t}\n${createHash('sha256')
      .update(call.init.body as string)
      .digest('base64url')}\n${cert}`;
    const raw = Buffer.from(h.signer.publicKey, 'base64url');
    const key = createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: raw.subarray(1, 33).toString('base64url'),
        y: raw.subarray(33).toString('base64url'),
      },
      format: 'jwk',
    });
    expect(
      verify(
        'sha256',
        Buffer.from(text),
        { key, dsaEncoding: 'ieee-p1363' },
        Buffer.from(sig as string, 'base64url'),
      ),
    ).toBe(true);
  });

  it('two requests in the same second are two signatures (the relay takes each once)', async () => {
    const h = await r2Harness(
      { clock: () => 1_800_000_000_000 },
      serverForR2({ now: () => 1_800_000_000_000 }),
    );
    await enrolWithProof(h);
    value(await h.client.collect());
    value(await h.client.collect());
    const [a, b] = h.calls.slice(-2).map((c) => headerOf(c, 'x-relay-signature'));
    expect(a).not.toBe(b);
    expect(a?.split('.')[0]).toBe(b?.split('.')[0]);
  });

  it('an old access: only Authorization (an older relay refuses unknown headers at the preflight), unless the revision is announced', async () => {
    const h = await r2Harness({ signer: undefined as never });
    const noSigner = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: (u, i) => {
        h.calls.push({ url: u, init: i });
        return h.server.fetch(u, i);
      },
      store: h.store,
      clock: h.server.now,
    });
    value(await noSigner.enrol({ proof: await mintProof('alpha', h.server.now()) }));
    value(await noSigner.ping());
    const keys = Object.keys(lastCall(h).init.headers as object).sort();
    expect(keys).toEqual(['Authorization', 'Content-Type', 'Origin']);
  });

  it("the key is not the signer's any more: no request is made, the device is lost (and no new key is made)", async () => {
    const h = await r2Harness();
    await enrolWithProof(h);
    const other = await newSigner();
    const lost = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: (u, i) => {
        h.calls.push({ url: u, init: i });
        return h.server.fetch(u, i);
      },
      store: h.store,
      clock: h.server.now,
      signer: other.signer,
    });
    const calls = h.calls.length;
    const r = fail(await lost.ping());
    expect(r).toMatchObject({ kind: 'key-missing', class: 'reenrol' });
    expect(h.calls).toHaveLength(calls);
    // a signer that fails does the same
    const broken = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: h.server.fetch,
      store: h.store,
      clock: h.server.now,
      signer: {
        publicKey: h.signer.publicKey,
        sign: () => {
          throw new Error('vanished');
        },
      },
    });
    expect(fail(await broken.ping()).kind).toBe('key-missing');
  });

  it('a key that is missing makes the re-enrolment hook run, once', async () => {
    const server = serverForR2();
    const h = await r2Harness({}, server);
    await enrolWithProof(h);
    const other = await newSigner();
    const reenrol = vi.fn(async () => ({ proof: await mintProof('alpha', server.now()) }));
    const lost = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: server.fetch,
      store: h.store,
      clock: server.now,
      signer: other.signer,
      reenrol,
    });
    expect((await lost.ping()).ok).toBe(true);
    expect(reenrol).toHaveBeenCalledTimes(1);
    expect(readCertificate(JSON.parse(h.store.value as string).access)?.key).toBe(
      other.signer.publicKey,
    );
  });

  it('the revision of the relay is asked with the same proof (a signed ping), or from the health answer without credentials', async () => {
    const h = await r2Harness();
    const noCreds = value(await h.client.negotiate());
    expect(noCreds.revision).toBe(2);
    expect(noCreds.procedures?.preferred).toBe('zertifikat');
    expect(lastCall(h).url).toMatch(/\/gesund$/);
    await enrolWithProof(h);
    const withCert = value(await h.client.negotiate());
    expect(withCert.revision).toBe(2);
    expect(withCert.abilities).toContain('sperren');
    expect(lastCall(h).url).toMatch(/\/v1\/ping$/);
    expect(headerOf(lastCall(h), 'x-relay-signature')).toMatch(/^\d+\.[A-Za-z0-9_-]{86}$/);
  });

  it('an old access announces the revision; a relay of version 1 says nothing and is revision 1', async () => {
    const h = await r2Harness({}, serverFor({ revision: 1 }));
    await enrolWithProof(h);
    expect(h.store.value).toContain('"v":1');
    const r = value(await h.client.negotiate());
    expect(r).toEqual({ revision: 1, abilities: [] });
    expect(headerOf(lastCall(h), 'x-relay-protocol')).toBe('2');
    const health = value(
      await (await r2Harness({}, serverFor({ revision: 1 }))).client.negotiate(),
    );
    expect(health).toEqual({ revision: 1, abilities: [] });
  });

  it('a relay that refuses the unknown header already at the preflight (a network failure here): once more without it', async () => {
    const server = serverFor({ revision: 1 });
    const h = await r2Harness({}, server, (inner) => (url, init) => {
      const names = Object.keys((init.headers ?? {}) as object).map((n) => n.toLowerCase());
      if (names.includes('x-relay-protocol'))
        return Promise.reject(new TypeError('Failed to fetch'));
      return inner(url, init);
    });
    await enrolWithProof(h);
    const r = value(await h.client.negotiate());
    expect(r.revision).toBe(1);
    // a certificate does not take that way out: its headers are part of the proof
    const server2 = serverForR2();
    const c = await r2Harness({}, server2, (inner) => (url, init) => {
      const names = Object.keys((init.headers ?? {}) as object).map((n) => n.toLowerCase());
      return names.includes('x-relay-protocol') && String(url).endsWith('/ping')
        ? Promise.reject(new TypeError('Failed to fetch'))
        : inner(url, init);
    });
    await enrolWithProof(c);
    expect(fail(await c.client.negotiate()).kind).toBe('network');
  });

  it('a drop and a collect work with certificates', async () => {
    const server = serverForR2();
    const a = await r2Harness({}, server);
    const b = await r2Harness({}, server);
    const va = await enrolWithProof(a);
    const vb = await enrolWithProof(b);
    const dropped = value(
      await a.client.drop([{ device: vb.device, content: Uint8Array.of(1, 2, 3) }]),
    );
    expect(dropped.byDevice[vb.device]).toMatchObject({ ok: true });
    const got = value(await b.client.collect());
    expect(got.messages.map((m) => [m.from, [...m.content]])).toEqual([[va.device, [1, 2, 3]]]);
  });
});

describe('refusals: blocked, "new version needed", the clock and the proof are not "expired"', () => {
  it('a signed request with a clock that is off by more than two minutes is `possession-time`, passed on as it is', async () => {
    const server = serverForR2();
    const h = await r2Harness({}, server);
    await enrolWithProof(h);
    const skewed = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: server.fetch,
      store: h.store,
      clock: () => server.now() + 600_000,
      signer: h.signer,
    });
    const r = fail(await skewed.ping());
    expect(r).toMatchObject({
      kind: 'possession-time',
      token: 'besitz-zeit',
      status: 401,
      class: 'fatal',
    });
    expect(await skewed.state()).toBe('ready'); // nothing is dropped
  });

  it('426 `neue-fassung-noetig` to a request: nothing is dropped, the device is not blocked, the hook is not called', async () => {
    const onBlocked = vi.fn();
    const h = await r2Harness({ onBlocked }, serverForR2(), () =>
      errorFetch(426, 'neue-fassung-noetig'),
    );
    // a stored old access, as an earlier enrolment would have left it
    const plain = await r2Harness({}, serverFor({ revision: 1 }));
    await enrolWithProof(plain);
    h.store.value = plain.store.value;
    const r = fail(await h.client.ping());
    expect(r.kind).toBe('client-update-needed');
    expect(await h.client.state()).toBe('ready');
    expect(onBlocked).not.toHaveBeenCalled();
  });
});

describe('renewal and the step from the old access to a certificate', () => {
  it('a certificate is renewed from day 30, not before; the new one replaces it with the same key, group and role', async () => {
    const server = serverForR2();
    const h = await r2Harness({}, server);
    await enrolWithProof(h, 'lb:art');
    const before = JSON.parse(h.store.value as string);
    server.control.advanceTime(29 * DAY_MS); // 31 days left
    expect(value(await h.client.renewIfDue())).toMatchObject({ renewed: false });
    server.control.advanceTime(2 * DAY_MS); // 29 days left
    const r = value(await h.client.renewIfDue());
    expect(r.renewed).toBe(true);
    const after = JSON.parse(h.store.value as string);
    expect(after.access).not.toBe(before.access);
    const c = readCertificate(after.access)!;
    expect(c).toMatchObject({ group: '1', role: 'lb:art', key: h.signer.publicKey });
    expect(c.endS).toBeGreaterThan(readCertificate(before.access)!.endS);
    expect((await h.client.ping()).ok).toBe(true);
  });

  it('an old access asks for a certificate with our key and role (`upgrade`); afterwards every request is signed', async () => {
    const server = serverForR2();
    const store = await oldAccessStore(server);
    const h = await r2Harness({ store }, server);
    expect(await h.client.state()).toBe('ready');
    const v = value(await h.client.upgrade({ role: 'lb:art' }));
    expect(v).toMatchObject({ group: '1', role: 'lb:art' });
    expect(bodyOf(lastCall(h))).toEqual({ geraetSchluessel: h.signer.publicKey, rolle: 'lb:art' });
    expect(JSON.parse(store.value as string).v).toBe(2);
    const ping = value(await h.client.ping());
    expect(ping).toMatchObject({ group: '1', role: 'lb:art' });
    expect(headerOf(lastCall(h), 'x-relay-signature')).toBeDefined();
    // a certificate cannot be upgraded again
    expect(fail(await h.client.upgrade()).kind).toBe('bad-argument');
  });

  it('without a role (or with the role `ohne`) the key goes alone', async () => {
    const server = serverForR2();
    for (const role of [undefined, 'ohne']) {
      const store = await oldAccessStore(server);
      const h = await r2Harness({ store }, server);
      value(await h.client.upgrade(role === undefined ? {} : { role }));
      expect(bodyOf(lastCall(h))).toEqual({ geraetSchluessel: h.signer.publicKey });
      expect(value(await h.client.ping())).toMatchObject({ group: '1', role: 'ohne' });
    }
  });

  it('against a relay of version 1 (`unreadable`): the access stays and still works', async () => {
    const server = serverFor({ revision: 1 });
    const h = await r2Harness({}, server);
    await enrolWithProof(h);
    const text = h.store.value;
    const r = fail(await h.client.upgrade({ role: 'buero' }));
    expect(r.kind).toBe('unreadable');
    expect(h.store.value).toBe(text);
    expect((await h.client.ping()).ok).toBe(true);
  });

  it('a failure of the net is not an answer: nothing is stored, and an invalid role is refused before a request', async () => {
    const server = serverForR2();
    const store = await oldAccessStore(server);
    const text = store.value;
    const h = await r2Harness(
      { store, maxAttempts: 1 },
      server,
      () => () => Promise.reject(new Error('offline')),
    );
    expect(fail(await h.client.upgrade()).kind).toBe('network');
    expect(store.value).toBe(text);
    expect(fail(await h.client.upgrade({ role: 'Buero' })).kind).toBe('bad-argument');
  });

  it('a refusal other than `unreadable` is passed on (blocked, strict, …)', async () => {
    const server = serverForR2();
    const store = await oldAccessStore(server);
    const h = await r2Harness({ store }, server, () => errorFetch(403, 'rolle-nicht-erlaubt'));
    expect(fail(await h.client.upgrade()).kind).toBe('role-not-allowed');
  });

  it('an old access that is due is renewed as before', async () => {
    const server = serverFor({ revision: 1 });
    const h = await r2Harness({}, server);
    await enrolWithProof(h);
    server.control.advanceTime(65 * DAY_MS);
    expect(value(await h.client.renewIfDue()).renewed).toBe(true);
    expect(JSON.parse(h.store.value as string).v).toBe(1);
  });
});

describe('invitations, the device list and blocking: only with a certificate', () => {
  it('an invitation e2: the group, the inviting device and the role the inviter chose; a role of another form is refused before a request', async () => {
    const h = await r2Harness();
    const v = await enrolWithProof(h, 'buero');
    const inv = value(await h.client.invite({ role: 'lb:art' }));
    expect(inv).toMatchObject({ group: '1', inviter: v.device, role: 'lb:art', validForS: 600 });
    expect(inv.invitation.startsWith('e2.alpha.1.')).toBe(true);
    expect(bodyOf(lastCall(h))).toEqual({ rolle: 'lb:art' });
    const calls = h.calls.length;
    expect(fail(await h.client.invite({ role: 'admin' })).kind).toBe('bad-argument');
    expect(h.calls).toHaveLength(calls);
    // the relay's own refusal of a role passes on
    const member = await r2Harness({}, h.server);
    await enrolWithProof(member, 'lb:art');
    expect(fail(await member.client.invite({ role: 'buero' })).kind).toBe('role-not-allowed');
    expect(value(await member.client.invite()).role).toBe('lb:art');
  });

  it("an answer that is not for this device's group, or that gives an e1 to a certificate, is refused as malformed", async () => {
    const server = serverForR2();
    const good = await r2Harness({}, server);
    await enrolWithProof(good, 'buero');
    const e2 = value(await good.client.invite()).invitation;
    const swapped =
      (text: string): FetchLike =>
      () =>
        Promise.resolve(
          new Response(JSON.stringify({ einladung: text, gueltigS: 600 }), {
            status: 201,
            headers: { 'Content-Type': 'application/json' },
          }),
        );
    const h = await r2Harness({ store: good.store, signer: good.signer }, server, () =>
      swapped(e2.replace('e2.alpha.1.', 'e2.alpha.2.')),
    );
    expect(fail(await h.client.invite()).kind).toBe('malformed');
    const h2 = await r2Harness({ store: good.store, signer: good.signer }, server, () =>
      swapped(`e1.alpha.1802476800.${'A'.repeat(22)}.${'A'.repeat(43)}`),
    );
    expect(fail(await h2.client.invite()).kind).toBe('malformed');
    const other = await r2Harness({ store: good.store, signer: good.signer }, server, () =>
      swapped(e2.replace(/^e2\.alpha\.1\.geraet-[0-9a-f]{32}/, `e2.alpha.1.${DEV}`)),
    );
    expect(fail(await other.client.invite()).kind).toBe('malformed');
  });

  it('an old access gets an e1 as in version 1; a role is refused by the relay', async () => {
    const server = serverForR2();
    const plain = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: server.fetch,
      store: memoryStore(),
      clock: server.now,
    });
    value(await plain.enrol({ proof: await mintProof('alpha', server.now()) }));
    const inv = value(await plain.invite());
    expect(inv.invitation.startsWith('e1.')).toBe(true);
    expect(inv.group).toBeUndefined();
    expect(fail(await plain.invite({ role: 'buero' })).kind).toBe('unreadable');
  });

  it("the device list: the office sees its group, a member's device its role; the old access gets `role-not-allowed`", async () => {
    const server = serverForR2();
    const office = await r2Harness({}, server);
    const member = await r2Harness({}, server);
    const o = await enrolWithProof(office, 'buero');
    const m = await enrolWithProof(member, 'lb:art');
    value(await member.client.ping());
    const all = value(await office.client.devices());
    expect(all.max).toBe(50);
    expect(all.devices.map((d) => d.device).sort()).toEqual([o.device, m.device].sort());
    const mine = all.devices.find((d) => d.device === m.device);
    expect(mine).toMatchObject({
      role: 'lb:art',
      procedure: 'new',
      protocol: 2,
      introducedBy: { by: 'proof' },
    });
    expect(value(await member.client.devices()).devices.map((d) => d.device)).toEqual([m.device]);
    const plain = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: server.fetch,
      store: memoryStore(),
      clock: server.now,
    });
    value(await plain.enrol({ proof: await mintProof('alpha', server.now()) }));
    expect(fail(await plain.devices()).kind).toBe('role-not-allowed');
    // a tampered answer is no answer
    const tampered = await r2Harness(
      { store: office.store, signer: office.signer },
      server,
      () => () =>
        Promise.resolve(
          new Response(JSON.stringify({ geraete: [{ geraet: 'x' }], hoechstens: 50 }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
    );
    expect(fail(await tampered.client.devices()).kind).toBe('malformed');
  });

  it('the devices of one group are not those of another', async () => {
    const server = serverForR2();
    const a = await r2Harness({}, server, undefined, MULTI);
    const b = await r2Harness({}, server, undefined, MULTI);
    value(await a.client.enrol({ founder: await mintFounder('multi', '2', server.now()) }));
    value(await b.client.enrol({ founder: await mintFounder('multi', '3', server.now()) }));
    value(await b.client.ping());
    expect(value(await a.client.devices()).devices).toHaveLength(1);
  });

  it('blocking sends the id and the device is refused afterwards; a malformed id is refused before a request; the refusal of the relay is handed back as it is', async () => {
    const server = serverForR2();
    const office = await r2Harness({}, server);
    const target = await r2Harness({}, server);
    const member = await r2Harness({}, server);
    await enrolWithProof(office, 'buero');
    const t = await enrolWithProof(target, 'lb:art');
    await enrolWithProof(member, 'lb:other');
    expect(value(await office.client.block(t.device))).toEqual({ device: t.device });
    expect(bodyOf(lastCall(office))).toEqual({ geraet: t.device });
    expect(fail(await target.client.ping()).kind).toBe('device-blocked');
    const calls = office.calls.length;
    expect(fail(await office.client.block('geraet-xyz')).kind).toBe('bad-argument');
    expect(office.calls).toHaveLength(calls);
    // a member's device may not block an office device
    const o = (await office.client.deviceId()) as string;
    expect(fail(await member.client.block(o)).kind).toBe('role-not-allowed');
  });

  it("the list of blocks is bounded and the limit per hour is the relay's: both are refusals the caller decides about", async () => {
    const server = serverForR2();
    const office = await r2Harness({}, server);
    await enrolWithProof(office, 'buero');
    const ids = Array.from({ length: 3 }, (_, i) => `geraet-${String(i + 1).padStart(32, '0')}`);
    server.control.setLimits({ blocklistPerGroup: 2 });
    value(await office.client.block(ids[0] as string));
    value(await office.client.block(ids[1] as string));
    const full = fail(await office.client.block(ids[2] as string));
    expect(full).toMatchObject({ kind: 'blocklist-full', class: 'refused', status: 503 });
  });
});

describe('a block tells the device: the hook runs once, for the real 403 `gesperrt` of its own credential only', () => {
  /** Enrols against the reference server first, then puts `wrap` on the network. */
  const certificateHarness = async (
    over: Partial<RelayClientOptions> = {},
    wrap?: (i: FetchLike) => FetchLike,
  ) => {
    let active: FetchLike | undefined;
    const h = await r2Harness(
      over,
      serverForR2(),
      (inner) => (url, init) => (active ?? inner)(url, init),
    );
    const v = await enrolWithProof(h);
    if (wrap) active = wrap(h.server.fetch);
    return { h, v };
  };

  it('403 `gesperrt` to a request: the mark replaces the credentials, the hook runs once with the device and the day, the device does not enrol itself back', async () => {
    const onBlocked = vi.fn();
    const { h, v } = await certificateHarness({ onBlocked }, () => errorFetch(403, 'gesperrt'));
    const r = fail(await h.client.ping());
    expect(r).toMatchObject({ kind: 'device-blocked', token: 'gesperrt', status: 403 });
    expect(onBlocked).toHaveBeenCalledTimes(1);
    expect(onBlocked).toHaveBeenCalledWith({
      device: v.device,
      day: new Date(h.server.now()).toISOString().slice(0, 10),
    });
    expect(await h.client.state()).toBe('blocked');
    expect(JSON.parse(h.store.value as string)).toEqual({
      v: 2,
      blocked: v.device,
      day: new Date(h.server.now()).toISOString().slice(0, 10),
    });
    // later: no request at all, no second call of the hook
    const calls = h.calls.length;
    expect(fail(await h.client.collect()).kind).toBe('blocked-mark');
    expect(
      fail(await h.client.enrol({ proof: await mintProof('alpha', h.server.now()) })).kind,
    ).toBe('blocked-mark');
    expect(h.calls).toHaveLength(calls);
    expect(onBlocked).toHaveBeenCalledTimes(1);
  });

  it('a device on an old access: the same', async () => {
    const onBlocked = vi.fn();
    const server = serverFor({ revision: 1 });
    const h = await r2Harness({ onBlocked }, server, () => errorFetch(403, 'gesperrt'));
    const real = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: server.fetch,
      store: h.store,
      clock: server.now,
    });
    const v = value(await real.enrol({ proof: await mintProof('alpha', server.now()) }));
    expect(fail(await h.client.collect()).kind).toBe('device-blocked');
    expect(onBlocked).toHaveBeenCalledWith(expect.objectContaining({ device: v.device }));
  });

  it('a real block by the office: the target learns it from its next request, once', async () => {
    const server = serverForR2();
    const onBlocked = vi.fn();
    const office = await r2Harness({}, server);
    const target = await r2Harness({ onBlocked }, server);
    await enrolWithProof(office, 'buero');
    const t = await enrolWithProof(target, 'lb:art');
    value(await office.client.block(t.device));
    expect(fail(await target.client.collect()).kind).toBe('device-blocked');
    expect(fail(await target.client.collect()).kind).toBe('blocked-mark');
    expect(onBlocked).toHaveBeenCalledTimes(1);
    expect(await target.client.state()).toBe('blocked');
  });

  it('several requests finding out at once, and later ones: still once', async () => {
    const onBlocked = vi.fn();
    const { h } = await certificateHarness({ onBlocked }, () => errorFetch(403, 'gesperrt'));
    const kinds = (
      await Promise.all([
        h.client.ping(),
        h.client.collect(),
        h.client.devices(),
        h.client.invite(),
      ])
    ).map((r) => fail(r as RelayResult<unknown>).kind);
    for (const k of kinds) expect(['device-blocked', 'blocked-mark']).toContain(k);
    await h.client.ping();
    expect(onBlocked).toHaveBeenCalledTimes(1);
  });

  it('a block the device is marked with already does not tell again, and sends nothing', async () => {
    const onBlocked = vi.fn();
    const { h, v } = await certificateHarness({ onBlocked });
    h.store.value = JSON.stringify({ v: 2, blocked: v.device, day: '2026-11-22' });
    const calls = h.calls.length;
    expect(fail(await h.client.ping()).kind).toBe('blocked-mark');
    expect(h.calls).toHaveLength(calls);
    expect(onBlocked).not.toHaveBeenCalled();
  });

  it('blocking itself tells too (the relay confirmed it); blocking another device tells nothing here', async () => {
    const onBlocked = vi.fn();
    const server = serverForR2();
    const h = await r2Harness({ onBlocked }, server);
    const other = await r2Harness({}, server);
    const me = await enrolWithProof(h, 'buero');
    const o = await enrolWithProof(other);
    value(await h.client.block(o.device));
    expect(onBlocked).not.toHaveBeenCalled();
    expect(await h.client.state()).toBe('ready');
    value(await h.client.block(me.device));
    expect(onBlocked).toHaveBeenCalledTimes(1);
    expect(onBlocked).toHaveBeenCalledWith(expect.objectContaining({ device: me.device }));
    expect(await h.client.state()).toBe('blocked');
  });

  const nothing: [string, (inner: FetchLike) => FetchLike][] = [
    ['a failure of the net', () => () => Promise.reject(new TypeError('Failed to fetch'))],
    [
      "a gateway's 403 without a protocol body",
      () => () => Promise.resolve(new Response('<html>no</html>', { status: 403 })),
    ],
    ['403 `herkunft`', () => errorFetch(403, 'herkunft')],
    ['403 `rolle-nicht-erlaubt`', () => errorFetch(403, 'rolle-nicht-erlaubt')],
    ['403 `app-unbekannt`', () => errorFetch(403, 'app-unbekannt')],
    ['401 `zugang-abgelaufen`', () => errorFetch(401, 'zugang-abgelaufen')],
    ['401 `besitz-ungueltig`', () => errorFetch(401, 'besitz-ungueltig')],
    ['426 `neue-fassung-noetig`', () => errorFetch(426, 'neue-fassung-noetig')],
    ['429', () => errorFetch(429, 'zu-viele-anfragen')],
    ['500', () => errorFetch(500, 'intern')],
    ['the word `gesperrt` with another status', () => errorFetch(401, 'gesperrt')],
    [
      'the word `gesperrt` as a refusal of one recipient of a drop',
      () => () =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              ergebnisse: [
                { geraet: 'geraet-' + 'a'.repeat(32), ok: false, art: 'gesperrt', fehler: 'x' },
              ],
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        ),
    ],
  ];
  for (const [name, wrap] of nothing) {
    it(`${name}: nothing is marked, the credentials stay`, async () => {
      const onBlocked = vi.fn();
      const { h } = await certificateHarness({ onBlocked, maxAttempts: 1 }, wrap);
      const before = h.store.value;
      await h.client.ping();
      await h.client.drop([{ device: 'geraet-' + 'a'.repeat(32), content: Uint8Array.of(1) }]);
      expect(onBlocked).not.toHaveBeenCalled();
      expect(h.store.value).toBe(before);
      expect(await h.client.state()).not.toBe('blocked');
    });
  }

  it('a `gesperrt` that answers an enrolment (no credential was sent) is no block of this device', async () => {
    const onBlocked = vi.fn();
    const server = serverForR2();
    const h = await r2Harness({ onBlocked }, server, () => errorFetch(403, 'gesperrt'));
    expect(fail(await h.client.enrol({ proof: await mintProof('alpha', server.now()) })).kind).toBe(
      'device-blocked',
    );
    expect(onBlocked).not.toHaveBeenCalled();
    expect(h.store.value).toBeUndefined();
  });

  it('a refusal of an access that is not the stored one (an earlier enrolment, refused late) marks nothing', async () => {
    const onBlocked = vi.fn();
    const server = serverForR2();
    const first = await r2Harness({}, server);
    await enrolWithProof(first);
    let swapped = false;
    const h = await r2Harness(
      { onBlocked, store: first.store, signer: first.signer },
      server,
      () => async (url, init) => {
        if (!swapped) {
          swapped = true;
          // while the request is on its way another enrolment replaces the stored credentials
          const other = await r2Harness({ store: memoryStore() }, server);
          await enrolWithProof(other);
          first.store.value = other.store.value;
        }
        return errorFetch(403, 'gesperrt')(url, init);
      },
    );
    expect(fail(await h.client.ping()).kind).toBe('device-blocked');
    expect(onBlocked).not.toHaveBeenCalled();
    expect(first.store.value).toContain('"v":2');
    expect(first.store.value).not.toContain('blocked');
  });

  it('a hook that fails does not break the client: the mark is stored, the result is the refusal', async () => {
    for (const onBlocked of [
      vi.fn(() => {
        throw new Error('x');
      }),
      vi.fn(() => Promise.reject(new Error('y'))),
    ]) {
      const { h, v } = await certificateHarness({ onBlocked }, () => errorFetch(403, 'gesperrt'));
      expect(fail(await h.client.ping()).kind).toBe('device-blocked');
      expect(JSON.parse(h.store.value as string).blocked).toBe(v.device);
      expect(onBlocked).toHaveBeenCalledTimes(1);
    }
  });

  it('a store that cannot write the mark: the hook still runs once and the refusal is the result', async () => {
    const onBlocked = vi.fn();
    const store = memoryStore();
    const { h } = await certificateHarness({ onBlocked, store }, () => errorFetch(403, 'gesperrt'));
    store.set = () => {
      throw new Error('quota');
    };
    expect(fail(await h.client.ping()).kind).toBe('device-blocked');
    expect(fail(await h.client.ping()).kind).toBe('device-blocked');
    expect(onBlocked).toHaveBeenCalledTimes(1);
  });

  it('without a hook the mark is stored all the same', async () => {
    const { h } = await certificateHarness({}, () => errorFetch(403, 'gesperrt'));
    await h.client.ping();
    expect(await h.client.state()).toBe('blocked');
  });
});
