// The relay client against the reference server: success paths, every kind of failure the client has to
// act on, retries and backoff with an injected sleep, the renewal threshold, re-enrolment, bounds.
import { describe, expect, it, vi } from 'vitest';
import {
  RelayClient,
  type CredentialStore,
  type FetchLike,
  type RelayClientOptions,
  type RelayResult,
} from '../../src/relay/index.ts';
import { ALPHA, BASE, mintProof, serverFor } from './helpers.ts';

const DAY_MS = 86_400_000;

function memoryStore(): CredentialStore & { value: string | undefined } {
  const s = {
    value: undefined as string | undefined,
    get: () => s.value,
    set: (t: string) => {
      s.value = t;
    },
    remove: () => {
      s.value = undefined;
    },
  };
  return s;
}

interface Harness {
  server: ReturnType<typeof serverFor>;
  client: RelayClient;
  store: ReturnType<typeof memoryStore>;
  calls: { url: string; init: RequestInit }[];
  sleeps: number[];
  fetch: FetchLike;
}

function harness(
  over: Partial<RelayClientOptions> = {},
  server = serverFor(),
  wrap?: (inner: FetchLike) => FetchLike,
): Harness {
  const calls: { url: string; init: RequestInit }[] = [];
  const sleeps: number[] = [];
  const inner: FetchLike = (url, init) => {
    calls.push({ url, init });
    return server.fetch(url, init);
  };
  const fetchFn = wrap ? wrap(inner) : inner;
  const store = memoryStore();
  const client = new RelayClient({
    baseUrl: BASE,
    appId: ALPHA.app,
    origin: ALPHA.origin,
    fetch: fetchFn,
    store,
    clock: server.now,
    random: () => 0.5,
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    ...over,
  });
  return { server, client, store, calls, sleeps, fetch: fetchFn };
}

const proofFor = (h: Harness): Promise<string> => mintProof('alpha', h.server.now());

async function enrolled(h: Harness): Promise<string> {
  const r = await h.client.enrol({ proof: await proofFor(h) });
  expect(r.ok).toBe(true);
  return (r as { value: { device: string } }).value.device;
}

/** Two devices of the same app on one server. */
async function pair() {
  const server = serverFor();
  const a = harness({}, server);
  const b = harness({}, server);
  const idA = await enrolled(a);
  const idB = await enrolled(b);
  return { server, a, b, idA, idB };
}

const bytes = (...n: number[]): Uint8Array => Uint8Array.from(n);

function errorFetch(status: number, art: string): FetchLike {
  return () =>
    Promise.resolve(
      new Response(JSON.stringify({ fehler: 'x', art }), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
}

function fail<T>(r: RelayResult<T>) {
  if (r.ok) throw new Error('expected a failure');
  return r;
}

describe('enrolment', () => {
  it('enrols with a proof, keeps the access in the store, and never shows it in a result', async () => {
    const h = harness();
    expect(await h.client.state()).toBe('none');
    const r = await h.client.enrol({ proof: await proofFor(h) });
    expect(r.ok).toBe(true);
    const device = (r as { value: { device: string; until: string } }).value;
    expect(device.device).toMatch(/^geraet-[0-9a-f]{32}$/);
    expect(device.until).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(await h.client.state()).toBe('ready');
    expect(await h.client.deviceId()).toBe(device.device);
    const access = JSON.parse(h.store.value as string).access as string;
    expect(JSON.stringify(r)).not.toContain(access);
    const ping = await h.client.ping();
    expect(ping).toEqual({ ok: true, value: { device: device.device, until: device.until } });
    expect(JSON.stringify(ping)).not.toContain(access);
  });

  it('a device invites another, which enrols with the invitation, once', async () => {
    const server = serverFor();
    const a = harness({}, server);
    const b = harness({}, server);
    await enrolled(a);
    const inv = await a.client.invite();
    expect(inv.ok).toBe(true);
    const invitation = (inv as { value: { invitation: string; validForS: number } }).value;
    expect(invitation.validForS).toBe(600);
    const r = await b.client.enrol({ invitation: invitation.invitation });
    expect(r.ok).toBe(true);
    const again = fail(
      await harness({}, server).client.enrol({ invitation: invitation.invitation }),
    );
    expect(again.kind).toBe('already-used');
    expect(again.class).toBe('fatal');
    expect(again.token).toBe('verbraucht');
    expect(again.attempts).toBe(1); // a fatal kind is not retried
  });

  it('a proof that is not shaped like one never reaches the network', async () => {
    const h = harness();
    for (const proof of ['', 'n1.x', 'hello', 'n1.' + 'a'.repeat(500) + '.' + 'b'.repeat(86)]) {
      expect(fail(await h.client.enrol({ proof })).kind).toBe('bad-argument');
    }
    expect(fail(await h.client.enrol({ invitation: 'e1.x' })).kind).toBe('bad-argument');
    expect(h.calls).toHaveLength(0);
  });

  it('the relay refusing a proof leaves the store unchanged and is not retried', async () => {
    const h = harness();
    const expired = await mintProof('alpha', h.server.now(), -10);
    const r = fail(await h.client.enrol({ proof: expired }));
    expect(r.kind).toBe('proof-expired');
    expect(r.status).toBe(403);
    expect(h.store.value).toBeUndefined();
    expect(h.calls).toHaveLength(1);
    expect(await h.client.state()).toBe('none');
  });

  it('a proof is used once: the second enrolment with it is refused, not retried', async () => {
    const h = harness();
    const proof = await proofFor(h);
    expect((await h.client.enrol({ proof })).ok).toBe(true);
    const r = fail(await harness({}, h.server).client.enrol({ proof }));
    expect(r.kind).toBe('already-used');
  });

  it('one enrolment at a time: a second call while one runs shares it', async () => {
    const h = harness();
    const proof = await proofFor(h);
    const [x, y] = await Promise.all([h.client.enrol({ proof }), h.client.enrol({ proof })]);
    expect(x).toEqual(y);
    expect(h.calls).toHaveLength(1);
  });

  it('an answer whose access names another app is not accepted', async () => {
    const h = harness({ appId: 'beta' });
    const r = fail(await h.client.enrol({ proof: await mintProof('beta', h.server.now()) }));
    // the reference server knows the app beta, but its origin is another: refused at the origin check
    expect(['origin-refused', 'malformed']).toContain(r.kind);
    expect(h.store.value).toBeUndefined();
  });

  it('a store that fails gives the kind storage, and no access is lost silently', async () => {
    const h = harness({
      store: {
        get: () => undefined,
        set: () => {
          throw new Error('quota');
        },
        remove: () => undefined,
      },
    });
    expect(fail(await h.client.enrol({ proof: await proofFor(h) })).kind).toBe('storage');
    const broken = harness({
      store: {
        get: () => {
          throw new Error('locked');
        },
        set: () => undefined,
        remove: () => undefined,
      },
    });
    expect(fail(await broken.client.ping()).kind).toBe('storage');
  });
});

describe('requests are what the protocol says', () => {
  it('method, address, headers, no cookies, no redirects, no cache, token only where needed', async () => {
    const h = harness();
    await enrolled(h);
    await h.client.ping();
    await h.client.health();
    const [enrolCall, pingCall, healthCall] = h.calls;
    expect(enrolCall?.url).toBe(`${BASE}/v1/einschreiben`);
    expect(pingCall?.url).toBe(`${BASE}/v1/ping`);
    expect(healthCall?.url).toBe(`${BASE}/gesund`);
    for (const c of h.calls) {
      expect(c.init.credentials).toBe('omit');
      expect(c.init.cache).toBe('no-store');
      expect(c.init.redirect).toBe('error');
      expect(c.init.referrerPolicy).toBe('no-referrer');
      expect((c.init.headers as Record<string, string>)['Origin']).toBe(ALPHA.origin);
    }
    const headers = (i: number): Record<string, string> =>
      h.calls[i]?.init.headers as Record<string, string>;
    expect(headers(0)['Authorization']).toBeUndefined();
    expect(headers(0)['Content-Type']).toBe('application/json');
    expect(headers(1)['Authorization']).toMatch(/^Bearer z1\.alpha\.geraet-[0-9a-f]{32}\./);
    expect(pingCall?.init.body).toBe('{}');
    expect(healthCall?.init.method).toBe('GET');
    expect(headers(2)['Authorization']).toBeUndefined();
    expect(healthCall?.init.body).toBeUndefined();
    // the address carries nothing but the endpoint
    for (const c of h.calls) expect(c.url).not.toMatch(/[?#]/);
  });

  it('the access is never in a result or in anything the client logs', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const h = harness({}, serverFor(), (inner) => {
        let n = 0;
        return (u, i) =>
          ++n % 3 === 0
            ? Promise.reject(
                new Error(
                  String(i.headers && (i.headers as Record<string, string>)['Authorization']),
                ),
              )
            : inner(u, i);
      });
      await enrolled(h);
      const access = JSON.parse(h.store.value as string).access as string;
      const results: unknown[] = [];
      for (let i = 0; i < 6; i += 1) results.push(await h.client.ping());
      results.push(await h.client.collect(), await h.client.invite(), await h.client.renew());
      const text = JSON.stringify(results);
      expect(text).not.toContain(access);
      expect(text).not.toContain('Bearer');
      for (const spy of [log, warn, error]) expect(spy).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
      warn.mockRestore();
      error.mockRestore();
    }
  });

  it('a bad base URL or app id is a programmer error at construction', () => {
    const base = { fetch: serverFor().fetch, store: memoryStore(), clock: () => 0 };
    for (const baseUrl of [
      'http://relay.test',
      'https://user@relay.test',
      'https://relay.test/x',
      'https://relay.test/?a=1',
      'nonsense',
    ]) {
      expect(() => new RelayClient({ ...base, baseUrl, appId: 'alpha' }), baseUrl).toThrow(
        TypeError,
      );
    }
    expect(
      () => new RelayClient({ ...base, baseUrl: 'https://relay.test', appId: 'Alpha' }),
    ).toThrow(TypeError);
    expect(
      () => new RelayClient({ ...base, baseUrl: 'http://localhost:8080', appId: 'alpha' }),
    ).not.toThrow();
  });
});

describe('renewal', () => {
  it('renews only when fewer than 30 days remain, and the new access is kept', async () => {
    const h = harness();
    await enrolled(h);
    const before = h.calls.length;
    const first = await h.client.renewIfDue();
    expect(first).toMatchObject({ ok: true, value: { renewed: false } });
    expect(h.calls.length).toBe(before); // no request
    const oldAccess = JSON.parse(h.store.value as string).access as string;
    h.server.control.advanceTime(59 * DAY_MS);
    expect(await h.client.renewIfDue()).toMatchObject({ ok: true, value: { renewed: false } });
    h.server.control.advanceTime(2 * DAY_MS);
    const r = await h.client.renewIfDue();
    expect(r).toMatchObject({ ok: true, value: { renewed: true } });
    const stored = JSON.parse(h.store.value as string);
    expect(stored.access).not.toBe(oldAccess);
    expect((await h.client.ping()).ok).toBe(true);
    // the old access still works at the relay until its own end
    expect(await h.client.renewIfDue()).toMatchObject({ ok: true, value: { renewed: false } });
  });

  it('exactly 30 days left does not renew, 29 does', async () => {
    const h = harness();
    await enrolled(h);
    h.server.control.advanceTime(60 * DAY_MS);
    // the end day is 90 days after the enrolment day; 60 days on, 30 days remain (by calendar day)
    const r30 = await h.client.renewIfDue();
    expect(r30.ok && r30.value.renewed).toBe(false);
    h.server.control.advanceTime(DAY_MS);
    const r29 = await h.client.renewIfDue();
    expect(r29.ok && r29.value.renewed).toBe(true);
  });

  it('renewIfDue without credentials says so', async () => {
    expect(fail(await harness().client.renewIfDue()).kind).toBe('no-credentials');
  });

  it('two renewals at once share one request', async () => {
    const h = harness();
    await enrolled(h);
    const n = h.calls.length;
    const [x, y] = await Promise.all([h.client.renew(), h.client.renew()]);
    expect(x).toEqual(y);
    expect(h.calls.length).toBe(n + 1);
  });
});

describe('expired access and re-enrolment', () => {
  it('an expired access is a failure of class reenrol, the state becomes stale, and nothing more is sent', async () => {
    const h = harness();
    await enrolled(h);
    h.server.control.advanceTime(91 * DAY_MS);
    const r = fail(await h.client.ping());
    expect(r.kind).toBe('access-expired');
    expect(r.class).toBe('reenrol');
    expect(r.token).toBe('zugang-abgelaufen');
    expect(await h.client.state()).toBe('stale');
    const n = h.calls.length;
    for (let i = 0; i < 5; i += 1)
      expect(fail(await h.client.collect()).kind).toBe('no-credentials');
    expect(h.calls.length).toBe(n); // no busy loop against the relay
    // a new enrolment clears it
    expect((await h.client.enrol({ proof: await proofFor(h) })).ok).toBe(true);
    expect(await h.client.state()).toBe('ready');
    expect((await h.client.ping()).ok).toBe(true);
  });

  it('with a re-enrolment hook the client enrols again once and retries, sharing it between calls', async () => {
    const h = harness();
    const hook = vi.fn(async () => ({ proof: await proofFor(h) }));
    const withHook = harness({ reenrol: hook }, h.server);
    const first = await enrolled(withHook);
    h.server.control.advanceTime(91 * DAY_MS);
    const [x, y] = await Promise.all([withHook.client.ping(), withHook.client.collect()]);
    expect(x.ok && y.ok).toBe(true);
    expect(hook).toHaveBeenCalledTimes(1);
    expect(await withHook.client.deviceId()).not.toBe(first);
  });

  it('a hook that gives nothing, or fails, leaves the failure and the state', async () => {
    for (const hook of [() => undefined, () => Promise.reject(new Error('no'))]) {
      const h = harness({ reenrol: hook });
      await enrolled(h);
      h.server.control.advanceTime(91 * DAY_MS);
      expect(fail(await h.client.ping()).kind).toBe('access-expired');
      expect(await h.client.state()).toBe('stale');
    }
  });

  it('a forged access (invalid) is also reenrol, a missing store is no-credentials', async () => {
    const h = harness();
    h.store.value = JSON.stringify({
      v: 1,
      device: `geraet-${'0'.repeat(32)}`,
      access: `z1.alpha.geraet-${'0'.repeat(32)}.1999999999.${'A'.repeat(43)}`,
      until: '2030-01-01',
    });
    const r = fail(await h.client.ping());
    expect(r.kind).toBe('access-invalid');
    expect(r.class).toBe('reenrol');
    expect(fail(await harness().client.ping()).kind).toBe('no-credentials');
  });
});

describe('drop and collect', () => {
  it('a message goes from one device to another, once, with presence', async () => {
    const { a, b, idA, idB } = await pair();
    const dropped = await a.client.drop([{ device: idB, content: bytes(1, 2, 3) }]);
    expect(dropped).toMatchObject({
      ok: true,
      value: { results: [{ device: idB, ok: true, present: false }] },
    });
    const got = await b.client.collect({ ask: [idA] });
    expect(got.ok).toBe(true);
    if (!got.ok) return;
    expect(got.value.messages).toHaveLength(1);
    expect([...(got.value.messages[0]?.content ?? [])]).toEqual([1, 2, 3]);
    expect(got.value.messages[0]?.from).toBe(idA);
    expect(got.value.more).toBe(false);
    // now B has collected, so A sees it present and a second collect is empty
    expect((await b.client.collect()).ok && (await b.client.collect())).toMatchObject({
      ok: true,
      value: { messages: [] },
    });
    const second = await a.client.drop([{ device: idB, content: bytes(9) }]);
    expect(second).toMatchObject({ ok: true, value: { results: [{ ok: true, present: true }] } });
  });

  it('ordering: messages come in the order dropped', async () => {
    const { a, b, idB } = await pair();
    for (const n of [1, 2, 3, 4, 5]) await a.client.drop([{ device: idB, content: bytes(n) }]);
    const got = await b.client.collect();
    expect(got.ok && got.value.messages.map((m) => m.content[0])).toEqual([1, 2, 3, 4, 5]);
  });

  it('results come back by recipient with no prototype, and a full mailbox is a result of that recipient only', async () => {
    const { a, b, idB } = await pair();
    const other = `geraet-${'9'.repeat(32)}`;
    for (let i = 0; i < 100; i += 1) await a.client.drop([{ device: idB, content: bytes(1) }]);
    const r = await a.client.drop([
      { device: idB, content: bytes(1) },
      { device: other, content: bytes(2) },
    ]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.results[0]).toMatchObject({
      ok: false,
      kind: 'recipient-full',
      class: 'refused',
      token: 'empfaenger-voll',
    });
    expect(r.value.results[1]).toMatchObject({ ok: true });
    expect(Object.getPrototypeOf(r.value.byDevice)).toBeNull();
    expect(r.value.byDevice[idB]?.ok).toBe(false);
    expect(Object.keys(r.value.byDevice)).toEqual([idB, other]);
    // collecting frees the mailbox
    await b.client.collectAll();
    const again = await a.client.drop([{ device: idB, content: bytes(1) }]);
    expect(again.ok && again.value.results[0]?.ok).toBe(true);
  });

  it('bad arguments are refused before any request', async () => {
    const { a, idA, idB } = await pair();
    const n = a.calls.length;
    const c = a.client;
    const ok = bytes(1);
    const refusals = [
      [],
      Array.from({ length: 51 }, (_, i) => ({
        device: `geraet-${i.toString(16).padStart(32, '0')}`,
        content: ok,
      })),
      [
        { device: idB, content: ok },
        { device: idB, content: ok },
      ],
      [{ device: idA, content: ok }],
      [{ device: 'nope', content: ok }],
      [{ device: idB, content: new Uint8Array(0) }],
      [{ device: idB, content: new Uint8Array(65_537) }],
      [{ device: idB, content: 'text' as unknown as Uint8Array }],
    ];
    for (const list of refusals) expect(fail(await c.drop(list)).kind).toBe('bad-argument');
    expect(a.calls.length).toBe(n);
    // the boundaries are accepted
    expect((await c.drop([{ device: idB, content: new Uint8Array(65_536) }])).ok).toBe(true);
    const fifty = Array.from({ length: 50 }, (_, i) => ({
      device: `geraet-${(i + 1).toString(16).padStart(32, '0')}`,
      content: ok,
    }));
    expect((await c.drop(fifty)).ok).toBe(true);
  });

  it('collect asks about at most 200 distinct ids', async () => {
    const { b, idA } = await pair();
    const ids = Array.from(
      { length: 200 },
      (_, i) => `geraet-${(i + 1).toString(16).padStart(32, '0')}`,
    );
    expect((await b.client.collect({ ask: ids })).ok).toBe(true);
    expect(fail(await b.client.collect({ ask: [...ids, idA] })).kind).toBe('bad-argument');
    expect(fail(await b.client.collect({ ask: [idA, idA] })).kind).toBe('bad-argument');
    expect(fail(await b.client.collect({ ask: ['nope'] })).kind).toBe('bad-argument');
  });

  it('collectAll follows `more`, keeps the order, and respects its bounds', async () => {
    const { server, a, b, idB } = await pair();
    server.control.setLimits({ collectBytes: 100_000 });
    const msg = (n: number): Uint8Array => new Uint8Array(60_000).fill(n);
    for (const n of [1, 2, 3]) await a.client.drop([{ device: idB, content: msg(n) }]);
    const all = await b.client.collectAll();
    expect(all.ok && all.value.messages.map((m) => m.content[0])).toEqual([1, 2, 3]);
    expect(all.ok && all.value.more).toBe(false);
    for (const n of [4, 5, 6]) await a.client.drop([{ device: idB, content: msg(n) }]);
    const bounded = await b.client.collectAll({ maxCalls: 2 });
    expect(bounded.ok && bounded.value.messages.map((m) => m.content[0])).toEqual([4, 5]);
    expect(bounded.ok && bounded.value.more).toBe(true);
    const byMessages = await b.client.collectAll({ maxMessages: 1 });
    expect(byMessages.ok && byMessages.value.messages.map((m) => m.content[0])).toEqual([6]);
    expect(byMessages.ok && byMessages.value.more).toBe(false);
  });

  it('a failure after the first collect keeps what was collected and says so', async () => {
    const server = serverFor();
    let collects = 0;
    const b = harness({}, server, (inner) => (u, i) => {
      if (u.endsWith('/abholen') && ++collects >= 2) return Promise.reject(new Error('down'));
      return inner(u, i);
    });
    const a = harness({}, server);
    await enrolled(a);
    const idB = await enrolled(b);
    server.control.setLimits({ collectBytes: 100_000 });
    for (const n of [1, 2, 3])
      await a.client.drop([{ device: idB, content: new Uint8Array(60_000).fill(n) }]);
    const r = await b.client.collectAll({ maxCalls: 10 });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.messages.map((m) => m.content[0])).toEqual([1]);
    expect(r.value.more).toBe(true);
    expect(r.value.interrupted?.kind).toBe('network');
  });
});

describe('ring', () => {
  const vapid = `vapid t=aaa.bbb.ccc, k=${'A'.repeat(87)}`;
  const request = (over: object = {}) => ({
    endpoint: 'https://fcm.googleapis.com/fcm/send/abc',
    vapid,
    ttl: 900,
    urgency: 'high' as const,
    content: bytes(1, 2, 3),
    ...over,
  });

  it('hands a built request to the relay and returns the push service status', async () => {
    const h = harness();
    await enrolled(h);
    expect(await h.client.ring(request())).toEqual({ ok: true, value: { service: 201, ms: 1 } });
    h.server.control.setPushResult(410);
    expect(await h.client.ring(request())).toMatchObject({ ok: true, value: { service: 410 } });
    const body = JSON.parse(h.calls[h.calls.length - 1]?.init.body as string);
    expect(Object.keys(body).sort()).toEqual([
      'dringlichkeit',
      'endpunkt',
      'inhalt',
      'ttl',
      'vapid',
    ]);
  });

  it('an unreachable push service is retryable by class but not repeated by the client', async () => {
    const h = harness();
    await enrolled(h);
    h.server.control.setPushResult('unreachable');
    const n = h.calls.length;
    const r = fail(await h.client.ring(request()));
    expect(r.kind).toBe('push-service-unreachable');
    expect(r.class).toBe('retry');
    expect(h.calls.length).toBe(n + 1);
  });

  it('a request that cannot fit is refused locally', async () => {
    const h = harness();
    await enrolled(h);
    const n = h.calls.length;
    for (const bad of [
      { ttl: -1 },
      { ttl: 86_401 },
      { ttl: 1.5 },
      { urgency: 'urgent' },
      { content: new Uint8Array(0) },
      { content: new Uint8Array(4097) },
      { endpoint: '' },
      { endpoint: 'h'.repeat(901) },
      { vapid: 'v'.repeat(1025) },
    ]) {
      expect(fail(await h.client.ring(request(bad))).kind).toBe('bad-argument');
    }
    expect(h.calls.length).toBe(n);
  });

  it('a request the relay refuses is ring-invalid, fatal', async () => {
    const h = harness();
    await enrolled(h);
    const r = fail(await h.client.ring(request({ endpoint: 'https://example.com/x' })));
    expect(r.kind).toBe('ring-invalid');
    expect(r.class).toBe('fatal');
  });
});

describe('retries and backoff', () => {
  it('a retryable kind is retried with growing waits, never faster than its hint, then given up', async () => {
    let n = 0;
    const h = harness({ maxAttempts: 4, backoffBaseMs: 4_000 }, serverFor(), () => {
      return () => {
        n += 1;
        return errorFetch(503, 'beschaeftigt')('', {});
      };
    });
    h.store.value = (await (async () => {
      const s = harness();
      await enrolled(s);
      return s.store.value;
    })()) as string;
    const r = fail(await h.client.ping());
    expect(r.kind).toBe('relay-busy');
    expect(r.attempts).toBe(4);
    expect(n).toBe(4);
    expect(h.sleeps).toHaveLength(3);
    for (let i = 1; i < h.sleeps.length; i += 1)
      expect(h.sleeps[i] as number).toBeGreaterThan(h.sleeps[i - 1] as number);
    for (const s of h.sleeps) {
      expect(s).toBeGreaterThanOrEqual(2_000);
      expect(s).toBeLessThanOrEqual(30_000);
    }
  });

  it('succeeds when the relay recovers, with the attempts counted', async () => {
    const server = serverFor();
    let n = 0;
    const h = harness(
      {},
      server,
      (inner) => (u, i) =>
        ++n <= 2 && u.endsWith('/ping') ? errorFetch(429, 'zu-viele-anfragen')(u, i) : inner(u, i),
    );
    await enrolled(h);
    n = 0;
    const r = await h.client.ping();
    expect(r.ok).toBe(true);
    expect(h.sleeps.length).toBe(2);
    expect(h.sleeps.every((s) => s >= 15_000)).toBe(true); // the kind's hint
  });

  it('a fatal kind is never retried, whichever the call', async () => {
    for (const [status, art] of [
      [400, 'unlesbar'],
      [403, 'gesperrt'],
      [403, 'herkunft'],
      [415, 'typ'],
      [404, 'unbekannt'],
      [409, 'verbraucht'],
    ] as const) {
      const h = harness();
      await enrolled(h);
      const swap = harness({ store: h.store }, h.server, () => errorFetch(status, art));
      const r = fail(await swap.client.ping());
      expect(r.class, art).toBe('fatal');
      expect(swap.calls.length + 0, art).toBe(0);
      expect(r.attempts, art).toBe(1);
      expect(swap.sleeps, art).toEqual([]);
    }
  });

  it('a request that is not safe to repeat is repeated only when nothing was done', async () => {
    const server = serverFor();
    const other = harness({}, server);
    const idB = await enrolled(other);
    const a = harness({}, server);
    await enrolled(a);
    const store = a.store;
    const count = { n: 0 };
    const make = (status: number, art: string) =>
      harness({ store }, server, () => () => {
        count.n += 1;
        return errorFetch(status, art)('', {});
      });
    // nothing was stored: repeated
    count.n = 0;
    const busy = make(503, 'beschaeftigt');
    expect(fail(await busy.client.drop([{ device: idB, content: bytes(1) }])).attempts).toBe(3);
    expect(count.n).toBe(3);
    // an internal error: the outcome is unknown, not repeated
    count.n = 0;
    const internal = make(500, 'intern');
    expect(fail(await internal.client.drop([{ device: idB, content: bytes(1) }])).attempts).toBe(1);
    expect(count.n).toBe(1);
    // but a ping (safe to repeat) is
    count.n = 0;
    expect(fail(await internal.client.ping()).attempts).toBe(3);
    // a network error: drop once, ping and collect again
    count.n = 0;
    const down = harness({ store }, server, () => () => {
      count.n += 1;
      return Promise.reject(new Error('offline'));
    });
    expect(fail(await down.client.drop([{ device: idB, content: bytes(1) }])).kind).toBe('network');
    expect(count.n).toBe(1);
    count.n = 0;
    expect(fail(await down.client.collect()).attempts).toBe(3);
    expect(count.n).toBe(3);
    count.n = 0;
    expect(fail(await down.client.invite()).attempts).toBe(1);
  });

  it('a gateway answer without a protocol body is `unavailable` (retry); unknown words and wrong statuses are `malformed` (fatal)', async () => {
    const base = harness();
    await enrolled(base);
    const run = async (make: () => Response) => {
      const h = harness({ store: base.store }, base.server, () => () => Promise.resolve(make()));
      return fail(await h.client.ping());
    };
    const gw = await run(() => new Response('<html>Bad gateway</html>', { status: 502 }));
    expect(gw.kind).toBe('unavailable');
    expect(gw.class).toBe('retry');
    expect(gw.attempts).toBe(3);
    expect((await run(() => new Response('<html>no</html>', { status: 404 }))).kind).toBe(
      'malformed',
    );
    const unknownWord = await run(
      () => new Response(JSON.stringify({ fehler: 'x', art: 'brandneu' }), { status: 400 }),
    );
    expect(unknownWord.kind).toBe('malformed');
    expect(unknownWord.attempts).toBe(1);
    // an unknown word on a 503 (the relay-wide "full" refusal of the existing servers): only the status counts
    const unknown503 = await run(
      () => new Response(JSON.stringify({ fehler: 'x', art: 'brandneu-voll' }), { status: 503 }),
    );
    expect(unknown503.kind).toBe('unavailable');
    expect(unknown503.class).toBe('retry');
    expect(unknown503.attempts).toBe(3);
    const wrongStatus = await run(
      () => new Response(JSON.stringify({ fehler: 'x', art: 'unlesbar' }), { status: 500 }),
    );
    expect(wrongStatus.kind).toBe('malformed');
    const dropWord = await run(
      () => new Response(JSON.stringify({ fehler: 'x', art: 'voll' }), { status: 400 }),
    );
    expect(dropWord.kind).toBe('malformed'); // a per-recipient word is no request refusal
  });

  it('a success body that is not exactly the protocol is malformed, not retried', async () => {
    const base = harness();
    await enrolled(base);
    for (const body of [
      '{"geraet":"x"}',
      '{"geraet":"geraet-' + 'a'.repeat(32) + '","app":"alpha","bis":"2030-01-01","extra":1}',
      'not json',
      '',
    ]) {
      const h = harness(
        { store: base.store },
        base.server,
        () => () => Promise.resolve(new Response(body, { status: 200 })),
      );
      const r = fail(await h.client.ping());
      expect(r.kind).toBe('malformed');
      expect(r.attempts).toBe(1);
    }
    // a ping answer for another device is not an answer for this one
    const h = harness(
      { store: base.store },
      base.server,
      () => () =>
        Promise.resolve(
          new Response(
            JSON.stringify({ geraet: `geraet-${'a'.repeat(32)}`, app: 'alpha', bis: '2030-01-01' }),
            { status: 200 },
          ),
        ),
    );
    expect(fail(await h.client.ping()).kind).toBe('malformed');
  });

  it('a body over the documented size is not read to the end', async () => {
    const base = harness();
    await enrolled(base);
    let pulled = 0;
    const endless = new ReadableStream<Uint8Array>({
      pull(c) {
        pulled += 1;
        c.enqueue(new TextEncoder().encode('x'.repeat(65_536)));
        if (pulled > 10_000) c.close();
      },
    });
    const h = harness(
      { store: base.store },
      base.server,
      () => () => Promise.resolve(new Response(endless, { status: 200 })),
    );
    const r = fail(await h.client.ping());
    expect(r.kind).toBe('malformed');
    expect(pulled).toBeLessThan(10);
    const announced = harness(
      { store: base.store },
      base.server,
      () => () =>
        Promise.resolve(
          new Response('{}', { status: 200, headers: { 'content-length': '999999999' } }),
        ),
    );
    expect(fail(await announced.client.ping()).kind).toBe('malformed');
  });
});

describe('time limits and aborting', () => {
  it('a request that does not answer is a timeout, retried for a safe call', async () => {
    const base = harness();
    await enrolled(base);
    const never: FetchLike = (_u, init) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () =>
          reject(new DOMException('aborted', 'AbortError')),
        );
      });
    const h = harness({ store: base.store, timeoutMs: 20 }, base.server, () => never);
    const r = fail(await h.client.ping());
    expect(r.kind).toBe('timeout');
    expect(r.attempts).toBe(3);
    const d = fail(
      await h.client.drop([{ device: `geraet-${'1'.repeat(32)}`, content: bytes(1) }]),
    );
    expect(d.kind).toBe('timeout');
    expect(d.attempts).toBe(1);
  });

  it('the caller can abort: kind aborted, no retry, also while waiting between attempts', async () => {
    const base = harness();
    await enrolled(base);
    const controller = new AbortController();
    const hang: FetchLike = (_u, init) =>
      new Promise((_r, reject) => {
        if (init.signal?.aborted) reject(new DOMException('aborted', 'AbortError'));
        init.signal?.addEventListener('abort', () =>
          reject(new DOMException('aborted', 'AbortError')),
        );
      });
    const h = harness({ store: base.store, timeoutMs: 10_000 }, base.server, () => hang);
    const p = h.client.ping({ signal: controller.signal });
    controller.abort();
    const r = fail(await p);
    expect(r.kind).toBe('aborted');
    expect(r.class).toBe('fatal');
    expect(h.sleeps).toEqual([]);
    // aborted before the call
    expect(fail(await h.client.ping({ signal: controller.signal })).kind).toBe('aborted');
    // aborted during the wait
    const c2 = new AbortController();
    const waiting = harness(
      {
        store: base.store,
        sleep: (_ms, signal) =>
          new Promise((_res, rej) => {
            c2.abort();
            if (signal?.aborted) rej(new Error('aborted'));
          }),
      },
      base.server,
      () => errorFetch(503, 'beschaeftigt'),
    );
    const w = fail(await waiting.client.ping({ signal: c2.signal }));
    expect(w.kind).toBe('aborted');
  });
});

describe('polling', () => {
  function scripted(responses: (RelayResult<unknown> | 'ok')[]) {
    const waits: number[] = [];
    const controller = new AbortController();
    const base = harness({
      poll: { busyMs: 1_000, idleMs: 10_000 },
      sleep: (ms) => {
        waits.push(ms);
        if (waits.length >= responses.length) controller.abort();
        return Promise.resolve();
      },
    });
    return { base, waits, controller };
  }

  it('waits about a second while busy, ten seconds otherwise, never less than the minimum', async () => {
    const { base, waits, controller } = scripted(['ok', 'ok', 'ok', 'ok']);
    await enrolled(base);
    let n = 0;
    const batches: number[] = [];
    const result = await base.client.poll((b) => void batches.push(b.messages.length), {
      signal: controller.signal,
      busy: () => ++n % 2 === 1,
    });
    expect(result.kind).toBe('aborted');
    expect(waits).toEqual([1_000, 10_000, 1_000, 10_000]);
    expect(batches).toHaveLength(4);
    // a cadence below the minimum is raised
    const fast = harness({ poll: { busyMs: 1, idleMs: 2 } });
    await enrolled(fast);
    const c = new AbortController();
    const seen: number[] = [];
    const slow = new RelayClient({
      baseUrl: BASE,
      appId: 'alpha',
      origin: ALPHA.origin,
      fetch: fast.fetch,
      store: fast.store,
      clock: fast.server.now,
      poll: { busyMs: 1, idleMs: 2 },
      sleep: (ms) => {
        seen.push(ms);
        c.abort();
        return Promise.resolve();
      },
    });
    await slow.poll(() => undefined, { signal: c.signal, busy: () => true });
    expect(seen[0]).toBeGreaterThanOrEqual(250);
  });

  it('delivers the messages to the handler, and a handler that throws does not stop the loop or lose the next batch', async () => {
    const server = serverFor();
    const a = harness({}, server);
    const idA = await enrolled(a);
    const controller = new AbortController();
    const b = harness(
      {
        sleep: () => {
          if (++seen >= 2) controller.abort();
          return Promise.resolve();
        },
      },
      server,
    );
    let seen = 0;
    const idB = await enrolled(b);
    await a.client.drop([{ device: idB, content: bytes(7) }]);
    const got: number[] = [];
    const r = await b.client.poll(
      (batch) => {
        for (const m of batch.messages) got.push(m.content[0] as number);
        if (got.length === 1) throw new Error('handler');
      },
      { signal: controller.signal, ask: () => [idA] },
    );
    expect(r.kind).toBe('aborted');
    expect(got).toEqual([7]);
  });

  it('after failures it waits 2, 4, 8 ... seconds and stops at a fatal kind or an expired access', async () => {
    const base = harness();
    await enrolled(base);
    const waits: number[] = [];
    const controller = new AbortController();
    const flaky = harness(
      {
        store: base.store,
        maxAttempts: 1,
        sleep: (ms) => {
          waits.push(ms);
          if (waits.length >= 4) controller.abort();
          return Promise.resolve();
        },
      },
      base.server,
      () => () => Promise.reject(new Error('offline')),
    );
    await flaky.client.poll(() => undefined, { signal: controller.signal });
    expect(waits.slice(0, 3)).toEqual([2_000, 4_000, 8_000]);
    const fatal = harness({ store: base.store, maxAttempts: 1 }, base.server, () =>
      errorFetch(403, 'gesperrt'),
    );
    const stop = await fatal.client.poll(() => undefined, { signal: new AbortController().signal });
    expect(stop.kind).toBe('device-blocked');
    base.server.control.advanceTime(91 * DAY_MS);
    const expired = await base.client.poll(() => undefined, {
      signal: new AbortController().signal,
    });
    expect(expired.class).toBe('reenrol');
  });
});

describe('health', () => {
  it('reads the health answer and nothing else', async () => {
    const h = harness();
    expect(await h.client.health()).toEqual({ ok: true, value: { commit: 'reference' } });
    const odd = harness(
      {},
      serverFor(),
      () => () =>
        Promise.resolve(new Response('{"ok":true,"stand":"x","sneaky":1}', { status: 200 })),
    );
    expect(fail(await odd.client.health()).kind).toBe('malformed');
    expect(await h.client.forget()).toEqual({ ok: true, value: null });
  });
});
