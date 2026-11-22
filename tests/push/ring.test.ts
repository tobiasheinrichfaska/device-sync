// The ring request builder: the request has exactly the members RelayClient.ring takes, passes the relay's
// own checks (end to end against the reference server), refuses every bad input with a code before any
// cryptography runs, and holds up under a seeded sweep of broken subscriptions.
import { describe, expect, it, vi } from 'vitest';
import { RelayClient, type RingRequest } from '../../src/relay/index.ts';
import {
  PUSH_LIMITS,
  buildRingRequest,
  generateVapidKeys,
  checkVapid,
  decryptPushMessage,
  isRingEndpoint,
  isRingRequest,
  readSubscription,
  type RingParams,
} from '../../src/push/index.ts';
import { ALPHA, BASE, mintProof, serverFor } from '../relay/helpers.ts';
import { b64, mulberry32, pairFromScalar, seededBytes, seededScalar } from './reference.ts';

const ENDPOINT = 'https://fcm.googleapis.com/fcm/send/abc:def-123';
const NOW = 1_800_000_000;

async function setup() {
  const receiver = await pairFromScalar(seededScalar(mulberry32(1)));
  const auth = b64(seededBytes(mulberry32(2), 16));
  const vapid = await generateVapidKeys();
  const subscription = {
    endpoint: ENDPOINT,
    expirationTime: null,
    keys: { p256dh: receiver.point, auth },
  };
  const rand = mulberry32(3);
  const params: RingParams = {
    subscription,
    vapid: { ...vapid, subject: 'mailto:ops@example.org' },
    nowS: NOW,
    ttl: 900,
    urgency: 'high',
    random: (n) => new Uint8Array(seededBytes(rand, n)),
  };
  return { receiver, auth, vapid, subscription, params };
}

const refused = async (over: Partial<RingParams>, reason: string) => {
  const { params } = await setup();
  const r = await buildRingRequest({ ...params, ...over });
  expect(r, JSON.stringify(Object.keys(over))).toEqual({ ok: false, reason });
};

describe('buildRingRequest', () => {
  it('builds exactly the five members the client takes, and the relay and client accept it', async () => {
    const { params, vapid } = await setup();
    const r = await buildRingRequest(params);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(Object.keys(r.value).sort()).toEqual(['content', 'endpoint', 'ttl', 'urgency', 'vapid']);
    expect(r.value).toMatchObject({ endpoint: ENDPOINT, ttl: 900, urgency: 'high' });
    expect(isRingRequest(r.value)).toBe(true);
    const checked = await checkVapid({ header: r.value.vapid, endpoint: ENDPOINT, nowS: NOW });
    expect(checked).toEqual({
      ok: true,
      value: {
        publicKey: vapid.publicKey,
        expiresS: NOW + 43_200,
        subject: 'mailto:ops@example.org',
      },
    });
  });

  it('the push is content-free: it decrypts to nothing, and padding only makes it longer', async () => {
    const { params, receiver, auth } = await setup();
    for (const padding of [0, 1, 100, 3993]) {
      const r = await buildRingRequest({ ...params, padding });
      expect(r.ok).toBe(true);
      if (!r.ok) continue;
      expect(r.value.content.length).toBe(103 + padding);
      const o = await decryptPushMessage({
        body: r.value.content,
        receiverPrivate: receiver.pair.privateKey,
        receiverPublic: receiver.point,
        authSecret: auth,
      });
      expect(o.ok && o.value.plaintext.length).toBe(0);
      expect(o.ok && o.value.padding).toBe(padding);
    }
    expect(PUSH_LIMITS.ringContentMax - 103).toBe(3993);
    await refused({ padding: 3994 }, 'padding');
  });

  it('two rings differ (fresh salt and ephemeral key) and the salt comes from the random parameter', async () => {
    const { params } = await setup();
    const a = await buildRingRequest(params);
    const b = await buildRingRequest(params);
    expect(a.ok && b.ok && b64(a.value.content) !== b64(b.value.content)).toBe(true);
    const fixedSalt = new Uint8Array(16).fill(9);
    const c = await buildRingRequest({ ...params, random: () => fixedSalt });
    expect(c.ok && [...c.value.content.subarray(0, 16)]).toEqual([...fixedSalt]);
  });

  it('works end to end: the client hands it to the reference server, which accepts it', async () => {
    const { params } = await setup();
    const server = serverFor();
    const client = new RelayClient({
      baseUrl: BASE,
      appId: ALPHA.app,
      origin: ALPHA.origin,
      fetch: server.fetch,
      store: (() => {
        let v: string | undefined;
        return {
          get: () => v,
          set: (t: string) => void (v = t),
          remove: () => void (v = undefined),
        };
      })(),
      clock: server.now,
      random: () => 0.5,
      sleep: () => Promise.resolve(),
    });
    expect((await client.enrol({ proof: await mintProof('alpha', server.now()) })).ok).toBe(true);
    const r = await buildRingRequest(params);
    if (!r.ok) throw new Error(r.reason);
    const answer = await client.ring(r.value);
    expect(answer.ok).toBe(true);
  });

  it('bad parameters are codes', async () => {
    const { params, vapid } = await setup();
    await refused({ ttl: -1 }, 'ttl');
    await refused({ ttl: 86_401 }, 'ttl');
    await refused({ ttl: 1.5 }, 'ttl');
    await refused({ ttl: '5' as never }, 'ttl');
    await refused({ urgency: 'urgent' as never }, 'urgency');
    await refused({ padding: -1 }, 'padding');
    await refused({ padding: 0.5 }, 'padding');
    await refused({ nowS: -5 }, 'time');
    await refused({ lifetimeS: 86_401 }, 'lifetime');
    await refused({ random: 5 as never }, 'random');
    await refused({ random: () => new Uint8Array(15) }, 'random');
    await refused({ random: () => 'x' as never }, 'random');
    await refused({ vapid: { ...vapid, publicKey: 'x' } }, 'vapid');
    await refused({ vapid: { ...vapid, privateKey: {} as never } }, 'vapid');
    await refused({ vapid: null as never }, 'vapid');
    await refused({ vapid: { ...vapid, subject: 'nope' } }, 'subject');
    const other = await generateVapidKeys();
    await refused(
      { vapid: { privateKey: vapid.privateKey, publicKey: other.publicKey } },
      'key-mismatch',
    );
    // a throwing random never escapes
    await refused(
      {
        random: () => {
          throw new Error('x');
        },
      },
      'crypto',
    );
    void params;
  });

  it('bad parameters never reach WebCrypto (everything is checked first)', async () => {
    const { params } = await setup();
    const sign = vi.spyOn(crypto.subtle, 'sign');
    const derive = vi.spyOn(crypto.subtle, 'deriveBits');
    const generate = vi.spyOn(crypto.subtle, 'generateKey');
    try {
      for (const over of [
        { ttl: -1 },
        { urgency: 'x' as never },
        { padding: -1 },
        { subscription: 5 },
      ]) {
        expect((await buildRingRequest({ ...params, ...over })).ok).toBe(false);
      }
      expect(sign).not.toHaveBeenCalled();
      expect(derive).not.toHaveBeenCalled();
      expect(generate).not.toHaveBeenCalled();
    } finally {
      sign.mockRestore();
      derive.mockRestore();
      generate.mockRestore();
    }
  });

  it('the endpoint must be one the relay hands a ring to (every rule of the protocol document)', async () => {
    const { subscription } = await setup();
    const withEndpoint = (endpoint: unknown) => ({ ...subscription, endpoint });
    const accept = [
      'https://fcm.googleapis.com/fcm/send/x',
      'https://updates.push.services.mozilla.com/wpush/v2/x',
      'https://web.push.apple.com/x',
      'https://a.b.push.apple.com/x',
      'https://wns2-par02p.notify.windows.com/w/?token=x',
      'https://fcm.googleapis.com/',
    ];
    const reject = [
      'http://fcm.googleapis.com/x',
      'https://fcm.googleapis.com:443/x',
      'https://user:pw@fcm.googleapis.com/x',
      'https://user@fcm.googleapis.com/x',
      'https://fcm.googleapis.com',
      'https://fcm.googleapis.com.evil.example/x',
      'https://evilfcm.googleapis.com/x',
      'https://FCM.googleapis.com/x',
      'https://push.apple.com/x',
      'https://.push.apple.com/x',
      'https://a..push.apple.com/x',
      'https://evil.example/https://web.push.apple.com/',
      'https://notify.windows.com/x',
      'https://xnotify.windows.com/x',
      'https://web.push.apple.com/x y',
      'https://web.push.apple.com/ü',
      'https://updates.push.services.mozilla.com.evil.net/x',
      'https://example.org/x',
      `https://web.push.apple.com/${'a'.repeat(900)}`,
      '',
      5,
      null,
    ];
    for (const e of accept) {
      expect(isRingEndpoint(e), String(e)).toBe(true);
      expect(readSubscription(withEndpoint(e)).ok, String(e)).toBe(true);
    }
    for (const e of reject) {
      expect(isRingEndpoint(e), String(e)).toBe(false);
      expect(readSubscription(withEndpoint(e)), String(e)).toEqual({
        ok: false,
        reason: 'endpoint',
      });
    }
    const exact = `https://web.push.apple.com/${'a'.repeat(900 - 'https://web.push.apple.com/'.length)}`;
    expect(exact).toHaveLength(900);
    expect(isRingEndpoint(exact)).toBe(true);
  });

  it('isRingRequest mirrors the client and relay limits at their boundaries', async () => {
    const { params } = await setup();
    const built = await buildRingRequest(params);
    if (!built.ok) throw new Error('setup');
    const base = built.value;
    const mod = (o: Partial<Record<keyof RingRequest, unknown>>) => ({ ...base, ...o });
    expect(isRingRequest(mod({ ttl: 0 }))).toBe(true);
    expect(isRingRequest(mod({ ttl: 86_400 }))).toBe(true);
    expect(isRingRequest(mod({ ttl: 86_401 }))).toBe(false);
    expect(isRingRequest(mod({ ttl: -1 }))).toBe(false);
    expect(isRingRequest(mod({ content: new Uint8Array(4096) }))).toBe(true);
    expect(isRingRequest(mod({ content: new Uint8Array(4097) }))).toBe(false);
    expect(isRingRequest(mod({ content: new Uint8Array(0) }))).toBe(false);
    expect(isRingRequest(mod({ vapid: base.vapid + 'x'.repeat(1024) }))).toBe(false);
    expect(isRingRequest(mod({ vapid: 'vapid t=a.b.c, k=short' }))).toBe(false);
    expect(isRingRequest({ ...base, extra: 1 })).toBe(false);
    const { urgency: _u, ...missing } = base;
    void _u;
    expect(isRingRequest(missing)).toBe(false);
    expect(isRingRequest(null)).toBe(false);
    expect(isRingRequest([])).toBe(false);
  });
});

describe('readSubscription: strict', () => {
  const good = async () => (await setup()).subscription;

  it('reads the browser form and returns the three values', async () => {
    const s = await good();
    expect(readSubscription(s)).toEqual({
      ok: true,
      value: { endpoint: s.endpoint, p256dh: s.keys.p256dh, auth: s.keys.auth },
    });
    const { expirationTime: _e, ...noExp } = s;
    void _e;
    expect(readSubscription(noExp).ok).toBe(true);
    expect(readSubscription({ ...s, expirationTime: 123456 }).ok).toBe(true);
  });

  it('refuses unknown members, wrong shapes, bad spellings and lengths', async () => {
    const s = await good();
    const cases: [unknown, string][] = [
      [null, 'subscription'],
      [[], 'subscription'],
      ['x', 'subscription'],
      [{ ...s, extra: 1 }, 'subscription'],
      [{ ...s, expirationTime: 'soon' }, 'subscription'],
      [{ ...s, expirationTime: NaN }, 'subscription'],
      [{ ...s, keys: null }, 'subscription'],
      [{ ...s, keys: { p256dh: s.keys.p256dh } }, 'subscription'],
      [{ ...s, keys: { ...s.keys, extra: 1 } }, 'subscription'],
      [{ endpoint: s.endpoint }, 'subscription'],
      [{ ...s, keys: { ...s.keys, p256dh: s.keys.p256dh.slice(1) } }, 'receiver-key'],
      [{ ...s, keys: { ...s.keys, p256dh: 5 } }, 'receiver-key'],
      [{ ...s, keys: { ...s.keys, auth: b64(new Uint8Array(15)) } }, 'auth-secret'],
      [{ ...s, keys: { ...s.keys, auth: b64(new Uint8Array(17)) } }, 'auth-secret'],
      [{ ...s, keys: { ...s.keys, auth: s.keys.auth + '=' } }, 'auth-secret'],
      [{ ...s, keys: { ...s.keys, auth: s.keys.auth.replace(/.$/, '+') } }, 'auth-secret'],
      [{ ...s, keys: { ...s.keys, auth: 7 } }, 'auth-secret'],
    ];
    for (const [value, reason] of cases)
      expect(readSubscription(value), JSON.stringify(value)).toEqual({ ok: false, reason });
  });

  it('refuses __proto__, constructor and prototype keys at both levels', async () => {
    const s = await good();
    const text = JSON.stringify(s);
    for (const key of ['__proto__', 'constructor', 'prototype']) {
      const outer = JSON.parse(text.replace('{', `{"${key}":{},`)) as unknown;
      expect(readSubscription(outer)).toEqual({ ok: false, reason: 'subscription' });
      const inner = JSON.parse(text.replace('"keys":{', `"keys":{"${key}":{},`)) as unknown;
      expect(readSubscription(inner)).toEqual({ ok: false, reason: 'subscription' });
    }
  });

  it('refuses class instances, getters that throw and proxies without throwing', async () => {
    const s = await good();
    class Sub {
      endpoint = s.endpoint;
      keys = s.keys;
    }
    expect(readSubscription(new Sub())).toEqual({ ok: false, reason: 'subscription' });
    const bomb = {
      get endpoint(): string {
        throw new Error('boom');
      },
      keys: s.keys,
    };
    expect(readSubscription(bomb).ok).toBe(false);
    const p = new Proxy(
      {},
      {
        ownKeys: () => {
          throw new Error('boom');
        },
      },
    );
    expect(readSubscription(p).ok).toBe(false);
  });

  it('2000 seeded damages of a valid subscription never throw and never accept a damaged key', async () => {
    const { subscription: s, params } = await setup();
    const rand = mulberry32(99);
    const flat = JSON.stringify(s);
    const alphabet = 'AZaz09-_=+/ :"{},';
    for (let i = 0; i < 2000; i += 1) {
      const at = Math.floor(rand() * flat.length);
      const ch = alphabet[Math.floor(rand() * alphabet.length)] as string;
      const text = flat.slice(0, at) + ch + flat.slice(at + 1);
      let value: unknown;
      try {
        value = JSON.parse(text);
      } catch {
        continue;
      }
      const r = readSubscription(value);
      if (r.ok) {
        expect(isRingEndpoint(r.value.endpoint)).toBe(true);
        if (r.value.p256dh !== s.keys.p256dh) {
          // Shape only is checked here; a point off the curve is refused when the ring is built.
          const built = await buildRingRequest({ ...params, subscription: value });
          expect(built).toEqual({ ok: false, reason: 'receiver-key' });
        }
      }
    }
  });
});
