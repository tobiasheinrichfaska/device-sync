// Opt-in (`npm run test:relay-real`): the real RelayClient end to end against the REAL relay server over
// real HTTP: enrol, invite, drop, collectAll, ring (the push service is a stand-in), renew, error kinds,
// limits and the 30-second wait. The clock of the relay is moved through the harness.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { RelayClient, type CredentialStore, type RelayResult } from '../../src/relay/index.ts';
import { buildRingRequest, generateVapidKeys } from '../../src/push/index.ts';
import { mintProof } from '../relay/helpers.ts';
import { startReal, type RealServer } from './realserver.ts';

const ORIGIN = 'https://alpha.example';
const DAY = 86_400_000;

let real: RealServer;
let skew = 0; // how far the relay's clock is ahead of this machine's
beforeAll(async () => {
  real = await startReal();
});
afterAll(async () => real?.stop());
beforeEach(async () => {
  await real.control.reset();
  skew = 0;
});
const advance = async (ms: number): Promise<void> => {
  skew += ms;
  await real.control.advanceTime!(ms);
};
const now = (): number => Date.now() + skew;

function store(): CredentialStore & { value: string | undefined } {
  const s = {
    value: undefined as string | undefined,
    get: () => s.value,
    set: (t: string) => void (s.value = t),
    remove: () => void (s.value = undefined),
  };
  return s;
}

function device(over: { appId?: string; origin?: string; reenrol?: () => any } = {}) {
  const sleeps: number[] = [];
  const st = store();
  const client = new RelayClient({
    baseUrl: real.base,
    appId: over.appId ?? 'alpha',
    origin: over.origin ?? ORIGIN,
    fetch: (u, i) => fetch(u, i),
    store: st,
    clock: now,
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    random: () => 0,
    ...(over.reenrol ? { reenrol: over.reenrol } : {}),
  });
  return { client, st, sleeps };
}

async function enrolled(app = 'alpha') {
  const d = device({ appId: app, origin: `https://${app}.example` });
  const r = await d.client.enrol({ proof: await mintProof(app, now()) });
  if (!r.ok) throw new Error(`enrol failed: ${r.kind}`);
  return { ...d, id: r.value.device, until: r.value.until };
}

const failure = <T>(r: RelayResult<T>) => {
  if (r.ok) throw new Error('expected a failure');
  return r;
};
const bytes = (n: number, fill = 7): Uint8Array => new Uint8Array(n).fill(fill);

describe('real relay: enrolment, invitation, health', () => {
  it('health, enrol with a proof, ping, state', async () => {
    const d = device();
    expect(await d.client.state()).toBe('none');
    const h = await d.client.health();
    expect(h.ok).toBe(true);
    const r = await d.client.enrol({ proof: await mintProof('alpha', now()) });
    expect(r.ok).toBe(true);
    expect(await d.client.state()).toBe('ready');
    const p = await d.client.ping();
    expect(p.ok && p.value.device).toBe(await d.client.deviceId());
    expect(p.ok && p.value.until).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it('a proof works once; an invitation enrols a second device once', async () => {
    const proof = await mintProof('alpha', now());
    const a = device();
    expect((await a.client.enrol({ proof })).ok).toBe(true);
    const again = failure(await device().client.enrol({ proof }));
    expect(again.kind).toBe('already-used');
    expect(again.token).toBe('verbraucht');

    const inv = await a.client.invite();
    expect(inv.ok && inv.value.validForS).toBe(600);
    if (!inv.ok) return;
    const b = device();
    expect((await b.client.enrol({ invitation: inv.value.invitation })).ok).toBe(true);
    expect(failure(await device().client.enrol({ invitation: inv.value.invitation })).kind).toBe(
      'already-used',
    );
  });

  it('an expired proof, an invitation after ten minutes and a wrong app are refused with their kinds', async () => {
    const old = await mintProof('alpha', now(), 5);
    await advance(10_000);
    expect(failure(await device().client.enrol({ proof: old })).kind).toBe('proof-expired');
    const a = await enrolled();
    const inv = await a.client.invite();
    await advance(11 * 60_000);
    // an access lives 90 days: the inviter still works, the invitation does not
    expect(inv.ok).toBe(true);
    if (inv.ok) {
      const r = failure(await device().client.enrol({ invitation: inv.value.invitation }));
      expect(r.kind).toBe('invitation-expired');
    }
    const wrongApp = device({ appId: 'beta', origin: 'https://beta.example' });
    const r = failure(await wrongApp.client.enrol({ proof: await mintProof('alpha', now()) }));
    expect(['proof-malformed', 'proof-signature', 'origin-refused']).toContain(r.kind);
    const noKey = device({ appId: 'nokey', origin: 'https://nokey.example' });
    expect(failure(await noKey.client.enrol({ proof: await mintProof('nokey', now()) })).kind).toBe(
      'proof-not-set-up',
    );
    const closed = device({ appId: 'closed', origin: 'https://closed.example' });
    expect(
      failure(await closed.client.enrol({ proof: await mintProof('closed', now()) })).kind,
    ).toBe('admission-closed');
  });

  it('an app with invitations off refuses to invite', async () => {
    const a = await enrolled('noinvite');
    expect(failure(await a.client.invite()).kind).toBe('invitations-off');
  });
});

describe('real relay: drop and collect', () => {
  it('a message arrives once, in full, with the sender, in order, and presence is reported', async () => {
    const a = await enrolled();
    const b = await enrolled();
    const sent = [bytes(10, 1), bytes(65_536, 2), bytes(1, 3)];
    for (const content of sent) {
      const r = await a.client.drop([{ device: b.id, content }]);
      expect(r.ok && r.value.results[0]).toMatchObject({ ok: true, present: false });
    }
    // b has not collected yet; a asks, b collects (and is present from then on)
    const got = await b.client.collectAll({ ask: [a.id] });
    expect(got.ok).toBe(true);
    if (!got.ok) return;
    expect(got.value.messages.map((m) => m.content.length)).toEqual([10, 65_536, 1]);
    expect(got.value.messages.every((m) => m.from === a.id)).toBe(true);
    expect(got.value.more).toBe(false);
    expect(got.value.messages[0]!.content).toEqual(bytes(10, 1));
    const empty = await b.client.collectAll();
    expect(empty.ok && empty.value.messages).toEqual([]);
    const again = await a.client.drop([{ device: b.id, content: bytes(2) }]);
    expect(again.ok && again.value.results[0]).toMatchObject({ ok: true, present: true });
    const asked = await a.client.collect({ ask: [b.id] });
    expect(asked.ok && asked.value.present).toEqual([b.id]);
  });

  it('50 recipients are taken, each stored apart; 100 per mailbox then recipient-full', async () => {
    const a = await enrolled();
    const b = await enrolled();
    const ids = Array.from({ length: 50 }, (_, i) => `geraet-${i.toString(16).padStart(32, '0')}`);
    const r = await a.client.drop(ids.map((device) => ({ device, content: bytes(5) })));
    expect(r.ok && r.value.results.every((x) => x.ok)).toBe(true);
    expect(r.ok && r.value.results.map((x) => x.device)).toEqual(ids);
    for (let i = 0; i < 100; i += 1) {
      const x = await a.client.drop([{ device: b.id, content: bytes(1) }]);
      expect(x.ok && x.value.results[0]!.ok, `message ${i}`).toBe(true);
    }
    const full = await a.client.drop([{ device: b.id, content: bytes(1) }]);
    expect(full.ok && full.value.results[0]).toMatchObject({
      ok: false,
      kind: 'recipient-full',
      class: 'refused',
    });
    // 51 recipients and a message over 64 KB never leave the client
    expect(
      failure(await a.client.drop([...ids, b.id].map((device) => ({ device, content: bytes(1) }))))
        .kind,
    ).toBe('bad-argument');
    expect(failure(await a.client.drop([{ device: b.id, content: bytes(65_537) }])).kind).toBe(
      'bad-argument',
    );
  });

  it('the largest drop the protocol allows (50 recipients, 64 KiB each, about 4.4 MB of JSON) is taken and collected', async () => {
    const a = await enrolled();
    const b = await enrolled();
    const ids = [
      b.id,
      ...Array.from({ length: 49 }, (_, i) => `geraet-${(i + 1).toString(16).padStart(32, '0')}`),
    ];
    const r = await a.client.drop(
      ids.map((device, i) => ({ device, content: bytes(65_536, i + 1) })),
    );
    expect(r.ok && r.value.results.every((x) => x.ok)).toBe(true);
    const got = await b.client.collectAll();
    expect(got.ok && got.value.messages.map((m) => [m.content.length, m.content[0]])).toEqual([
      [65_536, 1],
    ]);
  });

  it('collectAll follows `more` across calls and loses nothing', async () => {
    const a = await enrolled();
    const b = await enrolled();
    await real.control.setLimits!({ collectBytes: 100_000 });
    for (let i = 0; i < 6; i += 1) {
      await a.client.drop([{ device: b.id, content: bytes(40_000, i + 1) }]);
    }
    const one = await b.client.collect();
    expect(one.ok && one.value.more).toBe(true);
    const rest = await b.client.collectAll();
    expect(rest.ok).toBe(true);
    if (!rest.ok) return;
    const total = (one.ok ? one.value.messages.length : 0) + rest.value.messages.length;
    expect(total).toBe(6);
    expect(rest.value.more).toBe(false);
    expect(rest.value.messages.map((m) => m.content[0])).toEqual(
      [1, 2, 3, 4, 5, 6].slice(6 - rest.value.messages.length),
    );
    // with the bound of one call the loop stops with more = true and nothing is lost
    for (let i = 0; i < 6; i += 1)
      await a.client.drop([{ device: b.id, content: bytes(40_000, i + 1) }]);
    const bounded = await b.client.collectAll({ maxCalls: 1 });
    expect(bounded.ok && bounded.value.more).toBe(true);
    const tail = await b.client.collectAll();
    expect(
      (bounded.ok ? bounded.value.messages.length : 0) + (tail.ok ? tail.value.messages.length : 0),
    ).toBe(6);
  });

  it('a message waits 30 seconds on the relay clock and is gone after that', async () => {
    const a = await enrolled();
    const b = await enrolled();
    await a.client.drop([{ device: b.id, content: bytes(3) }]);
    await advance(29_000);
    const kept = await b.client.collectAll();
    expect(kept.ok && kept.value.messages.length).toBe(1);
    // presence ends 30 s after the last collect (b collected 0 s ago on the relay clock)
    const present = await a.client.collect({ ask: [b.id] });
    expect(present.ok && present.value.present).toEqual([b.id]);
    await a.client.drop([{ device: b.id, content: bytes(3) }]);
    await advance(31_000);
    const absent = await a.client.collect({ ask: [b.id] });
    expect(absent.ok && absent.value.present).toEqual([]);
    const gone = await b.client.collectAll();
    expect(gone.ok && gone.value.messages).toEqual([]);
  });

  it('the devices of two apps never reach each other', async () => {
    const a = await enrolled('alpha');
    const g = await enrolled('gamma');
    const r = await a.client.drop([{ device: g.id, content: bytes(2) }]);
    expect(r.ok && r.value.results[0]!.ok).toBe(true); // stored in a mailbox of alpha for that id
    const got = await g.client.collectAll();
    expect(got.ok && got.value.messages).toEqual([]);
  });

  it('the sender, app and total limits come back as results of the recipient', async () => {
    const a = await enrolled();
    const [b, c, d] = [await enrolled(), await enrolled(), await enrolled()];
    await real.control.setLimits!({ senderBytes: 1024 });
    expect((await a.client.drop([{ device: b.id, content: bytes(5) }])).ok).toBe(true);
    const r = await a.client.drop([{ device: c.id, content: bytes(5) }]);
    expect(r.ok && r.value.results[0]).toMatchObject({
      ok: false,
      kind: 'sender-full',
      class: 'refused',
    });
    await real.control.setLimits!({ senderBytes: 4_194_304, appBytes: 1024 });
    const r2 = await a.client.drop([{ device: d.id, content: bytes(5) }]);
    expect(r2.ok && r2.value.results[0]).toMatchObject({
      ok: false,
      kind: 'app-full',
      class: 'retry',
    });
  });
});

describe('real relay: ring', () => {
  async function ringRequest() {
    const receiver = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ]);
    const jwk = await crypto.subtle.exportKey('jwk', receiver.publicKey);
    const raw = Buffer.concat([
      Buffer.from([4]),
      Buffer.from(jwk.x!, 'base64url'),
      Buffer.from(jwk.y!, 'base64url'),
    ]).toString('base64url');
    const vapid = await generateVapidKeys();
    const r = await buildRingRequest({
      subscription: {
        endpoint: 'https://fcm.googleapis.com/fcm/send/abc:def-123',
        keys: {
          p256dh: raw,
          auth: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url'),
        },
      },
      vapid: { ...vapid, subject: 'mailto:ops@example.org' },
      nowS: Math.floor(now() / 1000),
      ttl: 900,
      urgency: 'high',
      random: (n) => crypto.getRandomValues(new Uint8Array(n)),
    });
    if (!r.ok) throw new Error(r.reason);
    return r.value;
  }

  it('a ring request built by the push layer reaches the stand-in push service unchanged', async () => {
    const a = await enrolled();
    const req = await ringRequest();
    await real.control.setPushResult!(201);
    const r = await a.client.ring(req);
    expect(r.ok && r.value.service).toBe(201);
    const seen = (await real.control.pushes()) as any[];
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      endpunkt: req.endpoint,
      vapid: req.vapid,
      ttl: 900,
      dringlichkeit: 'high',
    });
    expect(Buffer.from(seen[0].koerper.data)).toEqual(Buffer.from(req.content));
  });

  it('an unreachable push service is push-service-unreachable (retry); a status of the service passes through', async () => {
    const a = await enrolled();
    const req = await ringRequest();
    await real.control.setPushResult!('unreachable');
    const r = failure(await a.client.ring(req));
    expect(r).toMatchObject({ kind: 'push-service-unreachable', class: 'retry', status: 502 });
    expect(r.attempts).toBe(1); // a ring is not repeated after an unclear outcome
    await real.control.setPushResult!(410);
    const gone = await a.client.ring(req);
    expect(gone.ok && gone.value.service).toBe(410);
  });

  it('the ring limit comes back as ring-rate-limited', async () => {
    const a = await enrolled();
    const req = await ringRequest();
    await real.control.setLimits!({ ringPerHour: 60 });
    for (let i = 0; i < 60; i += 1) expect((await a.client.ring(req)).ok, `ring ${i}`).toBe(true);
    expect(failure(await a.client.ring(req)).kind).toBe('ring-rate-limited');
  });
});

describe('real relay: renewal, expiry, re-enrolment', () => {
  it('renewIfDue does nothing until fewer than 30 days remain, then renews and the old access still works', async () => {
    const a = await enrolled();
    const first = await a.client.renewIfDue();
    expect(first.ok && first.value.renewed).toBe(false);
    await advance(61 * DAY);
    const before = a.st.value;
    const second = await a.client.renewIfDue();
    expect(second.ok && second.value.renewed).toBe(true);
    expect(a.st.value).not.toBe(before);
    expect((await a.client.ping()).ok).toBe(true);
    await advance(31 * DAY); // past the end of the first access, inside the renewed one
    expect((await a.client.ping()).ok).toBe(true);
  });

  it('an expired access is `access-expired` (reenrol); the reenrol hook enrols again with a new device id', async () => {
    let hooks = 0;
    const d = device({
      reenrol: async () => {
        hooks += 1;
        return { proof: await mintProof('alpha', now()) };
      },
    });
    const r = await d.client.enrol({ proof: await mintProof('alpha', now()) });
    if (!r.ok) throw new Error('enrol');
    const idBefore = r.value.device;
    await advance(91 * DAY);
    const p = await d.client.ping();
    expect(p.ok).toBe(true);
    expect(hooks).toBe(1);
    expect(await d.client.deviceId()).not.toBe(idBefore);

    const plain = await enrolled();
    await advance(91 * DAY);
    const x = failure(await plain.client.ping());
    expect(x).toMatchObject({ kind: 'access-expired', class: 'reenrol', status: 401 });
  });

  it('a forged access is `access-invalid`; no access is `no-credentials`; no bearer is `access-missing`', async () => {
    const a = await enrolled();
    const stored = JSON.parse(a.st.value!);
    const parts = (stored.access as string).split('.');
    parts[parts.length - 1] = 'A'.repeat(43);
    a.st.value = JSON.stringify({ ...stored, access: parts.join('.') });
    expect(failure(await a.client.ping())).toMatchObject({
      kind: 'access-invalid',
      class: 'reenrol',
    });
    expect(failure(await device().client.ping()).kind).toBe('no-credentials');
    const raw = await fetch(`${real.base}/v1/ping`, {
      method: 'POST',
      headers: { Origin: ORIGIN, 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect((await raw.json()).art).toBe('zugang-fehlt');
  });
});

describe('real relay: error kinds through the client, limits', () => {
  it('a client with another origin is refused with origin-refused, fatal, not retried', async () => {
    const a = await enrolled();
    const stored = a.st.value!;
    const other = device({ origin: 'https://beta.example' });
    other.st.value = stored;
    const r = failure(await other.client.ping());
    expect(r).toMatchObject({ kind: 'origin-refused', class: 'fatal', status: 403, attempts: 1 });
  });

  it('the 301st request in a minute is rate-limited (retry, with backoff and the hint)', async () => {
    const a = await enrolled();
    await real.control.setLimits!({ requestsPerMinute: 5 });
    let last: RelayResult<unknown> | undefined;
    for (let i = 0; i < 6; i += 1) last = await a.client.ping();
    expect(last).toMatchObject({ ok: false, kind: 'rate-limited', class: 'retry' });
    expect(a.sleeps.length).toBeGreaterThan(0); // the client backed off between attempts
  });

  it('a full relay: the existing relay still sends its old word, which the client reads as unavailable', async () => {
    await enrolled();
    await real.control.setLimits!({ devicesTotal: 1 });
    const r = failure(await device().client.enrol({ proof: await mintProof('alpha', now()) }));
    expect(r.status).toBe(503);
    // The existing relay still sends its old wire word for this (docs/relay-protocol.md, open point 9);
    // the client cannot read it as `relay-full` and treats the 503 like any gateway answer.
    expect(r).toMatchObject({ kind: 'unavailable', token: null, class: 'retry' });
  });

  it('the invitation limit (10 per hour) is invite-rate-limited', async () => {
    const a = await enrolled();
    for (let i = 0; i < 10; i += 1) expect((await a.client.invite()).ok, `invite ${i}`).toBe(true);
    expect(failure(await a.client.invite()).kind).toBe('invite-rate-limited');
  });

  it('poll collects in a loop at the cadence and stops on abort', async () => {
    const a = await enrolled();
    const b = await enrolled();
    await a.client.drop([{ device: b.id, content: bytes(4) }]);
    const ac = new AbortController();
    const got: number[] = [];
    const result = await b.client.poll(
      (batch) => {
        got.push(batch.messages.length);
        if (got.length === 2) ac.abort();
      },
      { signal: ac.signal },
    );
    expect(result.kind).toBe('aborted');
    expect(got).toEqual([1, 0]);
    expect(b.sleeps[0]).toBeGreaterThanOrEqual(1000);
  });
});
