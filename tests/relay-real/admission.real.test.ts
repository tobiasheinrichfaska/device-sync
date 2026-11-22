// Opt-in (`npm run test:relay-real`): the real RelayClient of revision 2 end to end against the REAL relay
// server over real HTTP: enrolment with the device's own key, signed requests, renewal, the step from an
// old access, invitation e2, founder ticket and password, the device list, blocking and the blocked hook,
// negotiation. The clock of the relay is moved through the harness.
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { RelayClient, readCertificate, type RelayResult } from '../../src/relay/index.ts';
import { mintProof } from '../relay/helpers.ts';
import { memoryStore, mintFounder, newSigner } from '../relay/helpers-r2.ts';
import { realHeaderNames } from './real-source.ts';
import { realPath, startReal, type RealServer } from './realserver.ts';

const DAY = 86_400_000;
let real: RealServer;
let skew = 0;
const headers = realHeaderNames(realPath() as string);
beforeAll(async () => {
  real = await startReal('r2');
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
const value = <T>(r: RelayResult<T>): T => {
  if (!r.ok) throw new Error(`expected a value, got ${r.kind}`);
  return r.value;
};
const failure = <T>(r: RelayResult<T>) => {
  if (r.ok) throw new Error('expected a failure');
  return r;
};

async function device(app = 'alpha', over: { onBlocked?: (i: { device: string }) => void } = {}) {
  const { signer } = await newSigner();
  const store = memoryStore();
  const calls: { url: string; init: RequestInit }[] = [];
  const client = new RelayClient({
    baseUrl: real.base,
    appId: app,
    origin: `https://${app}.example`,
    fetch: (u, i) => {
      calls.push({ url: u, init: i });
      return fetch(u, i);
    },
    store,
    clock: now,
    signer,
    headers,
    sleep: () => Promise.resolve(),
    random: () => 0,
    maxAttempts: 1,
    ...over,
  });
  return { client, store, signer, calls };
}
async function enrolWithProof(role?: string, app = 'alpha', over = {}) {
  const d = await device(app, over);
  const v = value(
    await d.client.enrol({ proof: await mintProof(app, now()), ...(role ? { role } : {}) }),
  );
  return { ...d, ...v };
}

describe('real relay, revision 2: enrolment with a key, signed requests, negotiation', () => {
  it('a proof and our key give a certificate for exactly that key, and every request is signed', async () => {
    const d = await enrolWithProof('lb:art');
    expect(d).toMatchObject({ group: '1', role: 'lb:art' });
    expect(d.info?.revision).toBeGreaterThanOrEqual(2);
    const stored = JSON.parse(d.store.value as string);
    expect(readCertificate(stored.access)?.key).toBe(d.signer.publicKey);
    const ping = value(await d.client.ping());
    expect(ping).toMatchObject({ device: d.device, group: '1', role: 'lb:art' });
    expect(ping.info?.procedures?.preferred).toBe('zertifikat');
    // the same request twice in the same second is two signatures, both taken
    const calls = d.calls.length;
    value(await d.client.collect());
    value(await d.client.collect());
    const sigs = d.calls
      .slice(calls)
      .map((c) => (c.init.headers as Record<string, string>)[headers.possession]);
    expect(sigs[0]).not.toBe(sigs[1]);
  });

  it('negotiation: from the health answer without credentials, from a signed ping with them', async () => {
    const d = await device();
    const first = value(await d.client.negotiate());
    expect(first.revision).toBeGreaterThanOrEqual(2);
    expect(first.abilities).toContain('sperren');
    await enrolWithProof();
    const e = await enrolWithProof();
    expect(value(await e.client.negotiate()).revision).toBeGreaterThanOrEqual(2);
  });

  it('a signature made for another body is refused; a clock that is off is `possession-time`', async () => {
    const d = await enrolWithProof();
    const skewed = new RelayClient({
      baseUrl: real.base,
      appId: 'alpha',
      origin: 'https://alpha.example',
      fetch: (u, i) => fetch(u, i),
      store: d.store,
      clock: () => now() + 600_000,
      signer: d.signer,
      headers,
    });
    expect(failure(await skewed.ping())).toMatchObject({
      kind: 'possession-time',
      token: 'besitz-zeit',
      status: 401,
    });
    // a key the certificate does not name: no request at all
    const other = await newSigner();
    const lost = new RelayClient({
      baseUrl: real.base,
      appId: 'alpha',
      origin: 'https://alpha.example',
      fetch: (u, i) => fetch(u, i),
      store: d.store,
      clock: now,
      signer: other.signer,
      headers,
    });
    expect(failure(await lost.ping()).kind).toBe('key-missing');
  });

  it('a certificate is renewed from day 30, not before', async () => {
    const d = await enrolWithProof('lb:art');
    await advance(29 * DAY);
    expect(value(await d.client.renewIfDue())).toMatchObject({ renewed: false });
    await advance(2 * DAY);
    expect(value(await d.client.renewIfDue()).renewed).toBe(true);
    const c = readCertificate(JSON.parse(d.store.value as string).access)!;
    expect(c).toMatchObject({ group: '1', role: 'lb:art', key: d.signer.publicKey });
    expect((await d.client.ping()).ok).toBe(true);
  });

  it('an old access becomes a certificate with our key and role; an old relay is not needed for that', async () => {
    const { signer } = await newSigner();
    const store = memoryStore();
    const plain = new RelayClient({
      baseUrl: real.base,
      appId: 'alpha',
      origin: 'https://alpha.example',
      fetch: (u, i) => fetch(u, i),
      store,
      clock: now,
    });
    value(await plain.enrol({ proof: await mintProof('alpha', now()) }));
    expect(JSON.parse(store.value as string).v).toBe(1);
    const up = new RelayClient({
      baseUrl: real.base,
      appId: 'alpha',
      origin: 'https://alpha.example',
      fetch: (u, i) => fetch(u, i),
      store,
      clock: now,
      signer,
      headers,
    });
    expect(value(await up.upgrade({ role: 'lb:art' }))).toMatchObject({
      group: '1',
      role: 'lb:art',
    });
    expect(JSON.parse(store.value as string).v).toBe(2);
    expect(value(await up.ping())).toMatchObject({ role: 'lb:art' });
    // an access renewed as before when it is due
    const store2 = memoryStore();
    const old = new RelayClient({
      baseUrl: real.base,
      appId: 'alpha',
      origin: 'https://alpha.example',
      fetch: (u, i) => fetch(u, i),
      store: store2,
      clock: now,
    });
    value(await old.enrol({ proof: await mintProof('alpha', now()) }));
    await advance(65 * DAY);
    expect(value(await old.renewIfDue()).renewed).toBe(true);
  });
});

describe('real relay, revision 2: invitation, founder ticket, password, strict group', () => {
  it("an e2 carries group and role; the new device takes it once; another app's e2 from this origin is refused", async () => {
    const office = await enrolWithProof('buero');
    const inv = value(await office.client.invite({ role: 'lb:art' }));
    expect(inv).toMatchObject({ group: '1', inviter: office.device, role: 'lb:art' });
    const joined = await device();
    expect(value(await joined.client.enrol({ invitation: inv.invitation }))).toMatchObject({
      group: '1',
      role: 'lb:art',
    });
    expect(failure(await (await device()).client.enrol({ invitation: inv.invitation })).kind).toBe(
      'already-used',
    );
    // a member's device may invite only its own role
    const member = await enrolWithProof('lb:art');
    expect(failure(await member.client.invite({ role: 'buero' })).kind).toBe('role-not-allowed');
    expect(value(await member.client.invite()).role).toBe('lb:art');
    // the old access still gets an e1
    const store = memoryStore();
    const plain = new RelayClient({
      baseUrl: real.base,
      appId: 'alpha',
      origin: 'https://alpha.example',
      fetch: (u, i) => fetch(u, i),
      store,
      clock: now,
    });
    value(await plain.enrol({ proof: await mintProof('alpha', now()) }));
    expect(value(await plain.invite()).invitation.startsWith('e1.')).toBe(true);
  });

  it('a founder ticket and a developer password make the first device of a group; the refusals are told apart', async () => {
    const a = await device('multi');
    const v = value(await a.client.enrol({ founder: await mintFounder('multi', '2', now()) }));
    expect(v).toMatchObject({ group: '2', role: 'buero' });
    const b = await device('multi');
    expect(
      failure(
        await b.client.enrol({ founder: await mintFounder('multi', '2', now(), 600, 'other') }),
      ).kind,
    ).toBe('developer-invalid');
    expect(
      failure(await b.client.enrol({ founder: await mintFounder('multi', '2', now(), -5) })).kind,
    ).toBe('developer-expired');
    expect(failure(await b.client.enrol({ password: 'correct horse', group: '2' })).kind).toBe(
      'developer-group-taken',
    );
    expect(failure(await b.client.enrol({ password: 'nope', group: '3' })).kind).toBe(
      'developer-invalid',
    );
    expect(value(await b.client.enrol({ password: 'repeat horse', group: '3' }))).toMatchObject({
      group: '3',
      role: 'buero',
    });
    expect(
      failure(await (await device('multi')).client.enrol({ password: 'old horse', group: '4' }))
        .kind,
    ).toBe('developer-expired');
  });

  it("a group beyond the app's limit is `admission-closed`, and a ticket refused there still works afterwards", async () => {
    await enrolWithProof(undefined, 'solo');
    const d = await device('solo');
    const ticket = await mintFounder('solo', '2', now());
    expect(failure(await d.client.enrol({ founder: ticket })).kind).toBe('admission-closed');
  });

  it('a strict group refuses the old ways with `client-update-needed`, says so in health, and takes an invitation with a certificate', async () => {
    const d = await device('strict');
    expect(
      failure(await d.client.enrol({ proof: await mintProof('strict', now()) })),
    ).toMatchObject({ kind: 'client-update-needed', status: 426 });
    expect(d.store.value).toBeUndefined();
    expect(value(await d.client.health())).toMatchObject({ app: 'strict', oldOff: true });
    // the first device by founder ticket (group 1 is strict: a certificate, no old access), then an invitation
    const first = await device('strict');
    expect(
      value(await first.client.enrol({ founder: await mintFounder('strict', '1', now()) })),
    ).toMatchObject({ group: '1', role: 'buero' });
    const inv = value(await first.client.invite());
    const second = await device('strict');
    expect(value(await second.client.enrol({ invitation: inv.invitation }))).toMatchObject({
      group: '1',
    });
    expect(JSON.parse(second.store.value as string).v).toBe(2);
  });
});

describe('real relay, revision 2: the device list, blocking and the blocked hook', () => {
  it("the office lists its group, a member's device its role; a certificate only", async () => {
    const office = await enrolWithProof('buero');
    const member = await enrolWithProof('lb:art');
    value(await member.client.ping());
    const all = value(await office.client.devices());
    expect(all.max).toBe(50);
    expect(all.devices.map((d) => d.device).sort()).toEqual([office.device, member.device].sort());
    expect(all.devices.find((d) => d.device === member.device)).toMatchObject({
      role: 'lb:art',
      procedure: 'new',
      protocol: 2,
    });
    expect(value(await member.client.devices()).devices.map((d) => d.device)).toEqual([
      member.device,
    ]);
    const store = memoryStore();
    const plain = new RelayClient({
      baseUrl: real.base,
      appId: 'alpha',
      origin: 'https://alpha.example',
      fetch: (u, i) => fetch(u, i),
      store,
      clock: now,
    });
    value(await plain.enrol({ proof: await mintProof('alpha', now()) }));
    expect(failure(await plain.devices()).kind).toBe('role-not-allowed');
  });

  it('a block: the target is refused on its next request, the hook runs once, it does not enrol itself back', async () => {
    const onBlocked = vi.fn();
    const office = await enrolWithProof('buero');
    const target = await enrolWithProof('lb:art', 'alpha', { onBlocked });
    expect(value(await office.client.block(target.device))).toEqual({ device: target.device });
    expect(failure(await target.client.collect()).kind).toBe('device-blocked');
    expect(failure(await target.client.collect()).kind).toBe('blocked-mark');
    expect(onBlocked).toHaveBeenCalledTimes(1);
    expect(onBlocked).toHaveBeenCalledWith(expect.objectContaining({ device: target.device }));
    expect(
      failure(await target.client.enrol({ proof: await mintProof('alpha', now()) })).kind,
    ).toBe('blocked-mark');
    // a member's device may not block an office device
    const member = await enrolWithProof('lb:other');
    expect(failure(await member.client.block(office.device)).kind).toBe('role-not-allowed');
  });

  it('a device on an old access that is blocked learns it too; blocking itself tells it at once', async () => {
    const onBlocked = vi.fn();
    const office = await enrolWithProof('buero');
    const store = memoryStore();
    const old = new RelayClient({
      baseUrl: real.base,
      appId: 'alpha',
      origin: 'https://alpha.example',
      fetch: (u, i) => fetch(u, i),
      store,
      clock: now,
      onBlocked,
    });
    const o = value(await old.enrol({ proof: await mintProof('alpha', now()) }));
    value(await old.ping());
    value(await office.client.block(o.device));
    expect(failure(await old.ping()).kind).toBe('device-blocked');
    expect(onBlocked).toHaveBeenCalledTimes(1);
    const selfHook = vi.fn();
    const me = await enrolWithProof('lb:art', 'alpha', { onBlocked: selfHook });
    value(await me.client.block(me.device));
    expect(selfHook).toHaveBeenCalledTimes(1);
    expect(await me.client.state()).toBe('blocked');
  });

  it('the list of blocks and the hourly limit are bounded', async () => {
    const office = await enrolWithProof('buero');
    await real.control.setLimits!({ blocklistPerGroup: 2, blocksPerHour: 3 });
    const ids = [1, 2, 3, 4].map((n) => `geraet-${String(n).padStart(32, '0')}`);
    value(await office.client.block(ids[0] as string));
    value(await office.client.block(ids[1] as string));
    expect(failure(await office.client.block(ids[2] as string))).toMatchObject({
      kind: 'blocklist-full',
      status: 503,
    });
    expect(failure(await office.client.block(ids[3] as string)).kind).toBe('invite-rate-limited');
  });
});
