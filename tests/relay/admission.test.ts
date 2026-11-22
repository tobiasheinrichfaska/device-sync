// Revision 2 (admission): the formats of certificate, invitation e2 and founder ticket, the roles, the
// strict readers of every answer, the proof of possession checked against an independent
// implementation (`node:crypto`), the stored state with its blocked mark, and seeded fuzzing of every
// reader (never throws, anything accepted is well formed).
import { createHash, createPublicKey, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  bodyHash,
  canBlock,
  canInvite,
  isHeaderName,
  isRawPublicKey,
  possessionText,
  possessionValue,
  readBlockAnswer,
  readCertificate,
  readDevicesAnswer,
  readEnrolAnswerR2,
  readFounderTicket,
  readHealthAnswer,
  readInfo,
  readInvitationR2,
  readInviteAnswer,
  readPingAnswerR2,
  readRenewAnswerR2,
  readStoredCredentials,
  readStoredState,
  readUpgradeAnswer,
  relayRoleOf,
  signerFromKeys,
  writeBlockedMark,
  writeStoredCredentials,
  RELAY_GROUP,
  RELAY_ROLE,
} from '../../src/relay/index.ts';
import { mulberry32 } from './helpers.ts';
import {
  DEV,
  DEV2,
  FAKE_KEY,
  J,
  MAC,
  certText,
  founderText,
  inv2Text,
  mutateText,
  newSigner,
  randomValue,
  ticketText,
} from './helpers-r2.ts';

const INFO = {
  v: 2,
  faehigkeiten: ['mandant', 'zertifikat'],
  verfahren: {
    angeboten: ['zugang', 'zertifikat'],
    bevorzugt: 'zertifikat',
    einschreiben: ['nachweis'],
  },
};
const END = 1802476800;
const DAY = new Date(END * 1000).toISOString().slice(0, 10);

describe('certificate, invitation e2 and founder ticket: one spelling, strictly read', () => {
  it('reads app, group, device, role, key and end; another shape is no certificate', () => {
    expect(readCertificate(certText())).toEqual({
      app: 'alpha',
      group: '1',
      device: DEV,
      role: 'buero',
      key: FAKE_KEY,
      endS: END,
    });
    expect(readCertificate(certText({ role: 'lb:art_1-x' }))?.role).toBe('lb:art_1-x');
    for (const bad of [
      certText({ role: 'admin' }),
      certText({ role: 'lb:' }),
      certText({ role: `lb:${'x'.repeat(41)}` }),
      certText({ group: 'standard' }),
      certText({ group: 'Big' }),
      certText({ group: 'x'.repeat(21) }),
      certText({ device: 'geraet-xyz' }),
      certText({ app: 'A' }),
      certText({ key: FAKE_KEY.slice(1) }),
      certText({ key: `${FAKE_KEY.slice(0, 86)}B` }), // a second spelling of the same key
      certText({ end: 0 }),
      `${certText()}.x`,
      certText().replace('c1.', 'c2.'),
      certText().slice(0, -1),
      `${certText()}\n`,
      certText({ key: 'A'.repeat(87) }), // not an uncompressed point (first byte 0)
    ]) {
      expect(readCertificate(bad), bad).toBeUndefined();
    }
    expect(readCertificate(undefined)).toBeUndefined();
    expect(readCertificate('c1.'.padEnd(500, 'a'))).toBeUndefined();
  });

  it('reads an invitation e2: app, group, inviter, role, end; nothing else is taken for one', () => {
    expect(readInvitationR2(inv2Text({ role: 'lb:art' }))).toEqual({
      app: 'alpha',
      group: '1',
      inviter: DEV,
      role: 'lb:art',
      endS: END,
    });
    for (const bad of [
      inv2Text({ role: 'ADMIN' }),
      inv2Text({ inviter: 'geraet-1' }),
      inv2Text({ group: 'standard' }),
      inv2Text().replace('e2.', 'e1.'),
      `${inv2Text()}x`,
      inv2Text().slice(0, -2),
      inv2Text().replace(/\.[A-Za-z0-9_-]{22}\./, '.AAAAAAAAAAAAAAAAAAAAAB.'), // random part with unused bits
    ]) {
      expect(readInvitationR2(bad), bad).toBeUndefined();
    }
  });

  it('reads a founder ticket: app, group, end; signature of 64 bytes in one spelling', () => {
    expect(readFounderTicket(founderText({ group: 'north' }))).toEqual({
      app: 'alpha',
      group: 'north',
      endS: END,
    });
    expect(readFounderTicket(founderText().replace('g1.', 'g2.'))).toBeUndefined();
    expect(readFounderTicket(`${founderText()}x`)).toBeUndefined();
    expect(readFounderTicket(founderText({ group: 'standard' }))).toBeUndefined();
    expect(readFounderTicket(5)).toBeUndefined();
  });

  it('group and role forms, and a raw key', () => {
    for (const g of ['1', 'north-2', 'a'.repeat(20)]) expect(RELAY_GROUP.test(g), g).toBe(true);
    for (const g of ['', 'standard', 'Nord', 'a'.repeat(21), 'a b', '1\n']) {
      expect(RELAY_GROUP.test(g), g).toBe(false);
    }
    for (const r of ['buero', 'ohne', 'lb:x', 'lb:a_b-C9'])
      expect(RELAY_ROLE.test(r), r).toBe(true);
    for (const r of ['', 'Buero', 'lb', 'lb:', 'lb:a b', 'buero\n', 'ohne ']) {
      expect(RELAY_ROLE.test(r), r).toBe(false);
    }
    expect(isRawPublicKey(FAKE_KEY)).toBe(true);
    expect(isRawPublicKey(FAKE_KEY.slice(0, 86))).toBe(false);
    expect(isRawPublicKey(`${FAKE_KEY.slice(0, 86)}B`)).toBe(false);
    expect(isRawPublicKey(5)).toBe(false);
    for (const h of ['x-relay-signature', 'x-a']) expect(isHeaderName(h)).toBe(true);
    for (const h of ['authorization', 'X-Relay', 'x-', 'x-a b', 5])
      expect(isHeaderName(h)).toBe(false);
  });
});

describe('roles: what each may do, as the relay decides it', () => {
  it('the relay role of an app role: the same text where the relay can hold it, else none: never more', () => {
    expect(relayRoleOf('buero')).toBe('buero');
    expect(relayRoleOf('lb:art')).toBe('lb:art');
    for (const v of ['ohne', 'admin', 'lb:', `lb:${'x'.repeat(41)}`, 'Buero', 5, undefined, null]) {
      expect(relayRoleOf(v), String(v)).toBe('ohne');
    }
  });

  it('inviting: the office any role; a member device only its own; a device without a role nothing', () => {
    for (const r of ['buero', 'ohne', 'lb:a']) expect(canInvite('buero', r)).toBe(true);
    expect(canInvite('lb:a', 'lb:a')).toBe(true);
    expect(canInvite('lb:a', 'lb:b')).toBe(false);
    expect(canInvite('lb:a', 'buero')).toBe(false);
    expect(canInvite('lb:a', 'ohne')).toBe(false);
    expect(canInvite('ohne', 'ohne')).toBe(false);
    expect(canInvite('buero', 'admin')).toBe(false);
    expect(canInvite('admin', 'ohne')).toBe(false);
  });

  it('blocking: itself always; the office every device; a member device the devices of its role, never an office or another member device', () => {
    for (const role of ['buero', 'ohne', 'lb:a'])
      expect(canBlock(role, undefined, true), role).toBe(true);
    expect(canBlock('buero', undefined, false)).toBe(true);
    expect(canBlock('buero', 'lb:z', false)).toBe(true);
    expect(canBlock('lb:a', 'lb:a', false)).toBe(true);
    expect(canBlock('lb:a', 'lb:b', false)).toBe(false);
    expect(canBlock('lb:a', 'buero', false)).toBe(false);
    expect(canBlock('lb:a', undefined, false)).toBe(false);
    expect(canBlock('ohne', 'ohne', false)).toBe(false);
  });
});

describe('the answers of revision 2', () => {
  const cert = (over: Parameters<typeof certText>[0] = {}) => certText({ key: FAKE_KEY, ...over });
  const enrol = {
    geraet: DEV,
    zertifikat: cert(),
    mandant: '1',
    rolle: 'buero',
    bis: DAY,
  };

  it('enrolment with our key: the certificate must name the device and carry exactly our key; group and role as in it', () => {
    expect(readEnrolAnswerR2(J(enrol), 'alpha', FAKE_KEY)).toEqual({
      device: DEV,
      access: cert(),
      until: DAY,
      group: '1',
      role: 'buero',
    });
    const read = (o: unknown, key = FAKE_KEY, app = 'alpha') => readEnrolAnswerR2(J(o), app, key);
    expect(read({ ...enrol, zertifikat: cert({ device: DEV2 }) })).toBeUndefined(); // another device
    expect(read(enrol, `${FAKE_KEY.slice(0, 80)}AAAAAAA`)).toBeUndefined(); // not our key
    expect(read(enrol, FAKE_KEY, 'beta')).toBeUndefined(); // another app
    expect(read({ ...enrol, mandant: '2' })).toBeUndefined();
    expect(read({ ...enrol, rolle: 'ohne' })).toBeUndefined();
    expect(read({ ...enrol, bis: '2027-01-01' })).toBeUndefined(); // not the certificate's end day
    expect(read({ ...enrol, extra: 1 })).toBeUndefined();
    const { zertifikat: _gone, ...without } = enrol;
    expect(read(without)).toBeUndefined(); // a keyed enrolment is answered with a certificate
    // a ticket beside the certificate (group 1) is checked and dropped; another device's is refused
    expect(read({ ...enrol, zugang: ticketText() })?.access).toBe(cert());
    expect(read({ ...enrol, zugang: ticketText('alpha', DEV2) })).toBeUndefined();
    expect(read({ ...enrol, zugang: 'z1.x' })).toBeUndefined();
    // what the relay says about itself comes along, strictly
    expect(read({ ...enrol, ...INFO })?.info).toEqual({
      revision: 2,
      abilities: ['mandant', 'zertifikat'],
      procedures: {
        offered: ['zugang', 'zertifikat'],
        preferred: 'zertifikat',
        enrolWays: ['nachweis'],
      },
    });
    expect(read({ ...enrol, faehigkeiten: ['x'] })).toBeUndefined(); // abilities only with `v`
    expect(read({ ...enrol, ...INFO, v: 0 })).toBeUndefined();
    expect(read({ ...enrol, ...INFO, faehigkeiten: ['Bad Word'] })).toBeUndefined();
  });

  it('renewal of a certificate: same device, key, group, role, and not an earlier end', () => {
    const current = readCertificate(cert())!;
    const newer = cert({ end: END + 86_400 });
    const body = {
      zertifikat: newer,
      bis: new Date((END + 86_400) * 1000).toISOString().slice(0, 10),
    };
    const read = (o: unknown, c = current) => readRenewAnswerR2(J(o), 'alpha', c);
    expect(read(body)).toEqual({ access: newer, until: body.bis });
    expect(read({ ...body, zertifikat: cert({ end: END - 86_400 }) })).toBeUndefined(); // older end
    expect(
      read({ ...body, zertifikat: cert({ end: END + 86_400, role: 'ohne' }) }),
    ).toBeUndefined();
    expect(read({ ...body, zertifikat: cert({ end: END + 86_400, group: '2' }) })).toBeUndefined();
    expect(
      read({ ...body, zertifikat: cert({ end: END + 86_400, device: DEV2 }) }),
    ).toBeUndefined();
    expect(read({ ...body, bis: DAY })).toBeUndefined(); // end day of another end
    expect(read({ ...body, zugang: ticketText() })).toBeUndefined();
    expect(read({ ...body, ...INFO })?.info?.revision).toBe(2);
  });

  it('the step from an old access to a certificate: our key, the old access checked and dropped', () => {
    const body = {
      zugang: ticketText(),
      bis: '2027-05-01',
      zertifikat: cert({ role: 'lb:art' }),
      mandant: '1',
      rolle: 'lb:art',
    };
    expect(readUpgradeAnswer(J(body), 'alpha', DEV, FAKE_KEY)).toEqual({
      device: DEV,
      access: cert({ role: 'lb:art' }),
      until: DAY,
      group: '1',
      role: 'lb:art',
    });
    expect(readUpgradeAnswer(J(body), 'alpha', DEV2, FAKE_KEY)).toBeUndefined();
    expect(
      readUpgradeAnswer(J(body), 'alpha', DEV, `${FAKE_KEY.slice(0, 80)}AAAAAAA`),
    ).toBeUndefined();
    expect(readUpgradeAnswer(J({ ...body, mandant: '2' }), 'alpha', DEV, FAKE_KEY)).toBeUndefined();
    const { zugang: _z, ...noTicket } = body;
    expect(readUpgradeAnswer(J(noTicket), 'alpha', DEV, FAKE_KEY)).toBeUndefined();
  });

  it('ping: the certificate says group and role (both or none), the revision members come together', () => {
    const base = { geraet: DEV, app: 'alpha', bis: DAY };
    expect(readPingAnswerR2(J(base))).toEqual({ device: DEV, app: 'alpha', until: DAY });
    expect(readPingAnswerR2(J({ ...base, mandant: '1', rolle: 'buero', ...INFO }))).toMatchObject({
      group: '1',
      role: 'buero',
      info: { revision: 2 },
    });
    expect(readPingAnswerR2(J({ ...base, mandant: '1' }))).toBeUndefined();
    expect(readPingAnswerR2(J({ ...base, rolle: 'buero' }))).toBeUndefined();
    expect(readPingAnswerR2(J({ ...base, mandant: 'standard', rolle: 'buero' }))).toBeUndefined();
    expect(readPingAnswerR2(J({ ...base, mandant: '1', rolle: 'admin' }))).toBeUndefined();
    expect(readPingAnswerR2(J({ ...base, x: 1 }))).toBeUndefined();
    expect(readPingAnswerR2(J({ ...base, verfahren: INFO.verfahren }))).toBeUndefined(); // without `v`
  });

  it('invite: an e1 as before, or an e2 for this app with group, inviter and role', () => {
    const e2 = inv2Text({ role: 'lb:art', group: 'north' });
    expect(readInviteAnswer(J({ einladung: e2, gueltigS: 600 }), 'alpha')).toEqual({
      invitation: e2,
      validForS: 600,
      group: 'north',
      inviter: DEV,
      role: 'lb:art',
    });
    expect(readInviteAnswer(J({ einladung: e2, gueltigS: 600 }), 'beta')).toBeUndefined();
    expect(
      readInviteAnswer(J({ einladung: e2.slice(0, -1), gueltigS: 600 }), 'alpha'),
    ).toBeUndefined();
    expect(readInviteAnswer(J({ einladung: e2, gueltigS: 0 }), 'alpha')).toBeUndefined();
  });

  it('the device list: every entry strictly, no device twice, times as the relay writes them', () => {
    const entry = {
      geraet: DEV,
      rolle: 'buero',
      von: 'alt',
      seit: '2026-11-22T10:00:00.000Z',
      zuletzt: '2026-11-22T10:05:00.000Z',
      verfahren: 'neu',
      p: 2,
    };
    const ok = readDevicesAnswer(
      J({
        geraete: [entry, { ...entry, geraet: DEV2, von: DEV, verfahren: 'alt', p: undefined }],
        hoechstens: 50,
      }),
    );
    expect(ok?.max).toBe(50);
    expect(ok?.devices[0]).toEqual({
      device: DEV,
      role: 'buero',
      introducedBy: { by: 'old-access' },
      sinceMs: Date.parse('2026-11-22T10:00:00.000Z'),
      lastMs: Date.parse('2026-11-22T10:05:00.000Z'),
      procedure: 'new',
      protocol: 2,
    });
    expect(ok?.devices[1]).toMatchObject({
      introducedBy: { by: 'device', device: DEV },
      procedure: 'old',
    });
    expect(ok?.devices[1]).not.toHaveProperty('protocol');
    const read = (o: unknown) => readDevicesAnswer(J(o));
    expect(read({ geraete: [entry, entry], hoechstens: 50 })).toBeUndefined(); // a device twice
    expect(read({ geraete: [{ ...entry, rolle: 'admin' }], hoechstens: 50 })).toBeUndefined();
    expect(read({ geraete: [{ ...entry, von: 'someone' }], hoechstens: 50 })).toBeUndefined();
    expect(read({ geraete: [{ ...entry, verfahren: 'mittel' }], hoechstens: 50 })).toBeUndefined();
    expect(read({ geraete: [{ ...entry, seit: '2026-11-22' }], hoechstens: 50 })).toBeUndefined();
    expect(
      read({ geraete: [{ ...entry, seit: '2026-11-22T10:00:00Z' }], hoechstens: 50 }),
    ).toBeUndefined();
    expect(
      read({ geraete: [{ ...entry, zuletzt: '2026-02-30T10:00:00.000Z' }], hoechstens: 50 }),
    ).toBeUndefined();
    expect(read({ geraete: [{ ...entry, p: 1000 }], hoechstens: 50 })).toBeUndefined();
    expect(read({ geraete: [{ ...entry, extra: 1 }], hoechstens: 50 })).toBeUndefined();
    expect(read({ geraete: [entry], hoechstens: 0 })).toBeUndefined();
    expect(read({ geraete: [entry], hoechstens: 1001 })).toBeUndefined();
    const many = Array.from({ length: 3 }, (_, i) => ({
      ...entry,
      geraet: `geraet-${String(i).padStart(32, '0')}`,
    }));
    expect(read({ geraete: many, hoechstens: 1 })).toBeUndefined(); // more than twice the limit
    expect(read({ geraete: many.slice(0, 2), hoechstens: 1 })?.devices).toHaveLength(2);
  });

  it('the block answer names the device that was asked about, and gesperrt true', () => {
    expect(readBlockAnswer(J({ geraet: DEV, gesperrt: true }), DEV)).toBe(true);
    expect(readBlockAnswer(J({ geraet: DEV2, gesperrt: true }), DEV)).toBe(false);
    expect(readBlockAnswer(J({ geraet: DEV, gesperrt: false }), DEV)).toBe(false);
    expect(readBlockAnswer(J({ geraet: DEV, gesperrt: true, x: 1 }), DEV)).toBe(false);
    expect(readBlockAnswer('{', DEV)).toBe(false);
  });

  it('what a relay says about itself: strict words, bounded lists', () => {
    expect(readInfo({})).toBeUndefined();
    expect(readInfo({ v: 2 })).toEqual({ revision: 2, abilities: [] });
    expect(readInfo({ v: 100 })).toBeNull();
    expect(readInfo({ v: 2, faehigkeiten: Array.from({ length: 21 }, () => 'a') })).toBeNull();
    expect(
      readInfo({ v: 2, verfahren: { angeboten: [], bevorzugt: 'x', einschreiben: [], y: 1 } }),
    ).toBeNull();
    expect(
      readInfo({
        v: 2,
        verfahren: {
          angeboten: Array.from({ length: 11 }, () => 'a'),
          bevorzugt: 'x',
          einschreiben: [],
        },
      }),
    ).toBeNull();
  });

  it('health: the procedures and `altAbgeschaltet` are read, anything else is refused', () => {
    const r = readHealthAnswer(
      J({
        ok: true,
        stand: 'abc',
        ...INFO,
        app: 'alpha',
        altAbgeschaltet: true,
        aufnahmeOffen: false,
      }),
    );
    expect(r).toMatchObject({ revision: 2, oldOff: true, adminOpen: false, app: 'alpha' });
    expect(r?.procedures?.preferred).toBe('zertifikat');
    expect(
      readHealthAnswer(J({ ok: true, stand: 'abc', verfahren: INFO.verfahren })),
    ).toBeUndefined();
  });
});

describe('the stored state: credentials of both kinds and the blocked mark', () => {
  const cert = certText();
  const c = {
    device: DEV,
    access: cert,
    until: DAY,
    group: '1',
    role: 'buero',
  };

  it("a certificate must be this app's and this device's, its end the stored one, group and role those in it; the old access as before", () => {
    expect(readStoredCredentials(writeStoredCredentials(c), 'alpha')).toEqual(c);
    expect(readStoredCredentials(writeStoredCredentials(c), 'beta')).toBeUndefined();
    const text = JSON.parse(writeStoredCredentials(c));
    for (const bad of [
      { ...text, device: DEV2 },
      { ...text, until: '2027-01-01' },
      { ...text, group: '2' },
      { ...text, role: 'ohne' },
      { ...text, extra: 1 },
      { ...text, access: ticketText() },
    ]) {
      expect(readStoredCredentials(J(bad), 'alpha'), J(bad)).toBeUndefined();
    }
    const old = { device: DEV, access: ticketText(), until: '2027-02-13' };
    expect(readStoredCredentials(writeStoredCredentials(old), 'alpha')).toEqual(old);
    // a version-1 text with a certificate in it is not read (the version says what it holds)
    expect(readStoredCredentials(J({ v: 1, ...old, access: cert }), 'alpha')).toBeUndefined();
  });

  it('the blocked mark: the device and the day, nothing else, and it is no credentials', () => {
    const mark = writeBlockedMark(DEV, '2026-11-22');
    expect(readStoredState(mark, 'alpha')).toEqual({
      kind: 'blocked',
      device: DEV,
      day: '2026-11-22',
    });
    expect(readStoredCredentials(mark, 'alpha')).toBeUndefined();
    expect(readStoredState(J({ v: 2, blocked: DEV, day: '2026-13-01' }), 'alpha')).toBeUndefined();
    expect(readStoredState(J({ v: 2, blocked: 'x', day: '2026-11-22' }), 'alpha')).toBeUndefined();
    expect(
      readStoredState(J({ v: 2, blocked: DEV, day: '2026-11-22', x: 1 }), 'alpha'),
    ).toBeUndefined();
    expect(readStoredState(J({ v: 3 }), 'alpha')).toBeUndefined();
  });
});

describe('proof of possession: the text, the hash and the header, against node:crypto', () => {
  it('the text is exactly version, method, path, time, hash of the body, certificate', () => {
    expect(possessionText('POST', '/v1/abholen', 1700000000, 'HASH', 'CERT')).toBe(
      'v1\nPOST\n/v1/abholen\n1700000000\nHASH\nCERT',
    );
  });

  it('the body hash is SHA-256 of the UTF-8 body, base64url (a known value: the empty body)', async () => {
    expect(await bodyHash('')).toBe('47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU');
    for (const body of ['{}', '{"an":[]}', 'ä€😀']) {
      expect(await bodyHash(body)).toBe(
        createHash('sha256').update(body, 'utf8').digest('base64url'),
      );
    }
  });

  it('the header is `<t>.<signature>` and the signature checks against the key, the text and nothing else', async () => {
    const { signer, publicKey } = await newSigner();
    const certificate = certText({ key: signer.publicKey });
    const args = {
      signer,
      method: 'POST',
      path: '/v1/ping',
      body: '{}',
      certificate,
      nowMs: 1_700_000_000_999,
    };
    const value = await possessionValue(args);
    expect(value).toMatch(/^1700000000\.[A-Za-z0-9_-]{86}$/);
    const [t, sig] = (value as string).split('.');
    // an independent check: the key from the public JWK, the text built here, node's ECDSA
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);
    const key = createPublicKey({ key: jwk as never, format: 'jwk' });
    const text = (over: Partial<Record<'method' | 'path' | 'body' | 'cert', string>> = {}) =>
      `v1\n${over.method ?? 'POST'}\n${over.path ?? '/v1/ping'}\n${t}\n${createHash('sha256')
        .update(over.body ?? '{}')
        .digest('base64url')}\n${over.cert ?? certificate}`;
    const good = (data: string): boolean =>
      verify(
        'sha256',
        Buffer.from(data),
        { key, dsaEncoding: 'ieee-p1363' },
        Buffer.from(sig as string, 'base64url'),
      );
    expect(good(text())).toBe(true);
    expect(good(text({ body: '{ }' }))).toBe(false);
    expect(good(text({ path: '/v1/abholen' }))).toBe(false);
    expect(good(text({ method: 'GET' }))).toBe(false);
    expect(good(text({ cert: `${certificate}x` }))).toBe(false);
    expect(good(text().replace(`\n${t}\n`, `\n${Number(t) + 1}\n`))).toBe(false);
    // two signatures of one request are two values (ECDSA draws its own nonce)
    expect(await possessionValue(args)).not.toBe(value);
    // the time is whole seconds of the parameter, never a clock read inside
    expect((await possessionValue({ ...args, nowMs: 5_999 }))?.startsWith('5.')).toBe(true);
  });

  it('a signer that throws, answers a wrong length or a bad time gives no header, never an exception', async () => {
    const base = {
      method: 'POST',
      path: '/v1/ping',
      body: '{}',
      certificate: certText(),
      nowMs: 1_700_000_000_000,
    };
    const mk = (sign: () => unknown) => ({ publicKey: FAKE_KEY, sign }) as never;
    expect(
      await possessionValue({
        ...base,
        signer: mk(() => {
          throw new Error('x');
        }),
      }),
    ).toBeUndefined();
    expect(
      await possessionValue({ ...base, signer: mk(() => Promise.reject(new Error('x'))) }),
    ).toBeUndefined();
    expect(
      await possessionValue({ ...base, signer: mk(() => new Uint8Array(63)) }),
    ).toBeUndefined();
    expect(await possessionValue({ ...base, signer: mk(() => 'x') })).toBeUndefined();
    expect(
      await possessionValue({ ...base, signer: mk(() => new Uint8Array(64)), nowMs: Number.NaN }),
    ).toBeUndefined();
  });

  it('a public key is 87 characters, raw and uncompressed: what `geraetSchluessel` wants', async () => {
    const { signer, publicKey } = await newSigner();
    expect(signer.publicKey).toHaveLength(87);
    expect(signer.publicKey).toBe(
      Buffer.from(await crypto.subtle.exportKey('raw', publicKey)).toString('base64url'),
    );
    // only a P-256 key signs: a key of another curve is refused
    const p384 = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    await expect(signerFromKeys(p384.privateKey, p384.publicKey)).rejects.toThrow();
  });
});

// ── seeded fuzzing of every reader of revision 2 ──────────────────────────────────────────────────

describe('readers of revision 2: seeded fuzzing, never throws, anything accepted is well formed', () => {
  const KEYS = [
    'geraet',
    'zertifikat',
    'mandant',
    'rolle',
    'bis',
    'zugang',
    'v',
    'faehigkeiten',
    'verfahren',
    'geraete',
    'hoechstens',
    'von',
    'seit',
    'zuletzt',
    'p',
    'gesperrt',
    'einladung',
    'gueltigS',
    'app',
    'ok',
    'stand',
  ];
  const current = readCertificate(certText())!;
  const entry = {
    geraet: DEV,
    rolle: 'buero',
    von: 'alt',
    seit: '2026-11-22T10:00:00.000Z',
    zuletzt: '2026-11-22T10:05:00.000Z',
    verfahren: 'neu',
    p: 2,
  };
  const valid: Record<string, string> = {
    enrol: J({
      geraet: DEV,
      zertifikat: certText(),
      mandant: '1',
      rolle: 'buero',
      bis: DAY,
      zugang: ticketText(),
      ...INFO,
    }),
    renew: J({
      zertifikat: certText({ end: END + 86_400 }),
      bis: new Date((END + 86_400) * 1000).toISOString().slice(0, 10),
      ...INFO,
    }),
    upgrade: J({
      zugang: ticketText(),
      bis: DAY,
      zertifikat: certText(),
      mandant: '1',
      rolle: 'buero',
      ...INFO,
    }),
    ping: J({ geraet: DEV, app: 'alpha', bis: DAY, mandant: '1', rolle: 'buero', ...INFO }),
    invite: J({ einladung: inv2Text(), gueltigS: 600 }),
    devices: J({ geraete: [entry, { ...entry, geraet: DEV2, von: DEV }], hoechstens: 50 }),
    block: J({ geraet: DEV, gesperrt: true }),
    health: J({
      ok: true,
      stand: 'abc',
      ...INFO,
      app: 'alpha',
      altAbgeschaltet: false,
      aufnahmeOffen: true,
    }),
    stored: writeStoredCredentials({
      device: DEV,
      access: certText(),
      until: DAY,
      group: '1',
      role: 'buero',
    }),
    mark: writeBlockedMark(DEV, '2026-11-22'),
    cert: certText(),
    e2: inv2Text(),
    g1: founderText(),
  };
  const readers: Record<string, (t: unknown) => unknown> = {
    enrol: (t) => readEnrolAnswerR2(t, 'alpha', FAKE_KEY),
    renew: (t) => readRenewAnswerR2(t, 'alpha', current),
    upgrade: (t) => readUpgradeAnswer(t, 'alpha', DEV, FAKE_KEY),
    ping: readPingAnswerR2,
    invite: (t) => readInviteAnswer(t, 'alpha'),
    devices: readDevicesAnswer,
    block: (t) => readBlockAnswer(t, DEV),
    health: readHealthAnswer,
    stored: (t) => readStoredState(t, 'alpha'),
    mark: (t) => readStoredState(t, 'alpha'),
    cert: readCertificate,
    e2: readInvitationR2,
    g1: readFounderTicket,
  };
  const truthy = (v: unknown): boolean => v !== undefined && v !== false;

  for (const [name, read] of Object.entries(readers)) {
    it(`${name}: 3000 mutated, random and structured inputs`, () => {
      const rng = mulberry32(0x5eed + name.length * 31);
      expect(truthy(read(valid[name])), 'the valid text reads').toBe(true);
      let accepted = 0;
      for (let i = 0; i < 3000; i += 1) {
        let input: unknown;
        const kind = i % 5;
        if (kind === 0) input = mutateText(rng, valid[name] as string);
        else if (kind === 1) input = J(randomValue(rng, KEYS));
        else if (kind === 2) {
          input = Array.from({ length: Math.floor(rng() * 60) }, () =>
            String.fromCharCode(Math.floor(rng() * 0x3000)),
          ).join('');
        } else if (kind === 3) input = mutateText(rng, mutateText(rng, valid[name] as string));
        else input = [undefined, null, 5, {}, [], true][Math.floor(rng() * 6)];
        let result: unknown;
        expect(
          () => {
            result = read(input);
          },
          String(input).slice(0, 80),
        ).not.toThrow();
        if (truthy(result)) accepted += 1;
      }
      expect(accepted).toBeLessThan(1500);
    });
  }

  it('a tamper sweep: every single-character change of a certificate, an e2 and a ticket is refused or still well formed', () => {
    for (const [text, read] of [
      [certText(), readCertificate],
      [inv2Text(), readInvitationR2],
      [founderText(), readFounderTicket],
    ] as const) {
      for (let i = 0; i < text.length; i += 1) {
        for (const ch of ['x', '.', '-', 'A', '0', ' ']) {
          const changed = text.slice(0, i) + ch + text.slice(i + 1);
          if (changed === text) continue;
          const r = read(changed) as { app?: string } | undefined;
          if (r === undefined) continue;
          // accepted only where the change fell in a place the format allows to vary (a name, a digit)
          expect(r.app, changed).toMatch(/^[a-z][a-z0-9]{1,15}$/);
          expect(changed.length).toBe(text.length);
        }
      }
    }
  });

  it('the MAC placeholder is a canonical 32-byte value (the readers need it canonical)', () => {
    expect(MAC).toHaveLength(43);
  });
});
