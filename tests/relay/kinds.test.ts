import { describe, expect, it } from 'vitest';
import {
  DROP_REFUSAL_TOKENS,
  LOCAL_KINDS,
  RELAY_KINDS,
  kindOfToken,
} from '../../src/relay/index.ts';

describe('the error-kind table', () => {
  it('has unique tokens and unique names, and well-formed rows', () => {
    expect(new Set(RELAY_KINDS.map((k) => k.token)).size).toBe(RELAY_KINDS.length);
    expect(new Set(RELAY_KINDS.map((k) => k.name)).size).toBe(RELAY_KINDS.length);
    for (const k of RELAY_KINDS) {
      expect(k.token, k.token).toMatch(/^[a-z][a-z-]{1,39}$/);
      expect(k.name, k.name).toMatch(/^[a-z][a-z-]+$/);
      expect(k.status === null || (k.status >= 400 && k.status <= 599), k.token).toBe(true);
    }
  });

  it('every retry kind has a delay hint, no fatal kind has one that invites a retry loop', () => {
    for (const k of RELAY_KINDS) {
      if (k.class === 'retry') expect(k.retryAfterMs, k.token).toBeGreaterThanOrEqual(250);
      if (k.class === 'fatal' || k.class === 'reenrol') expect(k.retryAfterMs, k.token).toBeNull();
    }
  });

  it('the classes of the kinds a client must act on', () => {
    const cls = (t: string): string | undefined => kindOfToken(t)?.class;
    expect(cls('zugang-abgelaufen')).toBe('reenrol');
    expect(cls('zugang-ungueltig')).toBe('reenrol');
    expect(cls('zu-viele-anfragen')).toBe('retry');
    expect(cls('gesperrt')).toBe('fatal');
    expect(cls('verbraucht')).toBe('fatal');
    expect(cls('empfaenger-voll')).toBe('refused');
  });

  it('looks a kind up by token and refuses what is not a known token', () => {
    expect(kindOfToken('unlesbar')?.status).toBe(400);
    for (const bad of [
      '',
      'UNLESBAR',
      '__proto__',
      'constructor',
      'toString',
      5,
      null,
      undefined,
      {},
    ]) {
      expect(kindOfToken(bad)).toBeUndefined();
    }
  });

  it('the refusals of one recipient are exactly the four without a status', () => {
    expect([...DROP_REFUSAL_TOKENS].sort()).toEqual([
      'absender-voll',
      'app-voll',
      'empfaenger-voll',
      'voll',
    ]);
  });

  it('local kinds have a class and never a token of the relay', () => {
    for (const [name, v] of Object.entries(LOCAL_KINDS)) {
      expect(['fatal', 'retry', 'reenrol']).toContain(v.class);
      expect(kindOfToken(name) === undefined || name === 'storage').toBe(true);
    }
  });
});

describe('refusals told apart: blocked is not expired, not "new version needed", not the clock', () => {
  const cls = (t: string) => kindOfToken(t);

  it('each kind has its own class; only the expired and invalid access mean "enrol anew"', () => {
    expect(cls('gesperrt')).toMatchObject({ name: 'device-blocked', status: 403, class: 'fatal' });
    expect(cls('neue-fassung-noetig')).toMatchObject({
      name: 'client-update-needed',
      status: 426,
      class: 'fatal',
    });
    expect(cls('zugang-abgelaufen')?.class).toBe('reenrol');
    expect(cls('zugang-ungueltig')?.class).toBe('reenrol');
    expect(cls('besitz-zeit')).toMatchObject({
      name: 'possession-time',
      status: 401,
      class: 'fatal',
    });
    const enrolAnew = RELAY_KINDS.filter((k) => k.class === 'reenrol').map((k) => k.token);
    expect(enrolAnew.sort()).toEqual(['zugang-abgelaufen', 'zugang-ungueltig']);
    expect(LOCAL_KINDS['no-credentials'].class).toBe('reenrol');
    expect(LOCAL_KINDS['key-missing'].class).toBe('reenrol');
    expect(LOCAL_KINDS['blocked-mark'].class).toBe('fatal');
  });

  it('a full relay or a closed intake says so (the device is not blocked) and does not mean "enrol anew"', () => {
    expect(cls('aufnahme-geschlossen')).toMatchObject({ name: 'admission-closed', class: 'fatal' });
    expect(cls('relay-voll')).toMatchObject({ name: 'relay-full', status: 503, class: 'refused' });
    expect(cls('geraete-voll')?.class).toBe('refused');
    expect(cls('sperrliste-voll')).toMatchObject({ status: 503, class: 'refused' });
    for (const t of ['aufnahme-geschlossen', 'relay-voll', 'geraete-voll', 'sperrliste-voll']) {
      expect(cls(t)?.class).not.toBe('reenrol');
      expect(cls(t)?.name).not.toBe('device-blocked');
    }
  });

  it('the proof of possession, the role and the developer ways have their own wire words', () => {
    for (const [token, name, status] of [
      ['besitz-fehlt', 'possession-missing', 401],
      ['besitz-ungueltig', 'possession-invalid', 401],
      ['rolle-nicht-erlaubt', 'role-not-allowed', 403],
      ['geraet-unbekannt', 'device-unknown', 404],
      ['entwickler-nicht-eingerichtet', 'developer-not-set-up', 403],
      ['entwickler-ungueltig', 'developer-invalid', 403],
      ['entwickler-abgelaufen', 'developer-expired', 403],
      ['entwickler-belegt', 'developer-group-taken', 403],
    ] as const) {
      expect(cls(token), token).toMatchObject({ name, status, class: 'fatal' });
    }
  });

  it("the wire word of one relay's product is not in the table (open point 9)", () => {
    for (const k of RELAY_KINDS) expect(k.token).not.toMatch(/punkt/);
  });
});
