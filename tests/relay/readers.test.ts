import { describe, expect, it } from 'vitest';
import {
  RELAY_DEVICE_ID,
  MAX_COLLECT_TEXT,
  RELAY_LIMITS,
  readAccess,
  readCollectAnswer,
  readDropAnswer,
  readEnrolAnswer,
  readErrorBody,
  readHealthAnswer,
  readInvitation,
  readInviteAnswer,
  readPingAnswer,
  readRenewAnswer,
  readRingAnswer,
  readStoredCredentials,
  writeStoredCredentials,
} from '../../src/relay/index.ts';
import { mulberry32 } from './helpers.ts';

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
const MAC = b64(new Uint8Array(32).fill(7));
const DEV = `geraet-${'ab12'.repeat(8)}`;
const DEV2 = `geraet-${'cd34'.repeat(8)}`;
const access = (app = 'alpha', device = DEV, end = 1802476800): string =>
  `z1.${app}.${device}.${end}.${MAC}`;
const INVITATION = `e1.alpha.1802476800.${b64(new Uint8Array(16).fill(3))}.${MAC}`;
const J = JSON.stringify;

const enrol = { geraet: DEV, zugang: access(), bis: '2027-02-13' };

describe('strict readers: the exact shapes', () => {
  it('enrol', () => {
    expect(readEnrolAnswer(J(enrol), 'alpha')).toEqual({
      device: DEV,
      access: access(),
      until: '2027-02-13',
    });
    expect(readEnrolAnswer(J({ ...enrol, extra: 1 }), 'alpha')).toBeUndefined();
    expect(readEnrolAnswer(J({ geraet: DEV, zugang: access() }), 'alpha')).toBeUndefined();
    expect(readEnrolAnswer(J(enrol), 'beta')).toBeUndefined(); // the access names another app
    expect(readEnrolAnswer(J({ ...enrol, geraet: DEV2 }), 'alpha')).toBeUndefined(); // another device
    expect(readEnrolAnswer(J({ ...enrol, bis: '2027-02-30' }), 'alpha')).toBeUndefined(); // no such day
    expect(readEnrolAnswer(J({ ...enrol, bis: '2027-2-3' }), 'alpha')).toBeUndefined();
    expect(readEnrolAnswer(J({ ...enrol, zugang: `${access()}x` }), 'alpha')).toBeUndefined();
  });

  it('a MAC that is not canonical base64url is refused', () => {
    // The last character of 43 carries only 4 bits: "B" has non-zero unused bits.
    const bad = `z1.alpha.${DEV}.1802476800.${MAC.slice(0, 42)}B`;
    expect(readAccess(bad)).toBeUndefined();
    expect(readAccess(access())).toEqual({ app: 'alpha', device: DEV, endS: 1802476800 });
    expect(readAccess(`z1.alpha.${DEV}.0123.${MAC}`)).toBeUndefined(); // leading zero
    expect(readAccess(`z1.alpha.${DEV}.1234567890123.${MAC}`)).toBeUndefined(); // 13 digits
  });

  it('renew, ping, invite, ring, error body', () => {
    expect(readRenewAnswer(J({ zugang: access(), bis: '2027-05-01' }), 'alpha', DEV)).toEqual({
      access: access(),
      until: '2027-05-01',
    });
    expect(
      readRenewAnswer(J({ zugang: access(), bis: '2027-05-01' }), 'alpha', DEV2),
    ).toBeUndefined();
    expect(readPingAnswer(J({ geraet: DEV, app: 'alpha', bis: '2027-05-01' }))).toEqual({
      device: DEV,
      app: 'alpha',
      until: '2027-05-01',
    });
    expect(readPingAnswer(J({ geraet: DEV, app: 'Alpha', bis: '2027-05-01' }))).toBeUndefined();
    expect(
      readPingAnswer(J({ geraet: DEV, app: 'alpha', bis: '2027-05-01', v: 2 })),
    ).toBeUndefined();
    expect(readInviteAnswer(J({ einladung: INVITATION, gueltigS: 600 }), 'alpha')).toEqual({
      invitation: INVITATION,
      validForS: 600,
    });
    expect(readInviteAnswer(J({ einladung: INVITATION, gueltigS: 0 }), 'alpha')).toBeUndefined();
    expect(readInviteAnswer(J({ einladung: INVITATION, gueltigS: 600 }), 'beta')).toBeUndefined();
    expect(readInvitation(INVITATION)).toEqual({ app: 'alpha' });
    expect(readRingAnswer(J({ dienst: 201, ms: 4 }))).toEqual({ service: 201, ms: 4 });
    expect(readRingAnswer(J({ dienst: 99, ms: 4 }))).toBeUndefined();
    expect(readErrorBody(J({ fehler: 'x', art: 'unlesbar' }))).toEqual({ token: 'unlesbar' });
    expect(readErrorBody(J({ fehler: 'x'.repeat(201), art: 'unlesbar' }))).toBeUndefined();
    expect(readErrorBody(J({ fehler: 'x', art: 'Unlesbar' }))).toBeUndefined();
    expect(readErrorBody(J({ fehler: 'x', art: 'unlesbar', extra: 1 }))).toBeUndefined();
  });

  it('health: ok and stand required, revision members optional, nothing else', () => {
    expect(readHealthAnswer(J({ ok: true, stand: 'abc' }))).toEqual({ commit: 'abc' });
    expect(readHealthAnswer(J({ ok: false, stand: 'abc' }))).toBeUndefined();
    expect(readHealthAnswer(J({ ok: true, stand: 'abc', x: 1 }))).toBeUndefined();
    const full = {
      ok: true,
      stand: 'abc',
      v: 2,
      faehigkeiten: ['mandant', 'zertifikat'],
      verfahren: { angeboten: ['zugang'], bevorzugt: 'zertifikat', einschreiben: ['nachweis'] },
      app: 'alpha',
      altAbgeschaltet: false,
      aufnahmeOffen: true,
    };
    expect(readHealthAnswer(J(full))).toMatchObject({ commit: 'abc', revision: 2, app: 'alpha' });
    expect(readHealthAnswer(J({ ...full, faehigkeiten: Array(21).fill('a') }))).toBeUndefined();
    expect(readHealthAnswer(J({ ...full, verfahren: { angeboten: [] } }))).toBeUndefined();
  });

  it('drop: one result per recipient, in the order asked, naming each', () => {
    const asked = [DEV, DEV2];
    const good = {
      ergebnisse: [
        { geraet: DEV, ok: true, anwesend: false },
        { geraet: DEV2, ok: false, art: 'empfaenger-voll', fehler: 'full' },
      ],
    };
    expect(readDropAnswer(J(good), asked)).toEqual([
      { device: DEV, ok: true, present: false },
      { device: DEV2, ok: false, token: 'empfaenger-voll' },
    ]);
    expect(readDropAnswer(J(good), [DEV2, DEV])).toBeUndefined(); // wrong order
    expect(readDropAnswer(J(good), [DEV])).toBeUndefined(); // wrong length
    const extra = J({ ergebnisse: [{ geraet: DEV, ok: true, anwesend: false, x: 1 }] });
    expect(readDropAnswer(extra, [DEV])).toBeUndefined();
    expect(readDropAnswer(J({ ergebnisse: [{ geraet: DEV, ok: 'yes' }] }), [DEV])).toBeUndefined();
    // An unknown refusal word is kept as its token (the caller treats it as "not stored").
    const unknown = J({ ergebnisse: [{ geraet: DEV, ok: false, art: 'neu-grund', fehler: 'x' }] });
    expect(readDropAnswer(unknown, [DEV])).toEqual([
      { device: DEV, ok: false, token: 'neu-grund' },
    ]);
  });

  it('collect: messages in order, canonical content, only asked ids, bounded', () => {
    const msg = (von: string, content: Uint8Array, ageMs = 5): object => ({
      von,
      inhalt: b64(content),
      alterMs: ageMs,
    });
    const ok = J({
      nachrichten: [msg(DEV, new Uint8Array([1, 2, 3])), msg(DEV2, new Uint8Array([9]))],
      anwesend: [DEV2],
      mehr: true,
    });
    const r = readCollectAnswer(ok, [DEV2]);
    expect(r?.more).toBe(true);
    expect(r?.present).toEqual([DEV2]);
    expect(r?.messages.map((m) => [...m.content])).toEqual([[1, 2, 3], [9]]);
    expect(r?.messages.map((m) => m.from)).toEqual([DEV, DEV2]);
    // the contents are fresh copies: changing one read does not change the next
    const again = readCollectAnswer(ok, [DEV2]);
    (r!.messages[0]!.content as Uint8Array)[0] = 99;
    expect(again!.messages[0]!.content[0]).toBe(1);
    // present holds only asked ids
    expect(readCollectAnswer(ok, [])).toBeUndefined();
    // age over 30 s, empty content, padded content, 101 messages
    expect(
      readCollectAnswer(
        J({ nachrichten: [msg(DEV, new Uint8Array([1]), 30_001)], anwesend: [], mehr: false }),
        [],
      ),
    ).toBeUndefined();
    expect(
      readCollectAnswer(
        J({ nachrichten: [{ von: DEV, inhalt: '', alterMs: 1 }], anwesend: [], mehr: false }),
        [],
      ),
    ).toBeUndefined();
    expect(
      readCollectAnswer(
        J({ nachrichten: [{ von: DEV, inhalt: 'AQ==', alterMs: 1 }], anwesend: [], mehr: false }),
        [],
      ),
    ).toBeUndefined();
    const many = Array.from({ length: 101 }, () => msg(DEV, new Uint8Array([1])));
    expect(
      readCollectAnswer(J({ nachrichten: many, anwesend: [], mehr: false }), []),
    ).toBeUndefined();
    expect(
      readCollectAnswer(J({ nachrichten: many.slice(0, 100), anwesend: [], mehr: false }), []),
    ).toBeDefined();
  });

  it('collect: total content over 2 MiB and a message over 64 KB are refused', () => {
    const big = (n: number): object => ({ von: DEV, inhalt: b64(new Uint8Array(n)), alterMs: 1 });
    const text = (list: object[]): string => J({ nachrichten: list, anwesend: [], mehr: false });
    expect(readCollectAnswer(text([big(RELAY_LIMITS.maxContentBytes)]), [])).toBeDefined();
    expect(readCollectAnswer(text([big(RELAY_LIMITS.maxContentBytes + 1)]), [])).toBeUndefined();
    const full = Array.from({ length: 32 }, () => big(RELAY_LIMITS.maxContentBytes)); // exactly 2 MiB
    expect(readCollectAnswer(text(full), [])).toBeDefined();
    expect(readCollectAnswer(text([...full, big(1)]), [])).toBeUndefined();
    expect(MAX_COLLECT_TEXT).toBeGreaterThan(2_796_203);
    expect(readCollectAnswer('x'.repeat(MAX_COLLECT_TEXT + 1), [])).toBeUndefined();
  });

  it('presence: duplicates, own unknown ids and more than asked are refused', () => {
    const base = (anwesend: string[]): string => J({ nachrichten: [], anwesend, mehr: false });
    expect(readCollectAnswer(base([DEV, DEV]), [DEV, DEV2])).toBeUndefined();
    expect(readCollectAnswer(base([DEV]), [DEV2])).toBeUndefined();
    expect(readCollectAnswer(base([DEV, DEV2]), [DEV])).toBeUndefined();
    expect(readCollectAnswer(base([]), [])).toEqual({ messages: [], present: [], more: false });
  });

  it('duplicate keys, prototype keys and non-objects are refused everywhere', () => {
    expect(
      readPingAnswer(`{"geraet":"${DEV}","app":"alpha","bis":"2027-05-01","app":"beta"}`),
    ).toBeUndefined();
    expect(
      readPingAnswer(`{"__proto__":{"x":1},"geraet":"${DEV}","app":"alpha","bis":"2027-05-01"}`),
    ).toBeUndefined();
    expect(
      readPingAnswer(`{"constructor":1,"geraet":"${DEV}","app":"alpha","bis":"2027-05-01"}`),
    ).toBeUndefined();
    for (const text of ['null', '[]', '1', '"x"', 'true', '', '{', '{"a":}']) {
      expect(readPingAnswer(text)).toBeUndefined();
      expect(readCollectAnswer(text, [])).toBeUndefined();
      expect(readErrorBody(text)).toBeUndefined();
    }
    for (const notText of [undefined, null, 5, {}, [], Symbol.iterator]) {
      expect(readPingAnswer(notText)).toBeUndefined();
      expect(readEnrolAnswer(notText, 'alpha')).toBeUndefined();
    }
  });

  it('stored credentials round trip and are read strictly', () => {
    const c = { device: DEV, access: access(), until: '2027-02-13' };
    expect(readStoredCredentials(writeStoredCredentials(c), 'alpha')).toEqual(c);
    expect(readStoredCredentials(writeStoredCredentials(c), 'beta')).toBeUndefined();
    expect(readStoredCredentials(J({ v: 2, ...c }), 'alpha')).toBeUndefined();
    expect(readStoredCredentials(J({ v: 1, ...c, extra: 1 }), 'alpha')).toBeUndefined();
    expect(readStoredCredentials('{', 'alpha')).toBeUndefined();
  });

  it('RELAY_DEVICE_ID is one spelling', () => {
    expect(RELAY_DEVICE_ID.test(DEV)).toBe(true);
    expect(RELAY_DEVICE_ID.test(DEV.toUpperCase())).toBe(false);
    expect(RELAY_DEVICE_ID.test(`${DEV}\n`)).toBe(false);
  });
});

// ── fuzzing with a seeded generator: never throws, and anything accepted is well formed ───────────

function mutateText(rng: () => number, text: string): string {
  const n = 1 + Math.floor(rng() * 4);
  let s = text;
  for (let i = 0; i < n; i += 1) {
    const at = Math.floor(rng() * (s.length + 1));
    switch (Math.floor(rng() * 6)) {
      case 0:
        s = s.slice(0, at) + s.slice(at + 1);
        break;
      case 1:
        s = s.slice(0, at) + String.fromCharCode(32 + Math.floor(rng() * 95)) + s.slice(at);
        break;
      case 2:
        s = s.slice(0, at);
        break;
      case 3:
        s = s.slice(0, at) + '"extra":1,' + s.slice(at);
        break;
      case 4:
        s = s.replace(/"([a-zA-Z]+)":/, '"__proto__":');
        break;
      default:
        s = s.replace(
          /true|false|null|\d+/,
          ['null', '"x"', '[]', '{}', '-1', '1e400'][Math.floor(rng() * 6)] as string,
        );
    }
  }
  return s;
}

const randomValue = (rng: () => number, depth = 0): unknown => {
  const k = Math.floor(rng() * (depth > 2 ? 5 : 7));
  if (k === 0) return null;
  if (k === 1) return rng() < 0.5;
  if (k === 2) return Math.floor(rng() * 4000) - 1000;
  if (k === 3)
    return ['', 'x', DEV, access(), 'unlesbar', '2027-01-01', 'AQ'][Math.floor(rng() * 7)];
  if (k === 4) return rng().toString(36);
  if (k === 5)
    return Array.from({ length: Math.floor(rng() * 4) }, () => randomValue(rng, depth + 1));
  const o: Record<string, unknown> = {};
  for (const key of [
    'geraet',
    'zugang',
    'bis',
    'nachrichten',
    'anwesend',
    'mehr',
    'ergebnisse',
    'art',
    'fehler',
    'ok',
    'dienst',
    'ms',
    'stand',
    'von',
    'inhalt',
    'alterMs',
  ]) {
    if (rng() < 0.3) o[key] = randomValue(rng, depth + 1);
  }
  return o;
};

describe('strict readers: seeded fuzzing, never throws', () => {
  const valid: Record<string, string> = {
    enrol: J(enrol),
    renew: J({ zugang: access(), bis: '2027-05-01' }),
    ping: J({ geraet: DEV, app: 'alpha', bis: '2027-05-01' }),
    invite: J({ einladung: INVITATION, gueltigS: 600 }),
    drop: J({
      ergebnisse: [
        { geraet: DEV, ok: true, anwesend: true },
        { geraet: DEV2, ok: false, art: 'voll', fehler: 'x' },
      ],
    }),
    collect: J({
      nachrichten: [{ von: DEV, inhalt: 'AQID', alterMs: 12 }],
      anwesend: [DEV2],
      mehr: false,
    }),
    ring: J({ dienst: 201, ms: 3 }),
    error: J({ fehler: 'Text', art: 'unlesbar' }),
    health: J({ ok: true, stand: 'abc', v: 2 }),
    stored: writeStoredCredentials({ device: DEV, access: access(), until: '2027-02-13' }),
  };
  const readers: Record<string, (text: unknown) => unknown> = {
    enrol: (t) => readEnrolAnswer(t, 'alpha'),
    renew: (t) => readRenewAnswer(t, 'alpha', DEV),
    ping: readPingAnswer,
    invite: (t) => readInviteAnswer(t, 'alpha'),
    drop: (t) => readDropAnswer(t, [DEV, DEV2]),
    collect: (t) => readCollectAnswer(t, [DEV2, DEV]),
    ring: readRingAnswer,
    error: readErrorBody,
    health: readHealthAnswer,
    stored: (t) => readStoredCredentials(t, 'alpha'),
  };

  for (const [name, read] of Object.entries(readers)) {
    it(`${name}: 3500 mutated, random and structured inputs`, () => {
      const rng = mulberry32(0xc0ffee + name.length);
      expect(read(valid[name])).toBeDefined();
      let accepted = 0;
      for (let i = 0; i < 3500; i += 1) {
        let input: unknown;
        const kind = i % 4;
        if (kind === 0) input = mutateText(rng, valid[name] as string);
        else if (kind === 1) input = J(randomValue(rng));
        else if (kind === 2)
          input = Array.from({ length: Math.floor(rng() * 60) }, () =>
            String.fromCharCode(Math.floor(rng() * 0x3000)),
          ).join('');
        else input = mutateText(rng, mutateText(rng, valid[name] as string));
        let result: unknown;
        expect(
          () => {
            result = read(input);
          },
          String(input).slice(0, 80),
        ).not.toThrow();
        if (result !== undefined) accepted += 1;
      }
      // Mutations of a valid text sometimes still are valid (a changed padding space, say); not most.
      expect(accepted).toBeLessThan(1500);
    });
  }

  it('anything the collect reader accepts is within the documented bounds', () => {
    const rng = mulberry32(99);
    for (let i = 0; i < 3000; i += 1) {
      const text = mutateText(rng, valid['collect'] as string);
      const r = readCollectAnswer(text, [DEV2]);
      if (!r) continue;
      expect(r.messages.length).toBeLessThanOrEqual(RELAY_LIMITS.mailboxMessages);
      for (const m of r.messages) {
        expect(RELAY_DEVICE_ID.test(m.from)).toBe(true);
        expect(m.content.length).toBeGreaterThanOrEqual(1);
        expect(m.ageMs).toBeLessThanOrEqual(RELAY_LIMITS.waitMs);
      }
      for (const p of r.present) expect(p).toBe(DEV2);
    }
  });
});
