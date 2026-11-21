import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  MEETING_AHEAD_MS,
  MEETING_RENEW_MS,
  MEETING_VALID_MS,
  checkMeetingCode,
  meetingSigningText,
  parseMeetingCode,
  signMeetingCode,
  type MeetingCode,
} from '../../src/trust/index.ts';
import { APP, dev, type Dev } from './helpers.ts';

const NOW = 1_800_000_000_000;
const P = { appId: APP };
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

let c: Dev;
let bytes: Uint8Array;
let code: MeetingCode;
beforeAll(async () => {
  c = await dev('Phone C');
  bytes = await signMeetingCode(P, c.intro, 'member', NOW, c.keys.signing.privateKey);
  code = parseMeetingCode(P, bytes) as MeetingCode;
});

const accepted = async (b: Uint8Array, now = NOW, o = P) => {
  const parsed = parseMeetingCode(o, b);
  return !!parsed && (await checkMeetingCode(o, parsed, now)).ok;
};

describe('meeting code', () => {
  it('constants are the documented ones', () => {
    expect([MEETING_VALID_MS, MEETING_RENEW_MS, MEETING_AHEAD_MS]).toEqual([
      120_000, 30_000, 60_000,
    ]);
  });

  it('travels, is read strictly and is taken now', async () => {
    expect(code).toMatchObject({ introduction: c.intro, role: 'member', time: NOW });
    expect(code.private).toBeUndefined();
    expect(await checkMeetingCode(P, code, NOW + 1000)).toEqual({ ok: true });
    // the bytes are compact JSON with the members in this order
    expect(dec(bytes).startsWith('{"m":"syncdemo-meeting:2","device":"')).toBe(true);
    expect(Object.keys(JSON.parse(dec(bytes)))).toEqual([
      'm',
      'device',
      'name',
      'sig',
      'dh',
      'role',
      'time',
      'proof',
    ]);
  });

  it('the private flag is carried and signed', async () => {
    const b = await signMeetingCode(P, c.intro, 'member', NOW, c.keys.signing.privateKey, true);
    const p = parseMeetingCode(P, b) as MeetingCode;
    expect(p.private).toBe(true);
    expect((await checkMeetingCode(P, p, NOW)).ok).toBe(true);
    // dropping or adding the flag after signing breaks the signature
    const { private: _p, ...without } = p;
    expect(await checkMeetingCode(P, without as MeetingCode, NOW)).toEqual({
      ok: false,
      reason: 'changed',
    });
    expect((await checkMeetingCode(P, { ...code, private: true }, NOW)).ok).toBe(false);
    // a role that may not be private
    const only = { appId: APP, valid: { privateRoles: (r: string) => r !== 'member' } };
    expect(parseMeetingCode(only, b)).toBeUndefined();
    await expect(
      signMeetingCode(only, c.intro, 'member', NOW, c.keys.signing.privateKey, true),
    ).rejects.toThrow();
  });

  it('the signing text is exactly this', () => {
    expect(meetingSigningText('demo', c.intro, 'member', 5, false)).toBe(
      `demo-meeting:2|${c.id}|Phone C|${c.intro.sig}|${c.intro.dh}|member|5|0`,
    );
    expect(meetingSigningText('demo', c.intro, 'member', 5, true).endsWith('|5|1')).toBe(true);
  });

  describe('validity window (boundaries)', () => {
    it.each([
      ['exactly valid for 120 000 ms', NOW + MEETING_VALID_MS, true],
      ['one ms over', NOW + MEETING_VALID_MS + 1, false],
      ['same instant', NOW, true],
      ['look-ahead exactly 60 000 ms', NOW - MEETING_AHEAD_MS, true],
      ['look-ahead one ms over', NOW - MEETING_AHEAD_MS - 1, false],
    ])('%s', async (_label, now, good) => {
      expect((await checkMeetingCode(P, code, now)).ok).toBe(good);
    });

    it('the reasons say which side', async () => {
      expect(await checkMeetingCode(P, code, NOW + MEETING_VALID_MS + 1)).toEqual({
        ok: false,
        reason: 'expired',
      });
      expect(await checkMeetingCode(P, code, NOW - MEETING_AHEAD_MS - 1)).toEqual({
        ok: false,
        reason: 'ahead',
      });
    });
  });

  it('time is mandatory; role is mandatory; a code of another kind or app is nothing', () => {
    const o = JSON.parse(dec(bytes));
    for (const member of ['time', 'role', 'proof', 'name', 'sig', 'dh', 'device', 'm']) {
      const { [member]: _gone, ...rest } = o;
      expect(parseMeetingCode(P, enc(rest))).toBeUndefined();
    }
    expect(parseMeetingCode({ appId: 'otherapp' }, bytes)).toBeUndefined();
    expect(parseMeetingCode(P, enc({ ...o, m: 'syncdemo-invite:2' }))).toBeUndefined();
    expect(parseMeetingCode(P, enc({ ...o, m: 'syncdemo-meeting:1' }))).toBeUndefined();
  });

  it('values must be exactly right: ids, names, keys, role, time, proof, flag', () => {
    const o = JSON.parse(dec(bytes));
    const bad: Record<string, unknown[]> = {
      device: ['device-xyz', 5, null, 'device-' + 'A'.repeat(32)],
      name: ['a\u0007b', '', 'x'.repeat(41), 'a|b', 5],
      sig: [o.dh, 'x'.repeat(87), 5],
      dh: [o.sig, 'x'.repeat(87)],
      role: ['Admin', '', 'a b', 'a|b', 5, 'x'.repeat(81)],
      time: [-1, 1.5, '1', 2 ** 53, null, NaN],
      proof: ['x'.repeat(86), 'A'.repeat(85), 5, o.proof + 'A'],
      private: [false, 1, 'true', null],
    };
    for (const [member, values] of Object.entries(bad)) {
      for (const v of values) {
        expect(
          parseMeetingCode(P, enc({ ...o, [member]: v })),
          `${member}=${String(v)}`,
        ).toBeUndefined();
      }
    }
  });

  it('one spelling only: other order, spaces, duplicate members, escapes, trailing bytes', () => {
    const text = dec(bytes);
    const o = JSON.parse(text);
    const { m, ...rest } = o;
    expect(parseMeetingCode(P, enc({ ...rest, m }))).toBeUndefined(); // other order
    expect(
      parseMeetingCode(P, new TextEncoder().encode(JSON.stringify(o, null, 1))),
    ).toBeUndefined();
    expect(
      parseMeetingCode(P, new TextEncoder().encode(text.replace('{"m"', '{"m":"x","m"'))),
    ).toBeUndefined();
    expect(parseMeetingCode(P, new TextEncoder().encode(text + ' '))).toBeUndefined();
    expect(
      parseMeetingCode(P, new TextEncoder().encode(text.replace('Phone C', 'Phone\\u0020C'))),
    ).toBeUndefined();
    expect(parseMeetingCode(P, new Uint8Array([0xff, 0xfe]))).toBeUndefined();
    expect(parseMeetingCode(P, new Uint8Array(3000))).toBeUndefined();
    expect(parseMeetingCode(P, 'text' as never)).toBeUndefined();
  });

  describe('tamper sweep (never accepted)', () => {
    const fields = ['device', 'name', 'sig', 'dh', 'role', 'time', 'proof', 'm'];

    it('every field changed, deleted or added, one at a time', async () => {
      const o = JSON.parse(dec(bytes));
      const flip = (v: unknown): unknown =>
        typeof v === 'number'
          ? v + 1
          : typeof v === 'string'
            ? v.at(-1) === 'A'
              ? v.slice(0, -1) + 'B'
              : v.slice(0, -1) + 'A'
            : v;
      const cases: [string, unknown][] = [];
      for (const f of fields) {
        cases.push([`flip ${f}`, { ...o, [f]: flip(o[f]) }]);
        const { [f]: _gone, ...rest } = o;
        cases.push([`delete ${f}`, rest]);
        cases.push([`double ${f}`, { ...o, [`${f}2`]: o[f] }]);
      }
      cases.push(['add private', { ...o, private: true }]);
      cases.push(['add unknown', { ...o, extra: 1 }]);
      for (const [label, value] of cases) {
        expect(await accepted(enc(value)), label).toBe(false);
      }
      // the untouched code is accepted, so the table above is not vacuous
      expect(await accepted(bytes)).toBe(true);
    });

    it('every single byte altered, one at a time', async () => {
      let accepted_ = 0;
      for (let i = 0; i < bytes.length; i++) {
        for (const x of [1, 0x20]) {
          const copy = new Uint8Array(bytes);
          copy[i] = (copy[i] as number) ^ x;
          if (await accepted(copy)) accepted_++;
        }
      }
      expect(accepted_).toBe(0);
    });

    it('role, time and device swapped for another valid one: the signature no longer fits', async () => {
      const o = JSON.parse(dec(bytes));
      for (const changed of [{ role: 'admin' }, { time: NOW + 1 }, { name: 'Other' }]) {
        expect(await accepted(enc({ ...o, ...changed }), NOW + 5)).toBe(false);
      }
      const d = await dev('Other');
      expect(await accepted(enc({ ...o, device: d.id }))).toBe(false); // the device id is signed too
    });

    it('signed by another device key: refused; a copy for another app: refused', async () => {
      const other = (await generateDeviceKeys()).signing.privateKey;
      const forged = await signMeetingCode(P, c.intro, 'member', NOW, other);
      expect(await accepted(forged)).toBe(false);
      expect(await accepted(bytes, NOW, { appId: 'otherapp' })).toBe(false);
      const foreign = await signMeetingCode(
        { appId: 'otherapp' },
        c.intro,
        'member',
        NOW,
        c.keys.signing.privateKey,
      );
      expect(await accepted(foreign)).toBe(false);
      expect(await accepted(foreign, NOW, { appId: 'otherapp' })).toBe(true);
    });

    it('signed under the text of another kind (an invitation proof text) is no meeting code', async () => {
      const sig = await (
        await import('../../src/core/index.ts')
      ).signText(
        c.keys.signing.privateKey,
        `syncdemo-invite:2|${c.id}|member|${c.id}|${c.intro.name}|${c.intro.sig}|${c.intro.dh}`,
      );
      const o = JSON.parse(dec(bytes));
      expect(await accepted(enc({ ...o, proof: sig }))).toBe(false);
    });
  });

  it('signing refuses input that could never be read back', async () => {
    const key = c.keys.signing.privateKey;
    await expect(
      signMeetingCode(P, { ...c.intro, device: 'x' }, 'member', NOW, key),
    ).rejects.toThrow();
    await expect(signMeetingCode(P, c.intro, 'Bad Role', NOW, key)).rejects.toThrow();
    await expect(signMeetingCode(P, c.intro, 'member', -1, key)).rejects.toThrow();
  });
});
