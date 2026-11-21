// Seeded fuzzing of the strict parsers: never throws, and what is accepted is structurally valid,
// has exactly one spelling and shares nothing with the input or with a second reading.
import { beforeAll, describe, expect, it } from 'vitest';
import { base64url, fromBase64url } from '../../src/core/index.ts';
import {
  DEVICE_ID,
  createInvitation,
  invitationLink,
  invitationProof,
  parseIntroduction,
  parseInvitation,
  parseKnownList,
  parseMeetingCode,
  parseOpenInvitation,
  parseReply,
  replyText,
  resolveValidators,
  signMeetingCode,
  vouchAll,
  type DeviceEntry,
} from '../../src/trust/index.ts';
import { APP, dev, prng } from './helpers.ts';

const N = 3500;
const NOW = 1_800_000_000_000;
const P = { appId: APP };
const V = resolveValidators();

let meeting: Uint8Array;
let link: string;
let replyTxt: string;
let sampleJson: Record<string, unknown>[];

beforeAll(async () => {
  const [a, n] = [await dev('A'), await dev('N')];
  meeting = await signMeetingCode(P, a.intro, 'member', NOW, a.keys.signing.privateKey);
  const entry: DeviceEntry = { ...a.intro, role: 'admin', removed: false, private: false };
  const made = createInvitation(
    { appId: APP, voucher: vouchAll() },
    entry,
    'member',
    new Uint8Array(16).fill(3),
    NOW,
  );
  if (!made.ok) throw new Error('x');
  link = invitationLink(APP, 'https://example.org/p', made.invitation);
  replyTxt = replyText(APP, {
    to: a.id,
    introduction: n.intro,
    proof: await invitationProof(APP, made.invitation, n.intro),
  });
  sampleJson = [
    JSON.parse(new TextDecoder().decode(meeting)),
    JSON.parse(new TextDecoder().decode(fromBase64url(link.split('#join=')[1]!))),
  ];
});

const ALPHABET = 'ABCxyz019-_{}[]",:|# ä\u0007';
function mutateText(rnd: () => number, text: string): string {
  let s = text;
  for (let k = 0, n = 1 + Math.floor(rnd() * 3); k < n; k++) {
    const i = Math.floor(rnd() * (s.length + 1));
    const op = rnd();
    const ch = ALPHABET[Math.floor(rnd() * ALPHABET.length)] as string;
    if (op < 0.4) s = s.slice(0, i) + ch + s.slice(i + 1);
    else if (op < 0.6) s = s.slice(0, i) + ch + s.slice(i);
    else if (op < 0.8) s = s.slice(0, i) + s.slice(i + 1);
    else s = s.slice(0, i);
  }
  return s;
}
function randomBytes(rnd: () => number, max: number): Uint8Array {
  return Uint8Array.from({ length: Math.floor(rnd() * max) }, () => Math.floor(rnd() * 256));
}
function randomValue(rnd: () => number, depth = 0): unknown {
  const r = rnd();
  if (depth > 2 || r < 0.5) {
    const pool: unknown[] = [
      null,
      true,
      false,
      0,
      -1,
      1.5,
      NaN,
      2 ** 60,
      '',
      'x',
      'device-' + 'a'.repeat(32),
      'member',
      'A'.repeat(22),
      'A'.repeat(43),
      'A'.repeat(86),
      [],
      {},
    ];
    return pool[Math.floor(rnd() * pool.length)];
  }
  if (r < 0.7)
    return Array.from({ length: Math.floor(rnd() * 3) }, () => randomValue(rnd, depth + 1));
  const o: Record<string, unknown> = {};
  for (let k = 0, n = Math.floor(rnd() * 4); k < n; k++)
    o[
      ['m', 'device', 'name', 'proof', '__proto__', 'role', 'constructor'][
        Math.floor(rnd() * 7)
      ] as string
    ] = randomValue(rnd, depth + 1);
  return o;
}

describe('meeting code parser', () => {
  it(`${N} inputs: never throws, accepted ones are valid and have one spelling`, () => {
    const rnd = prng(101);
    const original = new TextDecoder().decode(meeting);
    let accepted = 0;
    for (let i = 0; i < N; i++) {
      const input =
        i % 3 === 0
          ? randomBytes(rnd, 600)
          : i % 3 === 1
            ? new TextEncoder().encode(mutateText(rnd, original))
            : new TextEncoder().encode(
                JSON.stringify({ ...sampleJson[0], ...(randomValue(rnd) as object) }),
              );
      const before = new Uint8Array(input);
      const got = parseMeetingCode(P, input);
      expect(input).toEqual(before); // the input is not changed
      if (!got) continue;
      accepted++;
      expect(parseIntroduction(got.introduction, V)).toEqual(got.introduction);
      expect(V.role(got.role)).toBe(true);
      expect(Number.isSafeInteger(got.time) && got.time >= 0).toBe(true);
      expect(got.proof).toMatch(/^[A-Za-z0-9_-]{86}$/);
      expect(DEVICE_ID.test(got.introduction.device)).toBe(true);
      const again = parseMeetingCode(P, input);
      expect(again).toEqual(got);
      expect(again).not.toBe(got);
      expect(again?.introduction).not.toBe(got.introduction);
    }
    expect(parseMeetingCode(P, meeting)).toBeDefined();
    expect(accepted).toBeGreaterThan(0); // not vacuous: some inputs are the code itself
    expect(accepted).toBeLessThan(N); // and most are not
  });
});

describe('invitation parser', () => {
  it(`${N} inputs: never throws, accepted ones are valid and unaliased`, () => {
    const rnd = prng(202);
    for (let i = 0; i < N; i++) {
      const input =
        i % 3 === 0
          ? mutateText(rnd, link)
          : i % 3 === 1
            ? `https://x.test/#join=${base64url(randomBytes(rnd, 400))}`
            : `#join=${base64url(new TextEncoder().encode(JSON.stringify({ ...sampleJson[1], ...(randomValue(rnd) as object) })))}`;
      const got = parseInvitation(P, input);
      if (!got) continue;
      expect(V.role(got.role)).toBe(true);
      expect(got.code).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(Number.isSafeInteger(got.until)).toBe(true);
      expect(parseIntroduction(got.from, V)).toEqual(got.from);
      const again = parseInvitation(P, input);
      expect(again).toEqual(got);
      expect(again?.from).not.toBe(got.from);
    }
    expect(parseInvitation(P, link)).toBeDefined();
  });

  it(`${N} random objects for the open record: never throws, result shares nothing with the input`, () => {
    const rnd = prng(303);
    for (let i = 0; i < N; i++) {
      const raw =
        i % 2 === 0
          ? randomValue(rnd)
          : {
              role: 'member',
              code: base64url(new Uint8Array(16)),
              until: NOW + 5,
              ...(randomValue(rnd) as object),
            };
      const got = parseOpenInvitation(P, raw, NOW);
      if (!got) continue;
      expect(got).not.toBe(raw);
      expect(NOW < got.until).toBe(true);
      expect(got.code).toMatch(/^[A-Za-z0-9_-]{22}$/);
    }
    expect(
      parseOpenInvitation(
        P,
        { role: 'member', code: base64url(new Uint8Array(16)), until: NOW + 5 },
        NOW,
      ),
    ).toBeDefined();
  });
});

describe('reply parser', () => {
  it(`${N} inputs: never throws, accepted ones are valid and unaliased`, () => {
    const rnd = prng(404);
    for (let i = 0; i < N; i++) {
      const input = i % 2 === 0 ? mutateText(rnd, replyTxt) : base64url(randomBytes(rnd, 500));
      const got = parseReply(P, input);
      if (!got) continue;
      expect(DEVICE_ID.test(got.to)).toBe(true);
      expect(got.proof).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const again = parseReply(P, input);
      expect(again).toEqual(got);
      expect(again?.introduction).not.toBe(got.introduction);
    }
    expect(parseReply(P, replyTxt)).toBeDefined();
  });

  it('non-string inputs of every parser are refused without throwing', () => {
    for (const v of [undefined, null, 5, {}, [], Symbol.iterator, () => 1]) {
      expect(parseReply(P, v as never)).toBeUndefined();
      expect(parseInvitation(P, v as never)).toBeUndefined();
      expect(parseMeetingCode(P, v as never)).toBeUndefined();
      expect(parseOpenInvitation(P, v, NOW)).toBeUndefined();
      expect(parseIntroduction(v, V)).toBeUndefined();
      expect(parseKnownList(v)).toEqual([]);
    }
  });
});

describe('introduction and known-list parsers', () => {
  it(`${N} random values: never throw, accepted ones are valid`, () => {
    const rnd = prng(505);
    for (let i = 0; i < N; i++) {
      const raw = randomValue(rnd);
      const intro = parseIntroduction(raw, V);
      if (intro) expect(parseIntroduction(intro, V)).toEqual(intro);
      const list = parseKnownList([
        raw,
        { device: 'device-' + 'a'.repeat(32), ...(randomValue(rnd) as object) },
      ]);
      for (const e of list) {
        expect(e.since).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(e.checkCode).toMatch(/^\d{4}( \d{4}){4}$/);
      }
    }
  });

  it('a predicate of the app that throws counts as false and never escapes', () => {
    const v = resolveValidators({
      name: () => {
        throw new Error('boom');
      },
      role: (() => 1) as never,
    });
    expect(v.name('x')).toBe(false);
    expect(v.role('member')).toBe(false);
    expect(V.name('has|bar')).toBe(false);
  });
});
