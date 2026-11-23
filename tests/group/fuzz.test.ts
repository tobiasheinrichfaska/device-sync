// Seeded fuzzing of every reader: 3000 inputs each, mutated from valid texts and random. A reader
// never throws, and what it accepts is exactly the one spelling the writer produces.
import { describe, expect, it } from 'vitest';
import {
  acceptGrant,
  decryptGroup,
  encryptGroup,
  parseGrant,
  parseRequest,
  readGroupDataHeader,
  readGroupState,
  rotateGroup,
  storeGroupState,
} from '../../src/group/index.ts';
import { dataText, grantText, requestText } from '../../src/group/wire.ts';
import { APP, fresh, prng, seeded, text, world } from './helpers.ts';

const COUNT = 3000;

function mutate(source: string, next: () => number): string {
  const chars = [...source];
  const times = 1 + Math.floor(next() * 3);
  for (let t = 0; t < times; t += 1) {
    const i = Math.floor(next() * Math.max(chars.length, 1));
    const junk = '"\\{}[],:0123456789abcXYZ_- \u0000é\ud800'.split('');
    switch (Math.floor(next() * 7)) {
      case 0:
        chars.splice(i, 1);
        break;
      case 1:
        chars.splice(i, 0, junk[Math.floor(next() * junk.length)] as string);
        break;
      case 2:
        chars[i] = junk[Math.floor(next() * junk.length)] as string;
        break;
      case 3:
        chars.length = i;
        break;
      case 4:
        chars.splice(i, 0, ...chars.slice(i, i + 5));
        break;
      case 5: {
        const j = Math.floor(next() * chars.length);
        [chars[i], chars[j]] = [chars[j] as string, chars[i] as string];
        break;
      }
      default:
        chars.splice(i, 0, ...'{"a":1}'.split(''));
    }
  }
  return chars.join('');
}

const randomText = (next: () => number): string =>
  Array.from({ length: Math.floor(next() * 120) }, () =>
    String.fromCharCode(Math.floor(next() * 0x2fff)),
  ).join('');

async function fixture() {
  const w = await world(['A', 'B']);
  const [a, b] = w.devs;
  const r = await rotateGroup({
    appId: APP,
    own: w.own(a!),
    trust: await w.trustOf(a!),
    state: fresh(),
    random: seeded(31),
  });
  if (!r.ok) throw new Error();
  const enc = await encryptGroup({
    appId: APP,
    state: r.state,
    plaintext: text('p'),
    random: seeded(32),
  });
  if (!enc.ok) throw new Error();
  const k = r.state.keys[0]!;
  return { w, a: a!, b: b!, r, enc, k };
}

const SIG = Buffer.alloc(64, 5).toString('base64url');

describe('fuzzing the readers', () => {
  it('parseGrant: 3000 inputs, one spelling', async () => {
    const { k } = await fixture();
    const good = grantText(APP, {
      set: 'main',
      epoch: 1,
      author: k.author,
      from: k.author,
      to: 'device-to',
      kid: k.kid,
      key: k.key,
      audience: k.audience,
      sig: SIG,
    });
    expect(parseGrant(APP, good)).toBeDefined();
    const next = prng(101);
    let accepted = 0;
    for (let i = 0; i < COUNT; i += 1) {
      const input = i % 5 === 0 ? randomText(next) : mutate(good, next);
      const out = parseGrant(APP, input);
      if (out) {
        accepted += 1;
        expect(grantText(APP, out)).toBe(input);
      }
    }
    expect(accepted).toBeLessThan(COUNT / 10);
    for (const v of [undefined, null, 1, {}, [], 'x']) expect(parseGrant(APP, v)).toBeUndefined();
  });

  it('parseRequest: 3000 inputs', () => {
    const req = { set: 'main', epoch: 7, from: 'device-a', to: 'device-b', sig: SIG };
    const good = requestText(APP, req);
    expect(parseRequest(APP, good)).toEqual(req);
    const next = prng(102);
    for (let i = 0; i < COUNT; i += 1) {
      const input = i % 5 === 0 ? randomText(next) : mutate(good, next);
      const out = parseRequest(APP, input);
      if (out) expect(requestText(APP, out)).toBe(input);
    }
  });

  it('readGroupState: 3000 inputs', async () => {
    const { r } = await fixture();
    const good = storeGroupState(APP, r.state);
    const next = prng(103);
    for (let i = 0; i < COUNT; i += 1) {
      const input = i % 5 === 0 ? randomText(next) : mutate(good, next);
      const out = await readGroupState(APP, input);
      if (out) expect(storeGroupState(APP, out)).toBe(input);
    }
  });

  it('the data text: 3000 inputs through the header reader and decryptGroup', async () => {
    const { enc, r } = await fixture();
    const next = prng(104);
    for (let i = 0; i < COUNT; i += 1) {
      const input = i % 5 === 0 ? randomText(next) : mutate(enc.text, next);
      const head = readGroupDataHeader(APP, input);
      if (head) {
        const t = input;
        const m = JSON.parse(t) as { epoch: number; kid: string; salt: string; ct: string };
        expect(
          dataText(
            APP,
            head.set,
            head.epoch,
            head.kid,
            Buffer.from(m.salt, 'base64url'),
            Buffer.from(m.ct, 'base64url'),
          ),
        ).toBe(input);
      }
      const dec = await decryptGroup({ appId: APP, state: r.state, text: input });
      if (dec.ok) expect(input).toBe(enc.text);
    }
  });

  it('acceptGrant with 3000 damaged or random files never throws and never accepts', async () => {
    const { w, b, r } = await fixture();
    const file = r.grants[0]!.file;
    const own = w.own(b);
    const trust = await w.trustOf(b);
    const next = prng(105);
    const good = new TextDecoder().decode(file);
    for (let i = 0; i < COUNT; i += 1) {
      const bytes =
        i % 5 === 0
          ? Uint8Array.from({ length: Math.floor(next() * 300) }, () => Math.floor(next() * 256))
          : new TextEncoder().encode(mutate(good, next));
      const res = await acceptGrant({ appId: APP, own, trust, state: fresh(), file: bytes });
      // a mutation that changed nothing is the valid file itself
      expect(res.ok, `input ${i}`).toBe(new TextDecoder().decode(bytes) === good);
    }
    for (const v of [undefined, null, 'x', 5, {}]) {
      const res = await acceptGrant({
        appId: APP,
        own,
        trust,
        state: fresh(),
        file: v as unknown as Uint8Array,
      });
      expect(res.ok).toBe(false);
    }
  });
});
