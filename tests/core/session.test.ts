import { beforeAll, describe, expect, it } from 'vitest';
import {
  SESSION_LIMITS,
  base64url,
  createHello,
  encodeHello,
  fromBase64url,
  maxSealedChars,
  nonceFor,
  openSession,
  parseHello,
  parseSealedMessage,
  resolveSessionLimits,
  type EncryptedSession,
  type Hello,
} from '../../src/core/index.ts';
import { dh, jwkToPoint, messageAad, nonce, refOpen, refSeal, refSession } from './reference.ts';
import {
  A,
  APP,
  B,
  C,
  connect,
  extractablePair,
  mutate,
  pairFromJwk,
  party,
  rng,
  show,
  text,
  type Party,
} from './secure-helpers.ts';

let PA: Party;
let PB: Party;
let PC: Party;
beforeAll(async () => {
  [PA, PB, PC] = [await party(A), await party(B), await party(C)];
});

async function seal(s: EncryptedSession, message: string): Promise<string> {
  const r = await s.seal(text(message));
  if (!r.ok) throw new Error(r.reason);
  return r.text;
}
async function opened(s: EncryptedSession, wire: string): Promise<string | undefined> {
  const r = await s.open(wire);
  return r.ok ? show(r.plaintext) : undefined;
}
const reasonOf = async (s: EncryptedSession, wire: string): Promise<string> => {
  const r = await s.open(wire);
  return r.ok ? 'ok' : r.reason;
};

describe('the end-to-end session (cases of the typed earlier implementation)', () => {
  it('both sides make the same keys; messages go both ways in order', async () => {
    const { a, b } = await connect(PA, PB);
    const stand = JSON.stringify({ t: 'stand', vector: { [A]: 3 } });
    const w1 = await seal(a, stand);
    expect(w1).not.toContain(A.slice(7));
    expect(w1).not.toContain('stand');
    expect(await opened(b, w1)).toBe(stand);
    expect(await opened(b, await seal(a, 'done'))).toBe('done');
    expect(await opened(a, await seal(b, 'answer'))).toBe('answer');
    expect([a.sent, a.received, b.sent, b.received]).toEqual([2, 1, 1, 2]);
  });

  it('refuses a replayed, reordered, mirrored or altered message', async () => {
    const { a, b } = await connect(PA, PB);
    const w1 = await seal(a, 'one');
    const w2 = await seal(a, 'two');
    const w3 = await seal(a, 'three');
    expect(await reasonOf(b, w2)).toBe('gap');
    expect(await opened(b, w1)).toBe('one');
    expect(await reasonOf(b, w1)).toBe('replayed');
    expect(await reasonOf(a, await seal(a, 'self'))).not.toBe('ok');
    expect(await opened(b, w2)).toBe('two');
    const message = parseSealedMessage(APP, w3);
    if (!message) throw new Error('unreadable');
    const flipped = new Uint8Array(message.ct);
    flipped[0] = (flipped[0] as number) ^ 1;
    const altered = `{"m":"demo-msg:2","n":${message.n},"ct":"${base64url(flipped)}"}`;
    expect(await reasonOf(b, altered)).toBe('bad-seal');
    // the refusals changed nothing: the three still arrives
    expect(await opened(b, w3)).toBe('three');
  });

  it('a third device cannot read along, even with every public key and both hellos', async () => {
    const { a, helloA, helloB } = await connect(PA, PB);
    // C opens a session with its own secret keys, as the device it is
    const hc = await createHello(C);
    const c = await openSession({
      appId: APP,
      own: { device: C, agreement: PC.agreement },
      peer: { device: A, dh: PA.dh },
      ephemeral: hc.ephemeral,
      ownHello: hc.hello,
      peerHello: helloA,
    });
    expect(c.ok).toBe(true);
    if (!c.ok) return;
    const secret = await seal(a, 'secret');
    expect(await reasonOf(c.session, secret)).toBe('bad-seal');
    // pretending to be B with B's hello but without B's secret key
    const hc2 = await createHello(B);
    const fake = await openSession({
      appId: APP,
      own: { device: B, agreement: PC.agreement },
      peer: { device: A, dh: PA.dh },
      ephemeral: hc2.ephemeral,
      ownHello: hc2.hello,
      peerHello: helloA,
    });
    expect(fake.ok).toBe(true);
    if (!fake.ok) return;
    expect(await reasonOf(fake.session, secret)).toBe('bad-seal');
    expect(helloB.device).toBe(B);
  });

  it('a wrong device key on one side gives no common key; a mirrored hello opens nothing', async () => {
    const ea = await createHello(A);
    const eb = await createHello(B);
    const stranger = await party('device-' + 'f'.repeat(32));
    const a2 = await openSession({
      appId: APP,
      own: { device: A, agreement: PA.agreement },
      peer: { device: B, dh: stranger.dh },
      ephemeral: ea.ephemeral,
      ownHello: ea.hello,
      peerHello: eb.hello,
    });
    const b2 = await openSession({
      appId: APP,
      own: { device: B, agreement: PB.agreement },
      peer: { device: A, dh: PA.dh },
      ephemeral: eb.ephemeral,
      ownHello: eb.hello,
      peerHello: ea.hello,
    });
    if (!a2.ok || !b2.ok) throw new Error('no session');
    expect(await reasonOf(b2.session, await seal(a2.session, 'x'))).toBe('bad-seal');
    expect(await reasonOf(a2.session, await seal(b2.session, 'x'))).toBe('bad-seal');
    const ec = await createHello(A);
    expect(
      await openSession({
        appId: APP,
        own: { device: A, agreement: PA.agreement },
        peer: { device: A, dh: PA.dh },
        ephemeral: ec.ephemeral,
        ownHello: ec.hello,
        peerHello: ec.hello,
      }),
    ).toEqual({ ok: false, reason: 'same-device' });
    const ed = await createHello(A);
    expect(
      await openSession({
        appId: APP,
        own: { device: A, agreement: PA.agreement },
        peer: { device: B, dh: PB.dh },
        ephemeral: ed.ephemeral,
        ownHello: ed.hello,
        peerHello: { device: B, eph: ed.hello.eph },
      }),
    ).toEqual({ ok: false, reason: 'mirrored' });
  });

  it('hello and sealed messages are read strictly', async () => {
    const { helloA } = await connect(PA, PB);
    const t = encodeHello(APP, helloA);
    expect(parseHello(APP, t)).toEqual(helloA);
    expect(parseHello(APP, JSON.stringify({ ...helloA, device: 'x' }))).toBeUndefined();
    expect(parseHello(APP, t.replace(helloA.eph, 'short'))).toBeUndefined();
    const ct = 'B'.repeat(40);
    expect(parseSealedMessage(APP, `{"m":"demo-msg:2","n":0,"ct":"${ct}"}`)).toBeDefined();
    expect(parseSealedMessage(APP, `{"m":"demo-msg:2","n":0,"ct":"${'B'.repeat(39)}"}`)).toBe(
      undefined,
    );
    expect(parseSealedMessage(APP, '{"t":"stand","vector":{}}')).toBeUndefined();
  });
});

describe('strict reading of hello and sealed messages (one spelling, bounded)', () => {
  let helloText: string;
  let wire: string;
  beforeAll(async () => {
    const { a, helloA } = await connect(PA, PB);
    helloText = encodeHello(APP, helloA);
    wire = await seal(a, 'payload');
  });

  it('the exact texts read; the documented spelling is what is written', () => {
    expect(helloText).toMatch(
      /^\{"m":"demo-hello:2","device":"device-a{32}","eph":"[A-Za-z0-9_-]{87}"\}$/,
    );
    expect(wire).toMatch(/^\{"m":"demo-msg:2","n":0,"ct":"[A-Za-z0-9_-]{31}"\}$/);
    expect(parseHello(APP, helloText)).toBeDefined();
    expect(parseSealedMessage(APP, wire)).toBeDefined();
  });

  it('refuses every other spelling of a hello', () => {
    const o = JSON.parse(helloText) as Record<string, string>;
    const bad: string[] = [
      ` ${helloText}`,
      `${helloText}\n`,
      `﻿${helloText}`,
      helloText.replace(',"device"', ', "device"'),
      JSON.stringify({ device: o.device, m: o.m, eph: o.eph }),
      JSON.stringify({ ...o, extra: 1 }),
      helloText.replace('"eph"', '"eph":"AAAA","eph"'),
      helloText.replace('"device"', '"device":"x","device"'),
      helloText.replace('"m"', '"__proto__":{},"m"'),
      helloText.replace('demo-hello:2', 'demo-hello:1'),
      helloText.replace('demo-hello:2', 'demo-msg:2'),
      helloText.replace('demo-hello:2', 'other-hello:2'),
      helloText.replace('"device":"device', '"device":"dev\\u0069ce'),
      helloText.replace(/"eph":"(.*)"\}$/, (_m, e: string) => `"eph":"${e}="}`),
      '',
      '{}',
      'null',
      '[]',
    ];
    for (const t of bad) expect(parseHello(APP, t), t).toBeUndefined();
    for (const t of [undefined, null, 5, {}, [], new Uint8Array(3)]) {
      expect(parseHello(APP, t)).toBeUndefined();
    }
  });

  it('refuses every other spelling of a sealed message', () => {
    const o = JSON.parse(wire) as { m: string; n: number; ct: string };
    const frame = (n: string, ct = o.ct, m = o.m) => `{"m":"${m}","n":${n},"ct":"${ct}"}`;
    const last = o.ct.at(-1) as string;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const sibling = alphabet[alphabet.indexOf(last) ^ 1] as string;
    const bad: string[] = [
      ` ${wire}`,
      `${wire}\n`,
      frame('00'),
      frame('01'),
      frame('0.0'),
      frame('1e0'),
      frame('-0'),
      frame('-1'),
      frame('"0"'),
      frame('9007199254740992'),
      frame('18446744073709551616'),
      frame('null'),
      frame('0', `${o.ct}=`),
      frame('0', o.ct.slice(0, -1) + sibling), // same bytes spelled twice: not canonical
      frame('0', o.ct.slice(0, 20)),
      frame('0', 'A'.repeat(21)), // fifteen bytes: shorter than a tag
      frame('0', o.ct.replace(/^./, '\\u0041')),
      frame('0', o.ct, 'demo-msg:1'),
      frame('0', o.ct, 'other-msg:2'),
      wire.replace('"n":0,', '"n":0,"n":1,'),
      wire.replace('"ct"', '"extra":1,"ct"'),
      wire.replace('{"m"', '{"__proto__":{"n":1},"m"'),
      JSON.stringify({ ct: o.ct, n: o.n, m: o.m }),
      wire.replace('"n":0,"ct"', '"ct"'),
    ];
    for (const t of bad) expect(parseSealedMessage(APP, t), t).toBeUndefined();
    for (const t of [undefined, null, 7, {}, [], new Uint8Array(4)]) {
      expect(parseSealedMessage(APP, t)).toBeUndefined();
    }
  });

  it('a device id with a separator, a control or format character, a lone surrogate or too long is refused', async () => {
    const eph = (await createHello(A)).hello.eph;
    const refused = [
      '',
      'a|b',
      'a\u0000b',
      'a\nb',
      'a\u007Fb',
      'a​b',
      'a‮b',
      `a${String.fromCharCode(0xd800)}b`,
      'x'.repeat(201),
    ];
    for (const device of refused) {
      expect(() => encodeHello(APP, { device, eph }), JSON.stringify(device)).toThrow(TypeError);
      const raw = `{"m":"demo-hello:2","device":${JSON.stringify(device)},"eph":"${eph}"}`;
      expect(parseHello(APP, raw)).toBeUndefined();
    }
    await expect(createHello('a|b')).rejects.toThrow(TypeError);
    expect(encodeHello(APP, { device: 'x'.repeat(200), eph })).toContain('x'.repeat(200));
    expect(encodeHello(APP, { device: 'Ünï 日本', eph })).toContain('Ünï 日本');
    expect(parseHello(APP, encodeHello(APP, { device: 'Ünï 日本', eph }))?.device).toBe('Ünï 日本');
  });

  it('an invalid app id is a programming error, never a silent default', () => {
    expect(() => parseHello('Demo', helloText)).toThrow();
    expect(() => parseSealedMessage('x', wire)).toThrow();
  });
});

describe('what a hello and a peer key must be', () => {
  const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const point = (bytes: Uint8Array): string => base64url(bytes);
  const withPrefix = (prefix: number, rest: number): Uint8Array => {
    const b = new Uint8Array(rest + 1);
    b[0] = prefix;
    return b;
  };

  async function tryHello(eph: string, device = B) {
    const mine = await createHello(A);
    const text = `{"m":"demo-hello:2","device":${JSON.stringify(device)},"eph":"${eph}"}`;
    const hello = parseHello(APP, text);
    if (!hello) return 'unreadable' as const;
    const r = await openSession({
      appId: APP,
      own: { device: A, agreement: PA.agreement },
      peer: { device: B, dh: PB.dh },
      ephemeral: mine.ephemeral,
      ownHello: mine.hello,
      peerHello: hello,
    });
    return r.ok ? ('open' as const) : r.reason;
  }

  it('wrong length, wrong prefix, infinity and compressed points never read', async () => {
    expect(await tryHello(point(new Uint8Array([0])))).toBe('unreadable'); // point at infinity
    expect(await tryHello('AA')).toBe('unreadable');
    expect(await tryHello(point(withPrefix(2, 32)))).toBe('unreadable'); // compressed
    expect(await tryHello(point(withPrefix(3, 32)))).toBe('unreadable');
    expect(await tryHello(point(withPrefix(4, 63)))).toBe('unreadable'); // one byte short
    expect(await tryHello(point(withPrefix(4, 65)))).toBe('unreadable'); // one byte long
    expect(await tryHello(point(withPrefix(0, 64)))).toBe('unreadable'); // wrong first byte
    expect(await tryHello(point(withPrefix(4, 96)))).toBe('unreadable'); // a P-384 sized point
  });

  it('well-formed but off the curve: (0,0), (1,1), x at or above the field prime', async () => {
    expect(await tryHello(point(withPrefix(4, 64)))).toBe('bad-point'); // all zero
    const one = withPrefix(4, 64);
    one[32] = 1;
    one[64] = 1;
    expect(await tryHello(point(one))).toBe('bad-point');
    const big = withPrefix(4, 64);
    big.set(Buffer.from(P.toString(16), 'hex'), 1);
    expect(await tryHello(point(big))).toBe('bad-point');
    const valid = fromBase64url((await createHello(B)).hello.eph);
    const off = new Uint8Array(valid);
    off[64] = (off[64] as number) ^ 1; // y changed by one bit: no longer on the curve
    expect(await tryHello(point(off))).toBe('bad-point');
    expect(await tryHello(point(valid))).toBe('open');
  });

  it('the same point spelled another way is not read', async () => {
    const eph = (await createHello(B)).hello.eph;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const twin =
      eph.slice(0, -1) + (alphabet[alphabet.indexOf(eph.at(-1) as string) ^ 1] as string);
    expect(fromBase64url(twin)).toEqual(fromBase64url(eph)); // the same bytes
    expect(await tryHello(twin)).toBe('unreadable');
    expect(await tryHello(eph)).toBe('open');
  });

  it('a peer static key that is not a valid point is refused with a code', async () => {
    const off = withPrefix(4, 64);
    const mk = async (dhKey: unknown) => {
      const mine = await createHello(A);
      const theirs = await createHello(B);
      return openSession({
        appId: APP,
        own: { device: A, agreement: PA.agreement },
        peer: { device: B, dh: dhKey as string },
        ephemeral: mine.ephemeral,
        ownHello: mine.hello,
        peerHello: theirs.hello,
      });
    };
    expect(await mk(point(off))).toEqual({ ok: false, reason: 'bad-peer-key' });
    expect(await mk('AA')).toEqual({ ok: false, reason: 'bad-peer-key' });
    expect(await mk(undefined)).toEqual({ ok: false, reason: 'bad-peer-key' });
    expect(await mk(PA.dh)).toEqual({ ok: false, reason: 'same-key' });
    expect((await mk(PB.dh)).ok).toBe(true);
  });

  it('inconsistent parameters are refused with codes, never thrown', async () => {
    const mine = await createHello(A);
    const theirs = await createHello(B);
    const base = {
      appId: APP,
      own: { device: A, agreement: PA.agreement },
      peer: { device: B, dh: PB.dh },
      ephemeral: mine.ephemeral,
      ownHello: mine.hello,
      peerHello: theirs.hello,
    };
    const code = async (over: Record<string, unknown>) =>
      (await openSession({ ...base, ...over } as typeof base)) as { ok: boolean; reason?: string };
    // a failing opening consumes nothing: every refusal below leaves the ephemeral pair usable
    expect(await code({ own: { device: '', agreement: PA.agreement } })).toMatchObject({
      reason: 'bad-own',
    });
    expect(await code({ own: null })).toMatchObject({ reason: 'bad-own' });
    expect(await code({ peer: { device: 'a|b', dh: PB.dh } })).toMatchObject({
      reason: 'bad-peer',
    });
    expect(await code({ peer: undefined })).toMatchObject({ reason: 'bad-peer' });
    expect(await code({ peerHello: { device: B } })).toMatchObject({ reason: 'bad-hello' });
    expect(await code({ ownHello: { ...mine.hello, extra: 1 } })).toMatchObject({
      reason: 'bad-hello',
    });
    expect(await code({ ownHello: { device: C, eph: mine.hello.eph } })).toMatchObject({
      reason: 'own-hello-mismatch',
    });
    expect(await code({ peerHello: { device: C, eph: theirs.hello.eph } })).toMatchObject({
      reason: 'wrong-device',
    });
    const other = await createHello(A);
    expect(await code({ ephemeral: other.ephemeral })).toMatchObject({
      reason: 'own-hello-mismatch',
    });
    // an agreement pair that is not an ECDH pair cannot derive anything
    expect(await code({ own: { device: A, agreement: PA.keys.signing } })).toMatchObject({
      reason: 'crypto-failure',
    });
    expect(await code({})).toMatchObject({ ok: true });
  });
});

describe('replay, duplication, reordering and dropping', () => {
  it('every order of four messages: accepted ones are always an in-order prefix, nothing twice', async () => {
    const perms = (items: number[]): number[][] =>
      items.length <= 1
        ? [items]
        : items.flatMap((x, i) =>
            perms([...items.slice(0, i), ...items.slice(i + 1)]).map((p) => [x, ...p]),
          );
    for (const order of perms([0, 1, 2, 3])) {
      const { a, b } = await connect(PA, PB);
      const wires = await Promise.all([0, 1, 2, 3].map((i) => seal(a, `m${i}`)));
      const got: string[] = [];
      for (const i of order) {
        const r = await b.open(wires[i] as string);
        if (r.ok) got.push(show(r.plaintext));
      }
      expect(got, order.join('')).toEqual(['m0', 'm1', 'm2', 'm3'].slice(0, got.length));
      // refused messages changed nothing: delivering everything in order finishes the job
      for (const i of [0, 1, 2, 3]) {
        const r = await b.open(wires[i] as string);
        if (r.ok) got.push(show(r.plaintext));
      }
      expect(got).toEqual(['m0', 'm1', 'm2', 'm3']);
    }
  });

  it('a duplicated message is delivered once; a dropped one stops the stream (gap)', async () => {
    const { a, b } = await connect(PA, PB);
    const w = await Promise.all([0, 1, 2].map((i) => seal(a, `m${i}`)));
    expect(await reasonOf(b, w[0] as string)).toBe('ok');
    for (let i = 0; i < 3; i += 1) expect(await reasonOf(b, w[0] as string)).toBe('replayed');
    // m1 is lost on the way: m2 is not accepted before it
    expect(await reasonOf(b, w[2] as string)).toBe('gap');
    expect(b.received).toBe(1);
    expect(await reasonOf(b, w[1] as string)).toBe('ok');
    expect(await reasonOf(b, w[2] as string)).toBe('ok');
    expect(b.received).toBe(3);
  });

  it('two openings of one message at the same time: exactly one succeeds', async () => {
    const { a, b } = await connect(PA, PB);
    const w = await seal(a, 'once');
    const results = await Promise.all([b.open(w), b.open(w), b.open(w)]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(b.received).toBe(1);
  });

  it('a refusal leaves the session exactly as it was (counters and confirmation)', async () => {
    const { a, b } = await connect(PA, PB);
    expect(b.confirmed).toBe(false);
    const w = await seal(a, 'x');
    for (const bad of ['', '{}', w.slice(0, -2), w.replace('"n":0', '"n":5'), 'null']) {
      expect((await b.open(bad)).ok).toBe(false);
      expect([b.received, b.sent, b.confirmed]).toEqual([0, 0, false]);
    }
    expect((await b.open(w)).ok).toBe(true);
    expect([b.received, b.confirmed]).toEqual([1, true]);
    expect(a.confirmed).toBe(false); // nothing from B has opened at A
  });
});

describe('a message cannot be reflected, and the two directions never share a key', () => {
  it('a message sealed by A is refused by A, and one sealed by B by B', async () => {
    for (let i = 0; i < 3; i += 1) {
      // a fresh session each time: the first message of a stream (counter 0) reaches the key check
      const { a, b } = await connect(PA, PB);
      const fromA = await seal(a, `a${i}`);
      const fromB = await seal(b, `b${i}`);
      expect(await reasonOf(a, fromA)).toBe('bad-seal');
      expect(await reasonOf(b, fromB)).toBe('bad-seal');
      expect([a.received, b.received]).toEqual([0, 0]);
      // the same messages go through in the honest direction
      expect(await opened(b, fromA)).toBe(`a${i}`);
      expect(await opened(a, fromB)).toBe(`b${i}`);
    }
  });

  it('the same plaintext at the same counter gives unrelated ciphertexts in the two directions', async () => {
    const { a, b } = await connect(PA, PB);
    const wa = parseSealedMessage(APP, await seal(a, 'same bytes, same counter'));
    const wb = parseSealedMessage(APP, await seal(b, 'same bytes, same counter'));
    if (!wa || !wb) throw new Error('unreadable');
    expect(wa.n).toBe(wb.n);
    // under one key and one nonce the bodies (without the tag) would be identical: a keystream reuse
    expect(wa.ct.slice(0, -16)).not.toEqual(wb.ct.slice(0, -16));
  });

  it('a message of one direction does not open with the key of the other (reference implementation)', async () => {
    const ja = await extractablePair();
    const jb = await extractablePair();
    const ea = await extractablePair();
    const eb = await extractablePair();
    const dA = {
      device: A,
      staticPriv: ja.jwk,
      staticDh: jwkToPoint(ja.jwk),
      ephPriv: ea.jwk,
      ephPoint: jwkToPoint(ea.jwk),
    };
    const dB = {
      device: B,
      staticPriv: jb.jwk,
      staticDh: jwkToPoint(jb.jwk),
      ephPriv: eb.jwk,
      ephPoint: jwkToPoint(eb.jwk),
    };
    const ref = refSession(APP, dA, dB, {});
    expect(ref.keyOf(A).equals(ref.keyOf(B))).toBe(false);
    const sealed = refSeal(APP, ref.keyOf(A), A, B, 0, text('x'));
    expect(refOpen(ref.keyOf(A), nonce(0), messageAad(APP, A, B, 0), sealed.ct)).toBeDefined();
    expect(refOpen(ref.keyOf(B), nonce(0), messageAad(APP, A, B, 0), sealed.ct)).toBeUndefined();
    expect(refOpen(ref.keyOf(A), nonce(0), messageAad(APP, B, A, 0), sealed.ct)).toBeUndefined();
    expect(refOpen(ref.keyOf(A), nonce(1), messageAad(APP, A, B, 0), sealed.ct)).toBeUndefined();
    expect(refOpen(ref.keyOf(A), nonce(0), messageAad(APP, A, B, 1), sealed.ct)).toBeUndefined();
  });
});

describe('only the two devices can complete the session', () => {
  it('a wrong peer key, a wrong device id or a wrong app id gives a session that cannot talk', async () => {
    const wrongKey = await (async () => {
      const ea = await createHello(A);
      const eb = await createHello(B);
      const open = (
        own: Party,
        peer: { device: string; dh: string },
        mine: typeof ea,
        theirs: typeof eb,
      ) =>
        openSession({
          appId: APP,
          own: { device: own.device, agreement: own.agreement },
          peer,
          ephemeral: mine.ephemeral,
          ownHello: mine.hello,
          peerHello: theirs.hello,
        });
      const a = await open(PA, { device: B, dh: PC.dh }, ea, eb);
      const b = await open(PB, { device: A, dh: PA.dh }, eb, ea as unknown as typeof eb);
      return { a, b };
    })();
    if (!wrongKey.a.ok || !wrongKey.b.ok) throw new Error('no session');
    expect(await reasonOf(wrongKey.b.session, await seal(wrongKey.a.session, 'x'))).toBe(
      'bad-seal',
    );

    // a man in the middle renames B's hello: the ids in the transcript differ
    const ea = await createHello(A);
    const eb = await createHello(B);
    const renamed: Hello = { device: C, eph: eb.hello.eph };
    const a2 = await openSession({
      appId: APP,
      own: { device: A, agreement: PA.agreement },
      peer: { device: C, dh: PB.dh },
      ephemeral: ea.ephemeral,
      ownHello: ea.hello,
      peerHello: renamed,
    });
    const b2 = await openSession({
      appId: APP,
      own: { device: B, agreement: PB.agreement },
      peer: { device: A, dh: PA.dh },
      ephemeral: eb.ephemeral,
      ownHello: eb.hello,
      peerHello: ea.hello,
    });
    if (!a2.ok || !b2.ok) throw new Error('no session');
    expect(await reasonOf(b2.session, await seal(a2.session, 'x'))).toBe('bad-seal');
    expect(await reasonOf(a2.session, await seal(b2.session, 'x'))).toBe('bad-seal');
  });

  it('two apps never talk: the other app reads neither hello nor message, and relabelling does not help', async () => {
    const ea = await createHello(A);
    const eb = await createHello(B);
    const s = async (
      appId: string,
      own: Party,
      peer: Party,
      mine: typeof ea,
      theirs: typeof eb,
    ) => {
      const r = await openSession({
        appId,
        own: { device: own.device, agreement: own.agreement },
        peer: { device: peer.device, dh: peer.dh },
        ephemeral: mine.ephemeral,
        ownHello: mine.hello,
        peerHello: theirs.hello,
      });
      if (!r.ok) throw new Error(r.reason);
      return r.session;
    };
    const a = await s('demo', PA, PB, ea, eb);
    const b = await s('other', PB, PA, eb, ea as unknown as typeof eb);
    const w = await seal(a, 'x');
    expect(parseHello('other', encodeHello('demo', ea.hello))).toBeUndefined();
    expect(await reasonOf(b, w)).toBe('bad-message');
    expect(await reasonOf(b, w.replace('demo-msg:2', 'other-msg:2'))).toBe('bad-seal');
  });

  it('a man in the middle with every public key and both hellos cannot speak to either side', async () => {
    const ea = await createHello(A);
    const eb = await createHello(B);
    const em = await createHello(B); // M poses as B towards A, with its own ephemeral key
    const toA = await openSession({
      appId: APP,
      own: { device: B, agreement: PC.agreement }, // M's own static key stands in for B's
      peer: { device: A, dh: PA.dh },
      ephemeral: em.ephemeral,
      ownHello: em.hello,
      peerHello: ea.hello,
    });
    const a = await openSession({
      appId: APP,
      own: { device: A, agreement: PA.agreement },
      peer: { device: B, dh: PB.dh },
      ephemeral: ea.ephemeral,
      ownHello: ea.hello,
      peerHello: em.hello, // A was handed M's hello instead of B's
    });
    const b = await openSession({
      appId: APP,
      own: { device: B, agreement: PB.agreement },
      peer: { device: A, dh: PA.dh },
      ephemeral: eb.ephemeral,
      ownHello: eb.hello,
      peerHello: ea.hello,
    });
    if (!toA.ok || !a.ok || !b.ok) throw new Error('no session');
    expect(await reasonOf(a.session, await seal(toA.session, 'from M, claiming to be B'))).toBe(
      'bad-seal',
    );
    const forB = await seal(a.session, 'for B'); // sealed for M's hello, the real B never agreed to it
    expect(await reasonOf(toA.session, forB)).toBe('bad-seal');
    expect(await reasonOf(b.session, forB)).toBe('bad-seal');
  });

  it('a stolen static key of A does not let anyone speak as B to A (no key-compromise impersonation)', async () => {
    const sa = await extractablePair();
    const sb = await extractablePair();
    const ea = await extractablePair();
    const em = await extractablePair(); // the attacker's ephemeral pair
    const a = {
      device: A,
      staticPriv: sa.jwk,
      staticDh: jwkToPoint(sa.jwk),
      ephPriv: ea.jwk,
      ephPoint: jwkToPoint(ea.jwk),
    };
    const staticB = jwkToPoint(sb.jwk);
    const helloA: Hello = { device: A, eph: a.ephPoint };
    const helloM: Hello = { device: B, eph: jwkToPoint(em.jwk) };
    const sessionA = await openSession({
      appId: APP,
      own: { device: A, agreement: await pairFromJwk(sa.jwk) },
      peer: { device: B, dh: staticB },
      ephemeral: await pairFromJwk(ea.jwk),
      ownHello: helloA,
      peerHello: helloM,
    });
    if (!sessionA.ok) throw new Error(sessionA.reason);
    const peer = { device: B, staticDh: staticB, ephPoint: helloM.eph };
    // The attacker holds A's static secret and its own ephemeral secret. Of the four secrets A
    // computes it can make three: ee, A's static x its own ephemeral, and ss. The fourth (A's
    // ephemeral x B's static) needs a secret of A's ephemeral pair or of B.
    const attackerCan = {
      ee: dh(em.jwk, a.ephPoint),
      myStaticPeerEph: dh(sa.jwk, helloM.eph),
      ss: dh(sa.jwk, staticB),
    };
    const real = refSession(APP, a, peer, {});
    expect(real.terms.ee.equals(attackerCan.ee)).toBe(true);
    expect(real.terms.myStaticPeerEph.equals(attackerCan.myStaticPeerEph)).toBe(true);
    expect(real.terms.ss.equals(attackerCan.ss)).toBe(true);
    const guesses = [
      Buffer.alloc(32),
      attackerCan.ss,
      attackerCan.ee,
      dh(em.jwk, a.staticDh),
      dh(sa.jwk, a.ephPoint),
    ];
    for (const guess of guesses) {
      const forged = refSession(APP, a, peer, { terms: { myEphPeerStatic: guess } });
      const w = refSeal(APP, forged.keyOf(B), B, A, 0, text('forged'));
      expect(await reasonOf(sessionA.session, w.text)).toBe('bad-seal');
    }
    // control: with the true fourth secret the same harness makes a message A accepts
    const honest = refSeal(APP, real.keyOf(B), B, A, 0, text('honest'));
    expect(await opened(sessionA.session, honest.text)).toBe('honest');
  });
});

describe('forward secrecy: leaking both static keys later does not open the recorded session', () => {
  it('everything computable from the static secrets and the public values is not enough; the ephemeral secret is', async () => {
    const sa = await extractablePair();
    const sb = await extractablePair();
    const ea = await extractablePair();
    const eb = await extractablePair();
    const a = {
      device: A,
      staticPriv: sa.jwk,
      staticDh: jwkToPoint(sa.jwk),
      ephPriv: ea.jwk,
      ephPoint: jwkToPoint(ea.jwk),
    };
    const b = {
      device: B,
      staticPriv: sb.jwk,
      staticDh: jwkToPoint(sb.jwk),
      ephPriv: eb.jwk,
      ephPoint: jwkToPoint(eb.jwk),
    };
    const open = async (
      me: typeof a,
      you: typeof b,
      ownPair: { jwk: typeof sa.jwk },
      hello: Hello,
      peerHello: Hello,
      statics: { jwk: typeof sa.jwk },
    ) =>
      openSession({
        appId: APP,
        own: { device: me.device, agreement: await pairFromJwk(statics.jwk) },
        peer: { device: you.device, dh: you.staticDh },
        ephemeral: await pairFromJwk(ownPair.jwk),
        ownHello: hello,
        peerHello,
      });
    const helloA: Hello = { device: A, eph: a.ephPoint };
    const helloB: Hello = { device: B, eph: b.ephPoint };
    const ra = await open(a, b, ea, helloA, helloB, sa);
    const rb = await open(b, a, eb, helloB, helloA, sb);
    if (!ra.ok || !rb.ok) throw new Error('no session');
    const recorded = [await seal(ra.session, 'old secret'), await seal(rb.session, 'old answer')];

    // The attacker records the wire and later obtains BOTH static secrets (but never an ephemeral one).
    const withEe = (ee: Buffer) => refSession(APP, a, b, { terms: { ee } });
    const control = refSession(APP, a, b, {}); // knowing the ephemeral secret
    const w0 = parseSealedMessage(APP, recorded[0] as string);
    if (!w0) throw new Error('unreadable');
    const tryKey = (keyOf: ReturnType<typeof withEe>['keyOf']) =>
      refOpen(keyOf(A), nonce(0), messageAad(APP, A, B, 0), w0.ct);
    expect(show(tryKey(control.keyOf) as Buffer)).toBe('old secret');

    // what the leak gives: ss, and both crossed terms (static secret x the other's public ephemeral)
    const terms = control.terms;
    expect(terms.ss.equals(dh(sb.jwk, a.staticDh))).toBe(true);
    expect(terms.myEphPeerStatic.equals(dh(sb.jwk, a.ephPoint))).toBe(true);
    expect(terms.myStaticPeerEph.equals(dh(sa.jwk, b.ephPoint))).toBe(true);
    // with those and any stand-in for the ephemeral term the key is wrong
    const stand = [
      Buffer.alloc(32),
      terms.ss,
      terms.myEphPeerStatic,
      terms.myStaticPeerEph,
      dh(sa.jwk, b.staticDh),
    ];
    for (const ee of stand) expect(tryKey(withEe(ee).keyOf)).toBeUndefined();
    expect(tryKey(withEe(control.terms.ee).keyOf)).toBeDefined();
    // the ephemeral shared secret is what stands between the leak and the recording
    expect(terms.ee.equals(dh(sb.jwk, a.ephPoint))).toBe(false); // not the static x ephemeral value
    expect(terms.ee.equals(terms.ss)).toBe(false);
  });
});

describe('nonces never repeat under one key', () => {
  it('thousands of messages: counters 0..n-1, every ciphertext different, concurrent seals get distinct counters', async () => {
    const { a } = await connect(PA, PB);
    const seen = new Set<string>();
    const counters: number[] = [];
    for (let i = 0; i < 3000; i += 1) {
      const m = parseSealedMessage(APP, await seal(a, 'same plaintext every time'));
      if (!m) throw new Error('unreadable');
      counters.push(m.n);
      seen.add(base64url(m.ct));
    }
    expect(counters).toEqual(Array.from({ length: 3000 }, (_, i) => i));
    expect(seen.size).toBe(3000);
    const { a: a2 } = await connect(PA, PB);
    const burst = await Promise.all(Array.from({ length: 300 }, () => a2.seal(text('x'))));
    const ns = burst.map((r) => (r.ok ? parseSealedMessage(APP, r.text)?.n : -1));
    expect(new Set(ns).size).toBe(300);
    expect(Math.max(...(ns as number[]))).toBe(299);
  });

  it('the nonce is the counter: 12 bytes, unique per counter, all the way to the limit', () => {
    expect(Buffer.from(nonceFor(0)).toString('hex')).toBe('000000000000000000000000');
    expect(Buffer.from(nonceFor(1)).toString('hex')).toBe('000000000000000000000001');
    expect(Buffer.from(nonceFor(2 ** 32 - 1)).toString('hex')).toBe('0000000000000000ffffffff');
    const set = new Set<string>();
    for (let n = 0; n < 5000; n += 1) set.add(Buffer.from(nonceFor(n)).toString('hex'));
    expect(set.size).toBe(5000);
  });

  it('one ephemeral pair opens one session only (a second would repeat nonces under the same keys)', async () => {
    const ea = await createHello(A);
    const eb = await createHello(B);
    const params = {
      appId: APP,
      own: { device: A, agreement: PA.agreement },
      peer: { device: B, dh: PB.dh },
      ephemeral: ea.ephemeral,
      ownHello: ea.hello,
      peerHello: eb.hello,
    };
    const [x, y] = await Promise.all([openSession(params), openSession(params)]);
    expect([x.ok, y.ok].filter(Boolean)).toHaveLength(1);
    expect(await openSession(params)).toEqual({ ok: false, reason: 'ephemeral-reused' });
  });
});

describe('the counter never wraps', () => {
  it('the sender stops at the limit and nothing moves; the receiver refuses a counter beyond it', async () => {
    const { a } = await connect(PA, PB, APP, { maxMessages: 3 });
    for (let i = 0; i < 3; i += 1) expect((await a.seal(text('x'))).ok).toBe(true);
    expect(await a.seal(text('x'))).toEqual({ ok: false, reason: 'counter-limit' });
    expect(a.sent).toBe(3);
    // a receiver whose limit is 3 refuses message number 3 even though its sender could make it
    const { a: wide, b: narrow } = await connect(PA, PB, APP, undefined, { maxMessages: 3 });
    const w = await Promise.all([0, 1, 2, 3].map(() => seal(wide, 'x')));
    for (let i = 0; i < 3; i += 1) expect(await reasonOf(narrow, w[i] as string)).toBe('ok');
    expect(await reasonOf(narrow, w[3] as string)).toBe('counter-limit');
    expect(narrow.received).toBe(3);
  });

  it('the limit is between 1 and 2^32 whatever is asked for; junk is ignored', () => {
    expect(resolveSessionLimits({ maxMessages: 2 ** 40 }).maxMessages).toBe(2 ** 32);
    expect(resolveSessionLimits({ maxMessages: 0 }).maxMessages).toBe(1);
    expect(resolveSessionLimits({ maxMessages: NaN }).maxMessages).toBe(SESSION_LIMITS.maxMessages);
    expect(resolveSessionLimits({ maxMessages: -5 }).maxMessages).toBe(SESSION_LIMITS.maxMessages);
    expect(resolveSessionLimits({ maxMessages: 1.5 }).maxMessages).toBe(SESSION_LIMITS.maxMessages);
    expect(resolveSessionLimits({ maxPlaintextBytes: '9' as never }).maxPlaintextBytes).toBe(
      SESSION_LIMITS.maxPlaintextBytes,
    );
    expect(resolveSessionLimits({ maxPlaintextBytes: 7 })).toEqual({
      ...SESSION_LIMITS,
      maxPlaintextBytes: 7,
    });
    expect(Object.isFrozen(SESSION_LIMITS)).toBe(true);
  });

  it('an override cannot come from the prototype chain', () => {
    const inherited = Object.create({ maxMessages: 1 }) as object;
    expect(resolveSessionLimits(inherited).maxMessages).toBe(SESSION_LIMITS.maxMessages);
    const polluted = JSON.parse('{"__proto__":{"maxMessages":1}}') as object;
    expect(resolveSessionLimits(polluted).maxMessages).toBe(SESSION_LIMITS.maxMessages);
    expect(({} as { maxMessages?: number }).maxMessages).toBeUndefined();
  });
});

describe('sizes are bounded', () => {
  it('the plaintext limit is exact; an empty message is fine; the wire text is capped before parsing', async () => {
    const limits = { maxPlaintextBytes: 10 };
    const { a } = await connect(PA, PB, APP, limits);
    expect((await a.seal(new Uint8Array(10))).ok).toBe(true);
    expect(await a.seal(new Uint8Array(11))).toEqual({ ok: false, reason: 'too-large' });
    expect(a.sent).toBe(1);
    const { a: wide, b: strict } = await connect(PA, PB, APP, undefined, limits);
    const w10 = await wide.seal(new Uint8Array(10));
    const empty = await wide.seal(new Uint8Array(0));
    const w11 = await wide.seal(new Uint8Array(11));
    if (!w10.ok || !w11.ok || !empty.ok) throw new Error('seal');
    expect((await strict.open(w10.text)).ok).toBe(true);
    expect(await strict.open(empty.text)).toMatchObject({ ok: true });
    expect(await strict.open(w11.text)).toEqual({ ok: false, reason: 'bad-message' });
    expect(await a.seal('text' as never)).toEqual({ ok: false, reason: 'bad-input' });
    const huge = `{"m":"demo-msg:2","n":0,"ct":"${'A'.repeat(maxSealedChars(SESSION_LIMITS) + 1)}"}`;
    expect(parseSealedMessage(APP, huge)).toBeUndefined();
    expect(await reasonOf(strict, 'x'.repeat(5_000_000))).toBe('bad-message');
  });

  it('every byte value and a large message round-trip', async () => {
    const { a, b } = await connect(PA, PB);
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    const r1 = await a.seal(all);
    if (!r1.ok) throw new Error('seal');
    const o1 = await b.open(r1.text);
    expect(o1.ok && Buffer.from(o1.plaintext).equals(Buffer.from(all))).toBe(true);
    const big = new Uint8Array(SESSION_LIMITS.maxPlaintextBytes).fill(7);
    const r2 = await a.seal(big);
    if (!r2.ok) throw new Error('seal');
    expect(r2.text.length).toBeLessThanOrEqual(maxSealedChars(SESSION_LIMITS));
    const o2 = await b.open(r2.text);
    expect(o2.ok && o2.plaintext.length === big.length).toBe(true);
    expect(await a.seal(new Uint8Array(big.length + 1))).toMatchObject({ reason: 'too-large' });
  });
});

describe('tamper sweeps: nothing altered is ever accepted', () => {
  it('every character of a sealed message replaced, cut or extended; every bit of the ciphertext flipped', async () => {
    const { a, b } = await connect(PA, PB);
    const w = await seal(a, 'sweep me');
    const swap = (c: string) => (c === 'A' ? 'B' : 'A');
    let refused = 0;
    for (let i = 0; i < w.length; i += 1) {
      const r = await b.open(w.slice(0, i) + swap(w[i] as string) + w.slice(i + 1));
      expect(r.ok, `position ${i}`).toBe(false);
      refused += 1;
    }
    for (let i = 0; i < w.length; i += 1) expect((await b.open(w.slice(0, i))).ok).toBe(false);
    for (const tail of [' ', '}', '\n', 'A', '"}']) expect((await b.open(w + tail)).ok).toBe(false);
    const m = parseSealedMessage(APP, w);
    if (!m) throw new Error('unreadable');
    for (let bit = 0; bit < m.ct.length * 8; bit += 1) {
      const ct = new Uint8Array(m.ct);
      ct[bit >> 3] = (ct[bit >> 3] as number) ^ (1 << (bit & 7));
      expect(
        (await b.open(`{"m":"demo-msg:2","n":0,"ct":"${base64url(ct)}"}`)).ok,
        `bit ${bit}`,
      ).toBe(false);
    }
    expect(refused).toBe(w.length);
    // the original is still accepted: the sweep changed no state
    expect(await opened(b, w)).toBe('sweep me');
  });

  it('every member of a sealed message changed: counter, marker, body', async () => {
    const { a, b } = await connect(PA, PB);
    await seal(a, 'first');
    const w = await seal(a, 'second');
    const m = parseSealedMessage(APP, w);
    if (!m) throw new Error('unreadable');
    for (const n of [0, 2, 3, 2 ** 32, 2 ** 40]) {
      expect((await b.open(`{"m":"demo-msg:2","n":${n},"ct":"${base64url(m.ct)}"}`)).ok).toBe(
        false,
      );
    }
    expect((await b.open(w)).ok).toBe(false); // n = 1 but the receiver still waits for 0: gap
    expect(b.received).toBe(0);
  });

  it('every character of a hello: a changed hello never gives a session that works with the real peer', async () => {
    let unreadable = 0;
    let readable = 0;
    const length = encodeHello(APP, (await createHello(A)).hello).length;
    for (let i = 0; i < length; i += 1) {
      const ea = await createHello(A);
      const eb = await createHello(B);
      const t = encodeHello(APP, ea.hello);
      const flipped = t.slice(0, i) + (t[i] === 'A' ? 'B' : 'A') + t.slice(i + 1);
      const parsed = parseHello(APP, flipped);
      if (!parsed) {
        unreadable += 1;
        continue;
      }
      readable += 1;
      expect(parsed).not.toEqual(ea.hello);
      const real = await openSession({
        appId: APP,
        own: { device: A, agreement: PA.agreement },
        peer: { device: B, dh: PB.dh },
        ephemeral: ea.ephemeral,
        ownHello: ea.hello,
        peerHello: eb.hello,
      });
      const hello2 = await createHello(B);
      const seen = await openSession({
        appId: APP,
        own: { device: B, agreement: PB.agreement },
        peer: { device: A, dh: PA.dh },
        ephemeral: hello2.ephemeral,
        ownHello: hello2.hello,
        peerHello: parsed,
      });
      if (!real.ok || !seen.ok) continue; // refused outright: fine
      expect(await reasonOf(real.session, await seal(seen.session, 'x'))).not.toBe('ok');
    }
    // the structure (marker, member names, quotes) never reads when altered; only characters of the
    // id and of the point can, and the point is then checked on the curve by openSession
    expect(unreadable + readable).toBe(length);
    expect(unreadable).toBeGreaterThan(30);
    expect(readable).toBeGreaterThan(90);
  });
});

describe('seeded fuzzing of the strict readers (never throws, valid and unaliased results)', () => {
  const ROUNDS = 3200;
  let helloText: string;
  let wire: string;
  beforeAll(async () => {
    const { a, helloA } = await connect(PA, PB);
    helloText = encodeHello(APP, helloA);
    wire = await seal(a, 'fuzz');
  });

  function inputs(seed: number, valid: string): string[] {
    const rnd = rng(seed);
    const out: string[] = [];
    for (let i = 0; i < ROUNDS; i += 1) {
      const kind = rnd();
      if (kind < 0.5) out.push(mutate(rnd, valid));
      else if (kind < 0.7) out.push(JSON.stringify(randomValue(rnd)));
      else if (kind < 0.85)
        out.push(
          valid.replace(
            /"[a-z]+":/,
            () => `"${['__proto__', 'constructor', 'toString'][Math.floor(rnd() * 3)]}":`,
          ),
        );
      else
        out.push(
          String.fromCharCode(
            ...Array.from({ length: Math.floor(rnd() * 60) }, () => Math.floor(rnd() * 0x250)),
          ),
        );
    }
    return out;
  }

  it('parseHello', () => {
    let readable = 0;
    for (const input of inputs(11, helloText)) {
      let result: Hello | undefined;
      expect(() => {
        result = parseHello(APP, input);
      }).not.toThrow();
      if (!result) continue;
      readable += 1;
      expect(encodeHello(APP, result)).toBe(input);
      const again = parseHello(APP, input);
      expect(again).toEqual(result);
      expect(again).not.toBe(result);
      expect(Object.keys(result)).toEqual(['device', 'eph']);
    }
    expect(readable).toBeGreaterThan(0);
    expect(({} as Record<string, unknown>).device).toBeUndefined();
  });

  it('parseSealedMessage', () => {
    let readable = 0;
    for (const input of inputs(12, wire)) {
      let result: ReturnType<typeof parseSealedMessage>;
      expect(() => {
        result = parseSealedMessage(APP, input);
      }).not.toThrow();
      if (!result) continue;
      readable += 1;
      expect(`{"m":"demo-msg:2","n":${result.n},"ct":"${base64url(result.ct)}"}`).toBe(input);
      const again = parseSealedMessage(APP, input);
      expect(again?.ct).not.toBe(result.ct);
      expect(again?.ct).toEqual(result.ct);
      result.ct.fill(0); // changing a result changes nothing else
      expect(parseSealedMessage(APP, input)?.ct).toEqual(again?.ct);
    }
    expect(readable).toBeGreaterThan(0);
  });

  it('the opening of a session with arbitrary hello and peer values never throws', async () => {
    const rnd = rng(13);
    for (let i = 0; i < 400; i += 1) {
      const mine = await createHello(A);
      const hello = randomValue(rnd) as never;
      const peer = randomValue(rnd) as never;
      const r = await openSession({
        appId: APP,
        own: { device: A, agreement: PA.agreement },
        peer,
        ephemeral: mine.ephemeral,
        ownHello: mine.hello,
        peerHello: hello,
      });
      expect(r.ok).toBe(false);
    }
  });

  it('open() with arbitrary values never throws and refuses', async () => {
    const { b } = await connect(PA, PB);
    const rnd = rng(14);
    for (let i = 0; i < 600; i += 1) {
      const v = rnd() < 0.5 ? randomValue(rnd) : JSON.stringify(randomValue(rnd));
      const r = await b.open(v);
      expect(r.ok).toBe(false);
    }
    expect(b.received).toBe(0);
  });
});

// A small generator for hostile JSON-like values (members that are in the documents' vocabulary).
function randomValue(rnd: () => number, depth = 0): unknown {
  const leaves: unknown[] = [
    null,
    true,
    0,
    -1,
    1.5,
    1e21,
    '',
    'x',
    'device-' + 'a'.repeat(32),
    'A'.repeat(87),
    'A'.repeat(16),
    '__proto__',
    [],
    {},
  ];
  const r = rnd();
  if (depth > 2 || r < 0.5) return leaves[Math.floor(rnd() * leaves.length)];
  if (r < 0.7)
    return Array.from({ length: Math.floor(rnd() * 3) }, () => randomValue(rnd, depth + 1));
  const names = ['m', 'device', 'eph', 'n', 'ct', '__proto__', 'constructor', 'x'];
  return Object.fromEntries(
    Array.from({ length: Math.floor(rnd() * 5) }, () => [
      names[Math.floor(rnd() * names.length)],
      randomValue(rnd, depth + 1),
    ]),
  );
}

describe('the session leaks no more than documented', () => {
  it('the wire text of a message holds neither plaintext nor ids; a hello holds the id in the clear', async () => {
    const { a, helloA } = await connect(PA, PB);
    const w = await seal(a, 'very secret words');
    expect(w).not.toContain('secret');
    expect(w).not.toContain(A);
    expect(w).not.toContain(B);
    expect(encodeHello(APP, helloA)).toContain(A);
    // the length of a message does show: ciphertext = plaintext + 16 bytes
    const m = parseSealedMessage(APP, w);
    expect(m?.ct.length).toBe('very secret words'.length + 16);
  });
});
