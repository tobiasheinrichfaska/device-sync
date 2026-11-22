import { beforeAll, describe, expect, it } from 'vitest';
import {
  FILE_LIMITS,
  base64url,
  fromBase64url,
  maxFileBytes,
  openFile,
  readFileHeader,
  resolveFileLimits,
  sealFile,
} from '../../src/core/index.ts';
import { jwkToPoint, refFile, refFileSeal, refOpen } from './reference.ts';
import {
  A,
  APP,
  B,
  C,
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

let counter = 0;
/** 12 distinct bytes per call (the tests supply the "randomness"). */
const random = (): Uint8Array => {
  counter += 1;
  const out = new Uint8Array(12);
  new DataView(out.buffer).setUint32(8, counter);
  out[0] = 0x5a;
  return out;
};

async function make(
  from: Party,
  to: Party,
  payload: string | Uint8Array,
  appId = APP,
  limits?: { maxPlaintextBytes: number },
): Promise<Uint8Array> {
  const r = await sealFile({
    appId,
    own: { device: from.device, agreement: from.agreement },
    to: { device: to.device, dh: to.dh },
    payload: typeof payload === 'string' ? text(payload) : payload,
    random: random(),
    ...(limits ? { limits } : {}),
  });
  if (!r.ok) throw new Error(r.reason);
  return r.file;
}

const open = (
  me: Party,
  from: { device: string; dh: string },
  file: Uint8Array,
  appId = APP,
  limits?: { maxPlaintextBytes: number },
) =>
  openFile({
    appId,
    own: { device: me.device, agreement: me.agreement },
    from,
    file,
    ...(limits ? { limits } : {}),
  });

const reasonOf = async (...args: Parameters<typeof open>): Promise<string> => {
  const r = await open(...args);
  return r.ok ? 'ok' : r.reason;
};

const asText = (file: Uint8Array): string => new TextDecoder().decode(file);
const json = (file: Uint8Array): Record<string, string> =>
  JSON.parse(asText(file)) as Record<string, string>;
const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);

describe('the file between two known devices (cases of both earlier implementations)', () => {
  it('B opens what A made for it; nothing readable in the file', async () => {
    const file = await make(PA, PB, '{"items":["Mia","Ben"],"secret":"k1"}');
    expect(asText(file)).not.toMatch(/Mia|Ben|secret|items/);
    expect(readFileHeader(APP, file)).toEqual({ from: A, to: B });
    const opened = await open(PB, PA, file);
    expect(opened.ok && opened.from).toBe(A);
    expect(opened.ok && show(opened.payload)).toBe('{"items":["Mia","Ben"],"secret":"k1"}');
  });

  it('a third device cannot open it, not even by naming itself as receiver', async () => {
    const file = await make(PA, PB, 'for B');
    expect(await open(PC, PA, file)).toEqual({ ok: false, reason: 'wrong-recipient' });
    const respelled = bytes(asText(file).replace(`"to":"${B}"`, `"to":"${C}"`));
    expect(readFileHeader(APP, respelled)).toEqual({ from: A, to: C });
    expect(await open(PC, PA, respelled)).toEqual({ ok: false, reason: 'cannot-open' });
  });

  it('a file that only claims to be from A does not open', async () => {
    const real = await make(PC, PB, 'made by C');
    const claimed = bytes(asText(real).replace(`"from":"${C}"`, `"from":"${A}"`));
    expect(readFileHeader(APP, claimed)?.from).toBe(A);
    expect(await open(PB, PA, claimed)).toEqual({ ok: false, reason: 'cannot-open' });
    // C cannot open it as A either: C simply is not A
    expect(await open(PB, { device: A, dh: PC.dh }, claimed)).toEqual({
      ok: false,
      reason: 'cannot-open',
    });
  });

  it('something else is no file of this app', async () => {
    const file = await make(PA, PB, 'x');
    const other: Uint8Array[] = [
      bytes('{"m":"demo-sync:1"}'),
      bytes('{"m":"demo-file:2"}'),
      bytes(asText(file).replace('demo-file:2', 'demo-file:1')), // an older generation
      bytes(asText(file).replace('demo-file:2', 'other-file:2')),
      new Uint8Array([0xff]),
      new Uint8Array(0),
      bytes('null'),
      bytes('[]'),
      bytes('hello'),
    ];
    for (const o of other) {
      expect(readFileHeader(APP, o)).toBeUndefined();
      expect(await open(PB, PA, o)).toEqual({ ok: false, reason: 'not-a-file' });
    }
    for (const v of [undefined, null, 'string', 5, {}, [1, 2]]) {
      expect(readFileHeader(APP, v)).toBeUndefined();
      expect(await open(PB, PA, v as never)).toEqual({ ok: false, reason: 'not-a-file' });
    }
  });

  it('only the named receiver opens it, and only from the named sender', async () => {
    const file = await make(PA, PB, 'Smilla');
    // wrong receiver id
    expect(await reasonOf(PC, PA, file)).toBe('wrong-recipient');
    // C's keys under B's id: the id matches, the key does not
    expect(await reasonOf({ ...PC, device: B }, PA, file)).toBe('cannot-open');
    // wrong sender id, wrong sender key
    expect(await reasonOf(PB, { device: C, dh: PC.dh }, file)).toBe('wrong-sender');
    expect(await reasonOf(PB, { device: A, dh: PC.dh }, file)).toBe('cannot-open');
    // the first character of the ciphertext changed
    const f = json(file);
    const first = f.ct?.[0] === 'A' ? 'B' : 'A';
    const altered = bytes(asText(file).replace(`"ct":"${f.ct?.[0]}`, `"ct":"${first}`));
    expect(await reasonOf(PB, PA, altered)).toBe('cannot-open');
    expect(await reasonOf(PB, PA, file)).toBe('ok');
  });

  it('a file to oneself is refused when made and never read', async () => {
    expect(
      await sealFile({
        appId: APP,
        own: { device: A, agreement: PA.agreement },
        to: { device: A, dh: PB.dh },
        payload: text('x'),
        random: random(),
      }),
    ).toEqual({ ok: false, reason: 'same-device' });
    const file = await make(PA, PB, 'x');
    const loop = bytes(asText(file).replace(`"to":"${B}"`, `"to":"${A}"`));
    expect(readFileHeader(APP, loop)).toBeUndefined();
  });
});

describe('what goes in and what comes out', () => {
  it('every byte value, an empty payload and a large payload round-trip', async () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    for (const payload of [all, new Uint8Array(0), new Uint8Array(1_000_000).fill(9)]) {
      const file = await make(PA, PB, payload);
      const r = await open(PB, PA, file);
      expect(r.ok && Buffer.from(r.payload).equals(Buffer.from(payload))).toBe(true);
    }
  });

  it('a result is a fresh copy and the input is not changed', async () => {
    const payload = text('stay');
    const file = await make(PA, PB, payload);
    expect(show(payload)).toBe('stay');
    const copy = new Uint8Array(file);
    const r1 = await open(PB, PA, file);
    const r2 = await open(PB, PA, file);
    expect(file).toEqual(copy);
    if (!r1.ok || !r2.ok) throw new Error('open');
    expect(r1.payload).not.toBe(r2.payload);
    r1.payload.fill(0);
    expect(show(r2.payload)).toBe('stay');
  });

  it('the file is the documented compact JSON in the documented order', async () => {
    const file = await make(PA, PB, 'x');
    expect(asText(file)).toMatch(
      new RegExp(
        `^\\{"m":"demo-file:2","from":"${A}","to":"${B}","eph":"[A-Za-z0-9_-]{87}","iv":"[A-Za-z0-9_-]{16}","ct":"[A-Za-z0-9_-]{23}"\\}$`,
      ),
    );
  });

  it('two files of one payload differ (a fresh ephemeral key each); a repeated nonce is harmless', async () => {
    const r = new Uint8Array(12).fill(7);
    const seal = async () => {
      const x = await sealFile({
        appId: APP,
        own: { device: A, agreement: PA.agreement },
        to: { device: B, dh: PB.dh },
        payload: text('same payload'),
        random: r,
      });
      if (!x.ok) throw new Error(x.reason);
      return x.file;
    };
    const [f1, f2] = [await seal(), await seal()];
    expect(json(f1).iv).toBe(json(f2).iv); // the caller repeated the nonce
    expect(json(f1).eph).not.toBe(json(f2).eph); // ... the key is still fresh
    expect(json(f1).ct).not.toBe(json(f2).ct);
    expect(await reasonOf(PB, PA, f1)).toBe('ok');
    expect(await reasonOf(PB, PA, f2)).toBe('ok');
  });

  it('every file uses a key of its own: 600 files, 600 different ephemeral keys', async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 600; i += 1) seen.add(json(await make(PA, PB, 'x')).eph as string);
    expect(seen.size).toBe(600);
  });
});

describe('refusals when making a file', () => {
  const base = () => ({
    appId: APP,
    own: { device: A, agreement: PA.agreement },
    to: { device: B, dh: PB.dh },
    payload: text('x'),
    random: random(),
  });
  const code = async (over: Record<string, unknown>) =>
    (await sealFile({ ...base(), ...over } as ReturnType<typeof base>)) as {
      ok: boolean;
      reason?: string;
    };

  it('answers with codes, never throws on foreign values', async () => {
    const off = base64url(Uint8Array.from([4, ...new Array(64).fill(0)]));
    expect(await code({ to: { device: B, dh: off } })).toMatchObject({ reason: 'bad-recipient' });
    expect(await code({ to: { device: B, dh: 'AA' } })).toMatchObject({ reason: 'bad-recipient' });
    expect(await code({ to: { device: 'a|b', dh: PB.dh } })).toMatchObject({
      reason: 'bad-recipient',
    });
    expect(await code({ to: null })).toMatchObject({ reason: 'bad-recipient' });
    expect(await code({ to: { device: B, dh: PA.dh } })).toMatchObject({ reason: 'same-key' });
    expect(await code({ own: { device: '', agreement: PA.agreement } })).toMatchObject({
      reason: 'bad-own',
    });
    expect(await code({ own: undefined })).toMatchObject({ reason: 'bad-own' });
    expect(await code({ own: { device: A, agreement: PA.keys.signing } })).toMatchObject({
      reason: 'crypto-failure',
    });
    expect(await code({ random: new Uint8Array(11) })).toMatchObject({ reason: 'bad-random' });
    expect(await code({ random: new Uint8Array(13) })).toMatchObject({ reason: 'bad-random' });
    expect(await code({ random: [1, 2, 3] })).toMatchObject({ reason: 'bad-random' });
    expect(await code({ payload: 'text' })).toMatchObject({ reason: 'bad-input' });
    expect(await code({})).toMatchObject({ ok: true });
    await expect(sealFile({ ...base(), appId: 'Bad App' })).rejects.toThrow();
  });

  it('refusals when opening are codes too', async () => {
    const file = await make(PA, PB, 'x');
    const mk = (over: Record<string, unknown>) =>
      openFile({
        appId: APP,
        own: { device: B, agreement: PB.agreement },
        from: { device: A, dh: PA.dh },
        file,
        ...over,
      } as never);
    expect(await mk({ from: { device: A, dh: 'AA' } })).toEqual({
      ok: false,
      reason: 'bad-sender',
    });
    expect(await mk({ from: null })).toEqual({ ok: false, reason: 'bad-sender' });
    expect(await mk({ own: null })).toEqual({ ok: false, reason: 'bad-own' });
    expect(await mk({ own: { device: B, agreement: undefined } })).toEqual({
      ok: false,
      reason: 'bad-own',
    });
    const off = base64url(Uint8Array.from([4, ...new Array(64).fill(1)]));
    expect(await mk({ from: { device: A, dh: off } })).toEqual({ ok: false, reason: 'bad-point' });
    const badEph = bytes(asText(file).replace(json(file).eph as string, off));
    expect(await open(PB, PA, badEph)).toEqual({ ok: false, reason: 'bad-point' });
    expect(await mk({})).toMatchObject({ ok: true });
  });
});

describe('sizes are bounded', () => {
  it('the payload limit is exact at both ends', async () => {
    const limits = { maxPlaintextBytes: 100 };
    const file = await make(PA, PB, new Uint8Array(100).fill(1), APP, limits);
    expect(await reasonOf(PB, PA, file, APP, limits)).toBe('ok');
    await expect(make(PA, PB, new Uint8Array(101), APP, limits)).rejects.toThrow('too-large');
    // a file made under a larger limit is refused by a reader with a smaller one, before any parsing
    const bigger = await make(PA, PB, new Uint8Array(101), APP, { maxPlaintextBytes: 101 });
    expect(await reasonOf(PB, PA, bigger, APP, limits)).toBe('not-a-file');
    expect(readFileHeader(APP, bigger, limits)).toBeUndefined();
    expect(await reasonOf(PB, PA, bigger, APP, { maxPlaintextBytes: 101 })).toBe('ok');
  });

  it('a file over the byte cap is refused without being read; the cap follows the limit', async () => {
    const limits = { maxPlaintextBytes: 50 };
    const cap = maxFileBytes(resolveFileLimits(limits));
    expect(cap).toBeGreaterThan(maxFileBytes({ maxPlaintextBytes: 0 }));
    expect(readFileHeader(APP, new Uint8Array(cap + 1).fill(0x7b), limits)).toBeUndefined();
    expect(await reasonOf(PB, PA, new Uint8Array(cap + 1).fill(0x41), APP, limits)).toBe(
      'not-a-file',
    );
  });

  it('the defaults and the overrides', () => {
    expect(FILE_LIMITS.maxPlaintextBytes).toBe(33_554_432);
    expect(Object.isFrozen(FILE_LIMITS)).toBe(true);
    expect(resolveFileLimits({ maxPlaintextBytes: NaN })).toEqual(FILE_LIMITS);
    expect(resolveFileLimits({ maxPlaintextBytes: -1 })).toEqual(FILE_LIMITS);
    expect(resolveFileLimits({ maxPlaintextBytes: 3 }).maxPlaintextBytes).toBe(3);
    expect(resolveFileLimits(Object.create({ maxPlaintextBytes: 3 }) as object)).toEqual(
      FILE_LIMITS,
    );
  });
});

describe("two apps never open each other's files", () => {
  it('another app id reads nothing; relabelling the marker does not help', async () => {
    const file = await make(PA, PB, 'demo only', 'demo');
    expect(readFileHeader('other', file)).toBeUndefined();
    expect(await reasonOf(PB, PA, file, 'other')).toBe('not-a-file');
    const relabelled = bytes(asText(file).replace('demo-file:2', 'other-file:2'));
    expect(readFileHeader('other', relabelled)).toBeDefined();
    expect(await reasonOf(PB, PA, relabelled, 'other')).toBe('cannot-open');
    expect(await reasonOf(PB, PA, file, 'demo')).toBe('ok');
  });
});

describe('tamper sweeps: nothing altered is ever accepted', () => {
  it('every character of the file replaced, every prefix, every extension', async () => {
    const file = await make(PA, PB, 'sweep');
    const s = asText(file);
    for (let i = 0; i < s.length; i += 1) {
      const c = s[i] === 'A' ? 'B' : 'A';
      const r = await open(PB, PA, bytes(s.slice(0, i) + c + s.slice(i + 1)));
      expect(r.ok, `position ${i}`).toBe(false);
    }
    for (let i = 0; i < s.length; i += 1)
      expect((await open(PB, PA, bytes(s.slice(0, i)))).ok).toBe(false);
    for (const tail of [' ', '\n', '}', 'A', '\u0000'])
      expect((await open(PB, PA, bytes(s + tail))).ok).toBe(false);
    expect((await open(PB, PA, new Uint8Array([...file, 0]))).ok).toBe(false);
    expect((await open(PB, PA, new Uint8Array([0xef, 0xbb, 0xbf, ...file]))).ok).toBe(false);
    expect(await reasonOf(PB, PA, file)).toBe('ok');
  });

  it('every bit of the ephemeral key, the nonce and the ciphertext flipped', async () => {
    const file = await make(PA, PB, 'bits');
    const f = json(file);
    const frame = (g: Record<string, string>) =>
      bytes(
        `{"m":"demo-file:2","from":"${A}","to":"${B}","eph":"${g.eph}","iv":"${g.iv}","ct":"${g.ct}"}`,
      );
    for (const member of ['eph', 'iv', 'ct'] as const) {
      const raw = fromBase64url(f[member] as string);
      for (let bit = 0; bit < raw.length * 8; bit += 1) {
        const flipped = new Uint8Array(raw);
        flipped[bit >> 3] = (flipped[bit >> 3] as number) ^ (1 << (bit & 7));
        const r = await open(PB, PA, frame({ ...f, [member]: base64url(flipped) }));
        expect(r.ok, `${member} bit ${bit}`).toBe(false);
      }
    }
    expect(await reasonOf(PB, PA, file)).toBe('ok');
  });

  it('members swapped between two files, and header fields swapped, never open', async () => {
    const f1 = json(await make(PA, PB, 'one'));
    const f2 = json(await make(PA, PB, 'two'));
    const frame = (o: Record<string, string>) =>
      bytes(
        `{"m":"demo-file:2","from":"${o.from}","to":"${o.to}","eph":"${o.eph}","iv":"${o.iv}","ct":"${o.ct}"}`,
      );
    for (const member of ['eph', 'iv', 'ct']) {
      expect((await open(PB, PA, frame({ ...f1, [member]: f2[member] as string }))).ok).toBe(false);
    }
    expect((await open(PB, PA, frame(f1))).ok).toBe(true);
    // A's file to B turned into B's file to A (the same bytes under the other direction)
    const turned = frame({ ...f1, from: B, to: A });
    expect(await reasonOf(PA, PB, turned)).toBe('cannot-open');
    expect(await reasonOf(PA, PB, turned)).not.toBe('ok');
  });
});

describe('the documented derivation reproduces the bytes (independent reference implementation)', () => {
  it('a file made by the library opens with node:crypto, and a file made with node:crypto opens in the library', async () => {
    const sa = await extractablePair();
    const sb = await extractablePair();
    const [pa, pb] = [await pairFromJwk(sa.jwk), await pairFromJwk(sb.jwk)];
    const dhA = jwkToPoint(sa.jwk);
    const dhB = jwkToPoint(sb.jwk);
    const sealed = await sealFile({
      appId: APP,
      own: { device: A, agreement: pa },
      to: { device: B, dh: dhB },
      payload: text('library to reference'),
      random: random(),
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    const f = json(sealed.file);
    const k = refFile(
      APP,
      { from: A, to: B, fromDh: dhA, toDh: dhB, eph: f.eph as string },
      { toPriv: sb.jwk },
    );
    const ct = Buffer.from(f.ct as string, 'base64url');
    expect(
      show(refOpen(k.key, Buffer.from(f.iv as string, 'base64url'), k.header, ct) as Buffer),
    ).toBe('library to reference');
    // the other way round: the reference makes the file
    const e = await extractablePair();
    const made = refFileSeal(
      APP,
      { from: A, to: B, fromDh: dhA, toDh: dhB, eph: jwkToPoint(e.jwk) },
      { fromPriv: sa.jwk, ephPriv: e.jwk },
      Buffer.alloc(12, 3),
      text('reference to library'),
    );
    const r = await openFile({
      appId: APP,
      own: { device: B, agreement: pb },
      from: { device: A, dh: dhA },
      file: made,
    });
    expect(r.ok && show(r.payload)).toBe('reference to library');
  });

  it('what the header text binds: a changed id, key, ephemeral key or app gives another key', async () => {
    const sa = await extractablePair();
    const sb = await extractablePair();
    const e = await extractablePair();
    const o = {
      from: A,
      to: B,
      fromDh: jwkToPoint(sa.jwk),
      toDh: jwkToPoint(sb.jwk),
      eph: jwkToPoint(e.jwk),
    };
    const key = (over: Partial<typeof o>, appId = APP) =>
      refFile(appId, { ...o, ...over }, { fromPriv: sa.jwk, ephPriv: e.jwk }).key.toString('hex');
    const base = key({});
    expect(key({ from: C })).not.toBe(base);
    expect(key({ to: C })).not.toBe(base);
    expect(key({}, 'other')).not.toBe(base);
    // swapping the ids of two fields cannot give the same text (length prefixes)
    const x = refFile(APP, { ...o, from: 'ab', to: 'c' }, { fromPriv: sa.jwk, ephPriv: e.jwk });
    const y = refFile(APP, { ...o, from: 'a', to: 'bc' }, { fromPriv: sa.jwk, ephPriv: e.jwk });
    expect(x.header).not.toBe(y.header);
  });
});

describe('what a file does NOT protect (documented limits, shown here so they stay true to the text)', () => {
  it('whoever holds the recipient\'s static secret can make a file that opens as "from A"', async () => {
    const sa = await extractablePair();
    const sb = await extractablePair();
    const e = await extractablePair();
    const pb = await pairFromJwk(sb.jwk);
    const dhA = jwkToPoint(sa.jwk);
    const dhB = jwkToPoint(sb.jwk);
    const forged = refFileSeal(
      APP,
      { from: A, to: B, fromDh: dhA, toDh: dhB, eph: jwkToPoint(e.jwk) },
      { toPriv: sb.jwk, ephPriv: e.jwk }, // no secret of A's anywhere
      Buffer.alloc(12, 1),
      text('forged'),
    );
    const r = await openFile({
      appId: APP,
      own: { device: B, agreement: pb },
      from: { device: A, dh: dhA },
      file: forged,
    });
    expect(r.ok && show(r.payload)).toBe('forged');
  });

  it("whoever holds the recipient's static secret opens every file ever made for it (no forward secrecy for files)", async () => {
    const sa = await extractablePair();
    const sb = await extractablePair();
    const [pa] = [await pairFromJwk(sa.jwk)];
    const dhA = jwkToPoint(sa.jwk);
    const dhB = jwkToPoint(sb.jwk);
    const sealed = await sealFile({
      appId: APP,
      own: { device: A, agreement: pa },
      to: { device: B, dh: dhB },
      payload: text('old file'),
      random: random(),
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    const f = json(sealed.file);
    const k = refFile(
      APP,
      { from: A, to: B, fromDh: dhA, toDh: dhB, eph: f.eph as string },
      { toPriv: sb.jwk },
    );
    const opened = refOpen(
      k.key,
      Buffer.from(f.iv as string, 'base64url'),
      k.header,
      Buffer.from(f.ct as string, 'base64url'),
    );
    expect(opened && show(opened)).toBe('old file');
  });

  it("the sender's static secret alone does not open its own old file (only the recipient can)", async () => {
    const sa = await extractablePair();
    const sb = await extractablePair();
    const pa = await pairFromJwk(sa.jwk);
    const dhA = jwkToPoint(sa.jwk);
    const dhB = jwkToPoint(sb.jwk);
    const sealed = await sealFile({
      appId: APP,
      own: { device: A, agreement: pa },
      to: { device: B, dh: dhB },
      payload: text('sender cannot reopen'),
      random: random(),
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    const f = json(sealed.file);
    // the sender knows its static secret and everything public, but the ephemeral secret is gone:
    // any stand-in for it (here its own static secret) gives a key that does not open the file
    const info = { from: A, to: B, fromDh: dhA, toDh: dhB, eph: f.eph as string };
    const header = refFile(APP, info, { toPriv: sb.jwk }).header;
    const wrong = refFile(APP, info, { fromPriv: sa.jwk, ephPriv: sa.jwk });
    const iv = Buffer.from(f.iv as string, 'base64url');
    const ct = Buffer.from(f.ct as string, 'base64url');
    expect(refOpen(wrong.key, iv, header, ct)).toBeUndefined();
  });
});

describe('seeded fuzzing of the strict reader (never throws, valid and unaliased results)', () => {
  let valid: string;
  beforeAll(async () => {
    valid = asText(await make(PA, PB, 'fuzz'));
  });

  it('readFileHeader: 3200 inputs', () => {
    const rnd = rng(21);
    let readable = 0;
    for (let i = 0; i < 3200; i += 1) {
      const kind = rnd();
      let input: Uint8Array;
      if (kind < 0.55) input = bytes(mutate(rnd, valid));
      else if (kind < 0.7) {
        input = bytes(
          valid.replace(
            /"[a-z]+":/,
            () => `"${['__proto__', 'constructor', 'toString'][Math.floor(rnd() * 3)]}":`,
          ),
        );
      } else if (kind < 0.85)
        input = Uint8Array.from({ length: Math.floor(rnd() * 80) }, () => Math.floor(rnd() * 256));
      else
        input = bytes(
          JSON.stringify(
            Object.fromEntries([
              ['m', 'demo-file:2'],
              ['from', A],
              ['to', rnd() < 0.5 ? B : A],
              ['eph', 'A'.repeat(87)],
              ['iv', 'A'.repeat(16)],
              ['ct', 'A'.repeat(22)],
            ]),
          ),
        );
      let header: ReturnType<typeof readFileHeader>;
      expect(() => {
        header = readFileHeader(APP, input);
      }).not.toThrow();
      if (!header) continue;
      readable += 1;
      const again = readFileHeader(APP, input);
      expect(again).toEqual(header);
      expect(again).not.toBe(header);
      expect(Object.keys(header)).toEqual(['from', 'to']);
      expect(header.from).not.toBe(header.to);
    }
    expect(readable).toBeGreaterThan(0);
    expect(({} as Record<string, unknown>).from).toBeUndefined();
  });

  it('openFile with arbitrary bytes never throws and never opens', async () => {
    const rnd = rng(22);
    for (let i = 0; i < 300; i += 1) {
      const input =
        rnd() < 0.7
          ? bytes(mutate(rnd, valid))
          : Uint8Array.from({ length: Math.floor(rnd() * 200) }, () => Math.floor(rnd() * 256));
      const r = await open(PB, PA, input);
      if (asText(input) !== valid) expect(r.ok).toBe(false);
    }
  });
});
