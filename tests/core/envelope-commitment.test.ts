// Key commitment of the envelope (round 5 follow-up). AES-GCM does not commit to its key: an author
// can craft ONE ciphertext (and tag) that decrypts under two different content keys. If the author
// wraps one key for reader A and the other for reader B, the two readers would decrypt different
// bytes under one envelope id. The envelope therefore carries `kc`, a commitment to the content key,
// and every reader checks it against the key its slot gave it BEFORE it decrypts the content.
//
// The crafting below solves the GCM tag equation for one free ciphertext block (GF(2^128), written
// from the specification of GHASH), with `node:crypto` only. One block of the two plaintexts is then
// random-looking, so a full attack that also keeps both insides valid JSON needs about 2^64 tries
// of grinding keys: out of reach for a test. What the test shows is the part that matters for the
// fix: the colliding ciphertext opens under both keys as an AEAD (the premise), a reader without
// the commitment rule would take both keys, and the reader of this package refuses the wrong key
// before it decrypts anything.
import { createCipheriv, generateKeyPairSync, randomBytes } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { base64url, readEnvelope } from '../../src/core/index.ts';
import { jwkToPoint, type PrivateJwk } from './reference.ts';
import {
  gcm,
  refCommit,
  refHeader,
  refId,
  refKek,
  refText,
  ungcm,
  type EnvelopeParts,
} from './envelope-reference.ts';
import { dh } from './reference.ts';
import {
  APP,
  DAY,
  member,
  open,
  reader,
  seal,
  type Member,
  type Reader,
} from './envelope-helpers.ts';

const R = 0xe1n << 120n;
const ONE = 1n << 127n;
const big = (b: Buffer): bigint => BigInt(`0x${b.toString('hex') || '0'}`);
const buf = (n: bigint): Buffer => Buffer.from(n.toString(16).padStart(32, '0'), 'hex');

function gmul(x: bigint, y: bigint): bigint {
  let z = 0n;
  let v = y;
  for (let i = 0; i < 128; i += 1) {
    if ((x >> BigInt(127 - i)) & 1n) z ^= v;
    v = v & 1n ? (v >> 1n) ^ R : v >> 1n;
  }
  return z;
}

function inverse(x: bigint): bigint {
  let result = ONE;
  for (let i = 0; i < 127; i += 1) result = gmul(gmul(result, result), x);
  return gmul(result, result); // x^(2^128 - 2)
}

const ecb = (key: Buffer, block: Buffer): Buffer => {
  const c = createCipheriv('aes-256-ecb', key, null).setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
};

const pad16 = (b: Buffer): Buffer => Buffer.concat([b, Buffer.alloc((16 - (b.length % 16)) % 16)]);

/** GHASH over the additional data and the ciphertext (a whole number of blocks). */
function ghash(h: bigint, aad: Buffer, ct: Buffer): bigint {
  let y = 0n;
  const feed = (data: Buffer): void => {
    for (let i = 0; i < data.length; i += 16) y = gmul(y ^ big(data.subarray(i, i + 16)), h);
  };
  feed(pad16(aad));
  feed(ct);
  const lengths = Buffer.alloc(16);
  lengths.writeBigUInt64BE(BigInt(aad.length) * 8n, 0);
  lengths.writeBigUInt64BE(BigInt(ct.length) * 8n, 8);
  return gmul(y ^ big(lengths), h);
}

function keystream(key: Buffer, iv: Buffer, length: number): Buffer {
  const out: Buffer[] = [];
  for (let n = 0; n * 16 < length; n += 1) {
    out.push(ecb(key, Buffer.concat([iv, Buffer.from([0, 0, 0, n + 2])])));
  }
  return Buffer.concat(out).subarray(0, length);
}

const xor = (a: Buffer, b: Buffer): Buffer => Buffer.from(a.map((v, i) => v ^ (b[i] as number)));

/** One ciphertext || tag that is valid under both keys (same nonce and additional data). */
function collide(k1: Buffer, k2: Buffer, iv: Buffer, aad: Buffer, free: Buffer): Buffer {
  const h1 = big(ecb(k1, Buffer.alloc(16)));
  const h2 = big(ecb(k2, Buffer.alloc(16)));
  const e1 = big(ecb(k1, Buffer.concat([iv, Buffer.from([0, 0, 0, 1])])));
  const e2 = big(ecb(k2, Buffer.concat([iv, Buffer.from([0, 0, 0, 1])])));
  // the last block X is followed only by the length block: tag_i(X) = tag_i(0) ^ X * H_i^2
  const body = Buffer.concat([free, Buffer.alloc(16)]);
  const t1 = ghash(h1, aad, body) ^ e1;
  const t2 = ghash(h2, aad, body) ^ e2;
  const x = gmul(t1 ^ t2, inverse(gmul(h1, h1) ^ gmul(h2, h2)));
  const ct = Buffer.concat([free, buf(x)]);
  return Buffer.concat([ct, buf(ghash(h1, aad, ct) ^ e1)]);
}

let A: Member;
let readerA: Reader;
let readerB: Reader;
beforeAll(async () => {
  A = await member('device-aaaa');
  [readerA, readerB] = await Promise.all([reader(), reader()]);
});
afterEach(() => vi.restoreAllMocks());

function craft(commitTo: 1 | 2): {
  text: string;
  k1: Buffer;
  k2: Buffer;
  iv: Buffer;
  header: string;
  ct: Buffer;
} {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ephPriv = privateKey.export({ format: 'jwk' }) as PrivateJwk;
  const eph = jwkToPoint(ephPriv);
  const header = refHeader(APP, DAY, eph);
  const k1 = randomBytes(32);
  const k2 = randomBytes(32);
  const iv = randomBytes(12);
  const ct = collide(k1, k2, iv, Buffer.from(header), randomBytes(16));
  const slot = (key: Buffer, r: Reader): string =>
    base64url(gcm(refKek(APP, dh(ephPriv, r.dh), header, r.dh), Buffer.alloc(12), undefined, key));
  const slots = [
    slot(k1, readerA),
    slot(k2, readerB),
    ...Array.from({ length: 6 }, () => base64url(randomBytes(48))),
  ];
  const parts: EnvelopeParts = {
    day: DAY,
    eph,
    iv: base64url(iv),
    kc: refCommit(APP, header, commitTo === 1 ? k1 : k2),
    ct: base64url(ct),
    k: slots,
  };
  const text = refText(APP, refId(APP, parts), parts);
  return { text, k1, k2, iv, header, ct };
}

describe('key commitment', () => {
  it('premise: one ciphertext and tag opens under two different keys (AES-GCM does not commit)', () => {
    const { k1, k2, iv, header, ct } = craft(1);
    const p1 = ungcm(k1, iv, header, ct);
    const p2 = ungcm(k2, iv, header, ct);
    expect(p1).toBeDefined();
    expect(p2).toBeDefined();
    expect(Buffer.compare(p1 as Buffer, p2 as Buffer)).not.toBe(0);
    // and it is the same as the plain construction says: the plaintexts are ct xor the two key streams
    expect(p1).toEqual(xor(ct.subarray(0, 32), keystream(k1, iv, 32)));
  });

  it('a reader without the commitment rule would take both keys (what the old code did)', () => {
    const { text, k1, k2, iv, header } = craft(1);
    const raw = JSON.parse(text) as { ct: string };
    const data = Buffer.from(raw.ct, 'base64url');
    const insides = [k1, k2].map((k) => ungcm(k, iv, header, data)?.toString('hex'));
    expect(insides[0]).toBeDefined();
    expect(insides[1]).toBeDefined();
    expect(insides[0]).not.toBe(insides[1]);
  });

  it.each([1, 2] as const)(
    'every reader whose key is not the committed one is refused before the content is decrypted (commit to key %i)',
    async (commitTo) => {
      const { text } = craft(commitTo);
      expect(readEnvelope(APP, text)).toBeDefined();
      const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
      const ofA = await open(readerA, text, {});
      const ofB = await open(readerB, text, {});
      // only the content decryption carries additional data (the header); slots do not
      const contentDecryptions = decrypt.mock.calls.filter(
        ([params]) => (params as { additionalData?: unknown }).additionalData !== undefined,
      ).length;
      const wrong = commitTo === 1 ? ofB : ofA;
      const right = commitTo === 1 ? ofA : ofB;
      expect(wrong).toEqual({ ok: false, reason: 'key-mismatch' });
      // the committed key goes on to the content (here it is garbage: the free block); the other
      // reader never reaches the content
      expect(right).toEqual({ ok: false, reason: 'damaged' });
      expect(contentDecryptions).toBe(1);
    },
  );

  it('a changed commitment is never accepted, an honest envelope opens for every reader', async () => {
    const r3 = await reader();
    const e = await seal(A, [readerA.dh, readerB.dh, r3.dh], { body: 'same for all' });
    for (const r of [readerA, readerB, r3]) {
      const got = await open(r, e, { [A.device]: A.sig });
      expect(got.ok && Buffer.from(got.body).toString()).toBe('same for all');
    }
    const parts = JSON.parse(e.text) as EnvelopeParts;
    const other = { ...parts, kc: refCommit(APP, refHeader(APP, DAY, parts.eph), randomBytes(32)) };
    const text = refText(APP, refId(APP, other), other);
    expect(await open(readerA, text, { [A.device]: A.sig })).toEqual({
      ok: false,
      reason: 'key-mismatch',
    });
  });
});
