// An independent implementation of Web Push encryption (RFC 8291 / RFC 8188) and of VAPID checking, written
// from the RFC texts with node:crypto only (no code of src/). The tests use it to show that the package
// agrees with an implementation that shares none of its code, and to play an attacker.
import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createPublicKey,
  createVerify,
  hkdfSync,
} from 'node:crypto';

export const b64 = (buf: Uint8Array): string => Buffer.from(buf).toString('base64url');
export const unb64 = (text: string): Buffer => Buffer.from(text, 'base64url');

const hk = (ikm: Buffer, salt: Buffer, info: Buffer, n: number): Buffer =>
  Buffer.from(hkdfSync('sha256', ikm, salt, info, n));

export function refKeys(
  ecdhSecret: Buffer,
  uaPublic: Buffer,
  asPublic: Buffer,
  auth: Buffer,
  salt: Buffer,
) {
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]);
  const ikm = hk(ecdhSecret, auth, keyInfo, 32);
  return {
    ikm,
    cek: hk(ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16),
    nonce: hk(ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12),
  };
}

/** The sender's side: private scalar given (or drawn), receiver's public point, one record. */
export function refEncrypt(p: {
  plaintext: Buffer;
  uaPublic: Buffer;
  auth: Buffer;
  salt: Buffer;
  asPrivate: Buffer;
  padding?: number;
  rs?: number;
}): Buffer {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(p.asPrivate);
  const asPublic = ecdh.getPublicKey();
  const { cek, nonce } = refKeys(
    ecdh.computeSecret(p.uaPublic),
    p.uaPublic,
    asPublic,
    p.auth,
    p.salt,
  );
  const rs = p.rs ?? 4096;
  const record = Buffer.concat([p.plaintext, Buffer.from([2]), Buffer.alloc(p.padding ?? 0)]);
  const c = createCipheriv('aes-128-gcm', cek, nonce);
  const sealed = Buffer.concat([c.update(record), c.final(), c.getAuthTag()]);
  const rsBytes = Buffer.alloc(4);
  rsBytes.writeUInt32BE(rs);
  return Buffer.concat([p.salt, rsBytes, Buffer.from([asPublic.length]), asPublic, sealed]);
}

/** The receiver's side; undefined when the tag does not verify or the record is not a final one. */
export function refDecrypt(body: Buffer, uaPrivate: Buffer, auth: Buffer): Buffer | undefined {
  const salt = body.subarray(0, 16);
  const idlen = body[20] as number;
  const asPublic = body.subarray(21, 21 + idlen);
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(uaPrivate);
  const { cek, nonce } = refKeys(
    ecdh.computeSecret(asPublic),
    ecdh.getPublicKey(),
    asPublic,
    auth,
    salt,
  );
  const sealed = body.subarray(21 + idlen);
  try {
    const d = createDecipheriv('aes-128-gcm', cek, nonce);
    d.setAuthTag(sealed.subarray(sealed.length - 16));
    const record = Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
    let end = record.length;
    while (end > 0 && record[end - 1] === 0) end -= 1;
    return end > 0 && record[end - 1] === 2 ? record.subarray(0, end - 1) : undefined;
  } catch {
    return undefined;
  }
}

/** ES256 check of a JWT with a raw P-256 point (r||s signature as JWT writes it). */
export function refVerifyJwt(jwt: string, point: string): boolean {
  const [h, c, s] = jwt.split('.') as [string, string, string];
  const raw = unb64(point);
  const key = createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64(raw.subarray(1, 33)), y: b64(raw.subarray(33, 65)) },
    format: 'jwk',
  });
  const v = createVerify('SHA256');
  v.update(`${h}.${c}`);
  return v.verify({ key, dsaEncoding: 'ieee-p1363' }, unb64(s));
}

/** A WebCrypto key pair from a private scalar (so the package and the reference use the same key). */
export async function pairFromScalar(d: Buffer): Promise<{ pair: CryptoKeyPair; point: string }> {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey();
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      x: b64(pub.subarray(1, 33)),
      y: b64(pub.subarray(33, 65)),
      d: b64(d),
    },
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const publicKey = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(pub),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
  return { pair: { privateKey, publicKey }, point: b64(pub) };
}

/** Tiny seeded PRNG (mulberry32), same as tests/relay/helpers.ts. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const seededBytes = (rand: () => number, n: number): Buffer =>
  Buffer.from(Array.from({ length: n }, () => Math.floor(rand() * 256)));

/** A random valid P-256 private scalar from a seeded generator. */
export function seededScalar(rand: () => number): Buffer {
  for (;;) {
    const d = seededBytes(rand, 32);
    try {
      createECDH('prime256v1').setPrivateKey(d);
      return d;
    } catch {
      /* not in range, draw again */
    }
  }
}
