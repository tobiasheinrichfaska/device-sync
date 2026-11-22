// Web Push message encryption against the RFC 8291 appendix A vector (every intermediate value), against an
// independent derivation with node:crypto, with refusals, boundaries, tamper sweeps and seeded fuzzing.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  PUSH_LIMITS,
  decryptPushMessage,
  encryptPushMessage,
  type PushEncryptParams,
} from '../../src/push/index.ts';
import {
  b64,
  mulberry32,
  pairFromScalar,
  refDecrypt,
  refEncrypt,
  refKeys,
  seededBytes,
  seededScalar,
  unb64,
} from './reference.ts';
import { createECDH } from 'node:crypto';

const V = (
  JSON.parse(readFileSync(new URL('../vectors/push.json', import.meta.url), 'utf8')) as {
    rfc8291: Record<string, string>;
  }
).rfc8291 as Record<string, string>;

const field = (name: string): string => V[name] as string;
const bytes = (name: string): Uint8Array => new Uint8Array(unb64(field(name)));

async function fixed() {
  const sender = await pairFromScalar(unb64(field('senderPrivate')));
  const receiver = await pairFromScalar(unb64(field('receiverPrivate')));
  return { sender, receiver };
}

const base = async (over: Partial<PushEncryptParams> = {}): Promise<PushEncryptParams> => ({
  plaintext: bytes('plaintext'),
  receiverPublic: field('receiverPublic'),
  authSecret: field('authSecret'),
  salt: bytes('salt'),
  ephemeral: (await fixed()).sender.pair,
  ...over,
});

describe('RFC 8291 appendix A', () => {
  it('the vector is internally consistent: its keys give its points and the body is header + ciphertext', async () => {
    const { sender, receiver } = await fixed();
    expect(sender.point).toBe(field('senderPublic'));
    expect(receiver.point).toBe(field('receiverPublic'));
    expect(field('header') + '').toHaveLength(115);
    const joined = Buffer.concat([unb64(field('header')), unb64(field('ciphertext'))]);
    expect(b64(joined)).toBe(field('body'));
  });

  it('the independent derivation reproduces every intermediate value', () => {
    const ecdh = createECDH('prime256v1');
    ecdh.setPrivateKey(unb64(field('senderPrivate')));
    const secret = ecdh.computeSecret(unb64(field('receiverPublic')));
    expect(b64(secret)).toBe(field('ecdhSecret'));
    const k = refKeys(
      secret,
      unb64(field('receiverPublic')),
      unb64(field('senderPublic')),
      unb64(field('authSecret')),
      unb64(field('salt')),
    );
    expect(b64(k.ikm)).toBe(field('ikm'));
    expect(b64(k.cek)).toBe(field('cek'));
    expect(b64(k.nonce)).toBe(field('nonce'));
    const keyInfo = Buffer.concat([
      Buffer.from('WebPush: info\0'),
      unb64(field('receiverPublic')),
      unb64(field('senderPublic')),
    ]);
    expect(b64(keyInfo)).toBe(field('keyInfo'));
  });

  it('encryptPushMessage produces the RFC body byte for byte', async () => {
    const r = await encryptPushMessage(await base());
    expect(r.ok && b64(r.value)).toBe(field('body'));
    expect(r.ok && r.value.length).toBe(144); // RFC text says 145; its own base64 is 144 octets
  });

  it('decryptPushMessage opens the RFC body (the receiver side)', async () => {
    const { receiver } = await fixed();
    const r = await decryptPushMessage({
      body: bytes('body'),
      receiverPrivate: receiver.pair.privateKey,
      receiverPublic: field('receiverPublic'),
      authSecret: field('authSecret'),
    });
    expect(r.ok && new TextDecoder().decode(r.value.plaintext)).toBe(
      'When I grow up, I want to be a watermelon',
    );
    expect(r.ok && r.value.padding).toBe(0);
  });

  it('the independent reference opens what the package wrote and vice versa', async () => {
    const mine = await encryptPushMessage(await base());
    expect(
      mine.ok &&
        refDecrypt(
          Buffer.from(mine.value),
          unb64(field('receiverPrivate')),
          unb64(field('authSecret')),
        )?.toString(),
    ).toBe('When I grow up, I want to be a watermelon');
    expect(
      refEncrypt({
        plaintext: Buffer.from(bytes('plaintext')),
        uaPublic: unb64(field('receiverPublic')),
        auth: unb64(field('authSecret')),
        salt: unb64(field('salt')),
        asPrivate: unb64(field('senderPrivate')),
      }).toString('base64url'),
    ).toBe(field('body'));
  });
});

describe('agreement with the independent derivation (seeded)', () => {
  it('300 random messages: same bytes, same plaintext, both directions', async () => {
    const rand = mulberry32(8291);
    for (let i = 0; i < 300; i += 1) {
      const receiverD = seededScalar(rand);
      const senderD = seededScalar(rand);
      const receiver = await pairFromScalar(receiverD);
      const sender = await pairFromScalar(senderD);
      const auth = seededBytes(rand, 16);
      const salt = seededBytes(rand, 16);
      const plaintext = seededBytes(rand, Math.floor(rand() * 200));
      const padding = Math.floor(rand() * 40);
      const mine = await encryptPushMessage({
        plaintext: new Uint8Array(plaintext),
        receiverPublic: receiver.point,
        authSecret: b64(auth),
        salt: new Uint8Array(salt),
        padding,
        ephemeral: sender.pair,
      });
      const theirs = refEncrypt({
        plaintext,
        uaPublic: unb64(receiver.point),
        auth,
        salt,
        asPrivate: senderD,
        padding,
      });
      expect(mine.ok && Buffer.compare(Buffer.from(mine.value), theirs)).toBe(0);
      expect(refDecrypt(theirs, receiverD, auth)?.equals(plaintext)).toBe(true);
      const opened = await decryptPushMessage({
        body: new Uint8Array(theirs),
        receiverPrivate: receiver.pair.privateKey,
        receiverPublic: receiver.point,
        authSecret: b64(auth),
      });
      expect(opened.ok && Buffer.from(opened.value.plaintext).equals(plaintext)).toBe(true);
      expect(opened.ok && opened.value.padding).toBe(padding);
    }
  });

  it('a message with a generated ephemeral key (no fixed pair) opens at the receiver', async () => {
    const { receiver } = await fixed();
    const sent = await encryptPushMessage(await base({ ephemeral: undefined as never }));
    // `ephemeral: undefined` must behave like absent
    const p = await base();
    const { ephemeral: _drop, ...rest } = p;
    void _drop;
    const r = await encryptPushMessage(rest);
    for (const m of [sent, r]) {
      expect(m.ok).toBe(true);
      if (!m.ok) continue;
      const o = await decryptPushMessage({
        body: m.value,
        receiverPrivate: receiver.pair.privateKey,
        receiverPublic: field('receiverPublic'),
        authSecret: field('authSecret'),
      });
      expect(o.ok).toBe(true);
    }
    const a = r.ok && r.value.subarray(21, 86);
    const b = sent.ok && sent.value.subarray(21, 86);
    expect(a).not.toEqual(b); // two draws, two ephemeral keys
  });
});

describe('encrypt: refusals and boundaries', () => {
  const refuses = async (over: Partial<PushEncryptParams>, reason: string) => {
    const r = await encryptPushMessage(await base(over));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toBe(reason);
  };

  it('bad inputs are codes, never exceptions', async () => {
    await refuses({ plaintext: 'x' as never }, 'plaintext');
    await refuses({ salt: new Uint8Array(15) }, 'salt');
    await refuses({ salt: new Uint8Array(17) }, 'salt');
    await refuses({ salt: 'x' as never }, 'salt');
    await refuses({ authSecret: b64(new Uint8Array(15)) }, 'auth-secret');
    await refuses({ authSecret: b64(new Uint8Array(17)) }, 'auth-secret');
    await refuses({ authSecret: field('authSecret') + '=' }, 'auth-secret');
    await refuses({ authSecret: 5 as never }, 'auth-secret');
    await refuses({ receiverPublic: 'AAAA' }, 'receiver-key');
    await refuses({ receiverPublic: field('receiverPublic').slice(0, 86) }, 'receiver-key');
    await refuses({ padding: -1 }, 'padding');
    await refuses({ padding: 1.5 }, 'padding');
    await refuses({ padding: NaN }, 'padding');
    await refuses({ padding: 5000 }, 'padding');
    await refuses({ recordSize: 17 }, 'record-size');
    await refuses({ recordSize: 4097 }, 'record-size');
    await refuses({ recordSize: 100.5 }, 'record-size');
  });

  it('a point that is not on the curve is refused', async () => {
    const raw = unb64(field('receiverPublic'));
    raw[64] = (raw[64] as number) ^ 1;
    await refuses({ receiverPublic: b64(raw) }, 'receiver-key');
  });

  it('a non-canonical spelling of the receiver key is refused', async () => {
    const last = field('receiverPublic').slice(-1);
    // the last character carries two spare bits; flip one without changing the bytes' meaning
    const alt = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
      .split('')
      .filter(
        (c) =>
          c !== last &&
          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(c) >> 2 ===
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(last) >> 2,
      )[0] as string;
    await refuses({ receiverPublic: field('receiverPublic').slice(0, -1) + alt }, 'receiver-key');
  });

  it('the record boundary: plaintext + padding + 17 must fit the record size, to the octet', async () => {
    const rs = 64;
    const ok = await encryptPushMessage(
      await base({ plaintext: new Uint8Array(40), padding: 7, recordSize: rs }),
    );
    expect(ok.ok && ok.value.length).toBe(PUSH_LIMITS.headerBytes + rs);
    await refuses({ plaintext: new Uint8Array(40), padding: 8, recordSize: rs }, 'too-long');
    await refuses({ plaintext: new Uint8Array(48), padding: 0, recordSize: rs }, 'too-long');
  });

  it('the largest message: 4096 record + 86 header, and an empty one is 103 octets', async () => {
    const big = await encryptPushMessage(await base({ plaintext: new Uint8Array(4079) }));
    expect(big.ok && big.value.length).toBe(4182);
    await refuses({ plaintext: new Uint8Array(4080) }, 'too-long');
    const empty = await encryptPushMessage(await base({ plaintext: new Uint8Array(0) }));
    expect(empty.ok && empty.value.length).toBe(PUSH_LIMITS.headerBytes + 17);
  });

  it('padding hides the length: equal sizes for different plaintexts', async () => {
    const a = await encryptPushMessage(await base({ plaintext: new Uint8Array(3), padding: 20 }));
    const b = await encryptPushMessage(await base({ plaintext: new Uint8Array(20), padding: 3 }));
    expect(a.ok && b.ok && a.value.length === b.value.length).toBe(true);
  });

  it('a foreign ephemeral object does not throw', async () => {
    const r = await encryptPushMessage(await base({ ephemeral: {} as never }));
    expect(r).toEqual({ ok: false, reason: 'crypto' });
  });
});

describe('decrypt: strict, tamper-evident, never throws', () => {
  const open = async (body: Uint8Array, over: Record<string, unknown> = {}) => {
    const { receiver } = await fixed();
    return decryptPushMessage({
      body,
      receiverPrivate: receiver.pair.privateKey,
      receiverPublic: field('receiverPublic'),
      authSecret: field('authSecret'),
      ...over,
    });
  };

  it('every single flipped bit of the RFC body is refused (full sweep)', async () => {
    const body = bytes('body');
    for (let bit = 0; bit < body.length * 8; bit += 1) {
      const copy = body.slice();
      copy[bit >> 3] = (copy[bit >> 3] as number) ^ (1 << (bit & 7));
      const r = await open(copy);
      // Bits of the salt, the key id and the ciphertext change a key or the tag; the record size bits
      // are read; the idlen bits change the key id. None may open.
      expect(r.ok, `bit ${bit}`).toBe(false);
    }
  }, 60_000);

  it('truncation at every length and extension by one octet are refused', async () => {
    const body = bytes('body');
    for (let n = 0; n < body.length; n += 1) expect((await open(body.slice(0, n))).ok).toBe(false);
    expect((await open(Uint8Array.from([...body, 0]))).ok).toBe(false);
  });

  it('wrong receiver key, wrong auth secret, other app key: refused as decrypt', async () => {
    const other = await pairFromScalar(Buffer.alloc(32, 7));
    const r1 = await open(bytes('body'), { receiverPrivate: other.pair.privateKey });
    expect(r1).toEqual({ ok: false, reason: 'decrypt' });
    const r2 = await open(bytes('body'), { authSecret: b64(new Uint8Array(16)) });
    expect(r2).toEqual({ ok: false, reason: 'decrypt' });
  });

  it('a second record (body longer than rs) is refused, not read in part', async () => {
    const body = bytes('body').slice();
    new DataView(body.buffer).setUint32(16, 40); // rs smaller than the record that follows
    expect(await open(body)).toEqual({ ok: false, reason: 'multiple-records' });
  });

  it('record sizes outside 18 to 4096 and a key id length other than 65 are refused', async () => {
    for (const rs of [0, 17, 4097, 0xffffffff]) {
      const body = bytes('body').slice();
      new DataView(body.buffer).setUint32(16, rs);
      expect(await open(body)).toEqual({ ok: false, reason: 'record-size' });
    }
    for (const idlen of [0, 64, 66, 255]) {
      const body = bytes('body').slice();
      body[20] = idlen;
      expect(await open(body)).toEqual({ ok: false, reason: 'key-id' });
    }
  });

  it('a key id that is not a curve point is refused', async () => {
    const body = bytes('body').slice();
    body[21 + 64] = (body[21 + 64] as number) ^ 1;
    expect(await open(body)).toEqual({ ok: false, reason: 'key-id' });
  });

  it('a record without the delimiter 2 (1 for "more", or nothing) is refused after authentication', async () => {
    // The reference signs a valid record whose delimiter is wrong: only a delimiter check can refuse it.
    const rand = mulberry32(5);
    const receiverD = seededScalar(rand);
    const senderD = seededScalar(rand);
    const receiver = await pairFromScalar(receiverD);
    const auth = seededBytes(rand, 16);
    const salt = seededBytes(rand, 16);
    const mk = (delimiter: number | undefined, tail: number[]): Buffer => {
      const ecdh = createECDH('prime256v1');
      ecdh.setPrivateKey(senderD);
      const asPublic = ecdh.getPublicKey();
      const { cek, nonce } = refKeys(
        ecdh.computeSecret(unb64(receiver.point)),
        unb64(receiver.point),
        asPublic,
        auth,
        salt,
      );
      return Buffer.from([
        ...salt,
        0,
        0,
        16,
        0,
        65,
        ...asPublic,
        ...sealRaw(cek, nonce, [5, ...(delimiter === undefined ? [] : [delimiter]), ...tail]),
      ]);
    };
    for (const body of [mk(1, []), mk(undefined, [0, 0]), mk(3, []), mk(2, [9])]) {
      const r = await decryptPushMessage({
        body: new Uint8Array(body),
        receiverPrivate: receiver.pair.privateKey,
        receiverPublic: receiver.point,
        authSecret: b64(auth),
      });
      expect(r).toEqual({ ok: false, reason: 'delimiter' });
    }
    // and the same construction with delimiter 2 and zero padding opens (the test builder is sound)
    const good = mk(2, [0, 0]);
    const r = await decryptPushMessage({
      body: new Uint8Array(good),
      receiverPrivate: receiver.pair.privateKey,
      receiverPublic: receiver.point,
      authSecret: b64(auth),
    });
    expect(r.ok && [...r.value.plaintext]).toEqual([5]);
    expect(r.ok && r.value.padding).toBe(2);
  });

  it('bad parameters are codes', async () => {
    expect(await open('x' as never)).toEqual({ ok: false, reason: 'body' });
    expect(await open(bytes('body'), { authSecret: 'short' })).toEqual({
      ok: false,
      reason: 'auth-secret',
    });
    expect(await open(bytes('body'), { receiverPublic: 'short' })).toEqual({
      ok: false,
      reason: 'receiver-key',
    });
    expect(await open(bytes('body'), { receiverPrivate: {} })).toEqual({
      ok: false,
      reason: 'crypto',
    });
  });

  it('300 seeded random bodies (some almost valid) never throw and never open', async () => {
    const rand = mulberry32(42);
    const good = bytes('body');
    for (let i = 0; i < 300; i += 1) {
      const body =
        i % 3 === 0
          ? seededBytes(rand, Math.floor(rand() * 300))
          : Buffer.from(good.map((b) => (rand() < 0.02 ? Math.floor(rand() * 256) : b)));
      const r = await open(new Uint8Array(body));
      if (Buffer.compare(body, Buffer.from(good)) !== 0) expect(r.ok).toBe(false);
    }
  });
});

import { createCipheriv } from 'node:crypto';
function sealRaw(cek: Buffer, nonce: Buffer, record: number[]): Buffer {
  const c = createCipheriv('aes-128-gcm', cek, nonce);
  return Buffer.concat([c.update(Buffer.from(record)), c.final(), c.getAuthTag()]);
}
