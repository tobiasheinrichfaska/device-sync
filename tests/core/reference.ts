// An independent implementation of the session and file key derivation, written from
// docs/wire-format.md with node:crypto only (no code of src/). The tests use it to show that the
// documented texts and numbers are enough to reproduce the bytes, and to play an attacker.
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
} from 'node:crypto';

export type PrivateJwk = {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  d: string;
};

const b64 = (buf: Uint8Array): string => Buffer.from(buf).toString('base64url');
const field = (text: string): string => `${Buffer.byteLength(text)}:${text}`;

export const pointToJwk = (point: string) => {
  const raw = Buffer.from(point, 'base64url');
  return { kty: 'EC', crv: 'P-256', x: b64(raw.subarray(1, 33)), y: b64(raw.subarray(33, 65)) };
};

export const jwkToPoint = (jwk: { x: string; y: string }): string =>
  b64(
    Buffer.concat([
      Buffer.from([4]),
      Buffer.from(jwk.x, 'base64url'),
      Buffer.from(jwk.y, 'base64url'),
    ]),
  );

export function dh(priv: PrivateJwk, point: string): Buffer {
  return diffieHellman({
    privateKey: createPrivateKey({ key: priv, format: 'jwk' }),
    publicKey: createPublicKey({ key: pointToJwk(point), format: 'jwk' }),
  });
}

export interface RefSide {
  device: string;
  staticPriv: PrivateJwk;
  staticDh: string;
  ephPriv: PrivateJwk;
  ephPoint: string;
}

export interface RefPeer {
  device: string;
  staticDh: string;
  ephPoint: string;
}

export interface Terms {
  ee: Buffer;
  myEphPeerStatic: Buffer;
  myStaticPeerEph: Buffer;
  ss: Buffer;
}

/** The session secrets seen from `me`; `override` replaces single terms (an attacker's stand-ins). */
export function refSession(
  appId: string,
  me: RefSide,
  peer: RefPeer,
  override: { terms?: Partial<Terms> } = {},
) {
  const m = `${appId}-session:2`;
  const iAmLo = Buffer.compare(Buffer.from(me.device), Buffer.from(peer.device)) < 0;
  const t = override.terms ?? {};
  const ee = t.ee ?? dh(me.ephPriv, peer.ephPoint);
  const myEphPeerStatic = t.myEphPeerStatic ?? dh(me.ephPriv, peer.staticDh);
  const myStaticPeerEph = t.myStaticPeerEph ?? dh(me.staticPriv, peer.ephPoint);
  const ss = t.ss ?? dh(me.staticPriv, peer.staticDh);
  const ikm = Buffer.concat(
    iAmLo ? [ee, myEphPeerStatic, myStaticPeerEph, ss] : [ee, myStaticPeerEph, myEphPeerStatic, ss],
  );
  const mine = { device: me.device, dh: me.staticDh, eph: me.ephPoint };
  const theirs = { device: peer.device, dh: peer.staticDh, eph: peer.ephPoint };
  const [lo, hi] = iAmLo ? [mine, theirs] : [theirs, mine];
  const part = (p: { device: string; dh: string; eph: string }) =>
    `${field(p.device)}|${field(p.dh)}|${field(p.eph)}`;
  const transcript = `${m}|${part(lo)}|${part(hi)}`;
  const salt = createHash('sha256').update(transcript).digest();
  const keyOf = (sender: string): Buffer =>
    Buffer.from(hkdfSync('sha256', ikm, salt, `${m}|key|${field(sender)}`, 32));
  return { transcript, salt, ikm, keyOf, terms: { ee, myEphPeerStatic, myStaticPeerEph, ss } };
}

export const nonce = (n: number): Buffer => {
  const iv = Buffer.alloc(12);
  iv.writeBigUInt64BE(BigInt(n), 4);
  return iv;
};

export const messageAad = (appId: string, sender: string, receiver: string, n: number): string =>
  `${appId}-msg:2|${field(sender)}|${field(receiver)}|${n}`;

export function refSeal(
  appId: string,
  key: Buffer,
  sender: string,
  receiver: string,
  n: number,
  plaintext: Uint8Array,
): { ct: Buffer; text: string } {
  const cipher = createCipheriv('aes-256-gcm', key, nonce(n));
  cipher.setAAD(Buffer.from(messageAad(appId, sender, receiver, n)));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const ct = Buffer.concat([body, cipher.getAuthTag()]);
  return { ct, text: `{"m":"${appId}-msg:2","n":${n},"ct":"${b64(ct)}"}` };
}

/** Plaintext, or undefined when the tag does not verify. */
export function refOpen(key: Buffer, iv: Buffer, aad: string, ct: Uint8Array): Buffer | undefined {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(Buffer.from(ct.subarray(ct.length - 16)));
    return Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]);
  } catch {
    return undefined;
  }
}

/**
 * The key and the AAD of a file. The holder is the sender (its static secret and the file's
 * ephemeral secret), the recipient (its static secret), or an attacker who holds the recipient's
 * static secret AND picked the ephemeral key (a forged file).
 */
export function refFile(
  appId: string,
  o: { from: string; to: string; fromDh: string; toDh: string; eph: string },
  secret:
    | { toPriv: PrivateJwk }
    | { fromPriv: PrivateJwk; ephPriv: PrivateJwk }
    | { toPriv: PrivateJwk; ephPriv: PrivateJwk },
) {
  const m = `${appId}-file:2`;
  const header = `${m}|${field(o.from)}|${field(o.to)}|${field(o.fromDh)}|${field(o.toDh)}|${field(o.eph)}`;
  const ikm =
    'toPriv' in secret && 'ephPriv' in secret
      ? Buffer.concat([dh(secret.ephPriv, o.toDh), dh(secret.toPriv, o.fromDh)])
      : 'toPriv' in secret
        ? Buffer.concat([dh(secret.toPriv, o.eph), dh(secret.toPriv, o.fromDh)])
        : Buffer.concat([dh(secret.ephPriv, o.toDh), dh(secret.fromPriv, o.toDh)]);
  const salt = createHash('sha256').update(header).digest();
  const key = Buffer.from(hkdfSync('sha256', ikm, salt, `${m}|key`, 32));
  return { header, ikm, salt, key };
}

/** A whole file made by the reference implementation. */
export function refFileSeal(
  appId: string,
  o: { from: string; to: string; fromDh: string; toDh: string; eph: string },
  secret: Parameters<typeof refFile>[2],
  iv: Buffer,
  plaintext: Uint8Array,
): Uint8Array {
  const { header, key } = refFile(appId, o, secret);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(header));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return Buffer.from(
    `{"m":"${appId}-file:2","from":${JSON.stringify(o.from)},"to":${JSON.stringify(o.to)},"eph":"${o.eph}","iv":"${b64(iv)}","ct":"${b64(ct)}"}`,
  );
}
