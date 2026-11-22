// An independent derivation of the group layer with node:crypto only, written from docs/group.md
// (no import from src/): key id, message key, message text, state text, grant text.
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  hkdfSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';

const u = (s: string): Buffer => Buffer.from(s, 'utf8');
const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const field = (s: string): string => `${u(s).length}:${s}`;

export const refGroup = (app: string): string => `${app}-group:2`;

export function refKeyId(app: string, set: string, epoch: number, key: Uint8Array): string {
  const salt = createHash('sha256')
    .update(`${refGroup(app)}|${field(set)}`)
    .digest();
  const out = hkdfSync('sha256', key, salt, u(`${refGroup(app)}|kid|${epoch}`), 16);
  return b64(new Uint8Array(out));
}

export const refInfo = (app: string, set: string, epoch: number, kid: string): string =>
  `${app}-gdata:2|${field(set)}|${epoch}|${kid}`;

export function refEncrypt(
  app: string,
  set: string,
  epoch: number,
  key: Uint8Array,
  salt: Uint8Array,
  plaintext: Uint8Array,
  context: string,
): string {
  const kid = refKeyId(app, set, epoch, key);
  const info = refInfo(app, set, epoch, kid);
  const k = Buffer.from(hkdfSync('sha256', key, salt, u(info), 32));
  const c = createCipheriv('aes-256-gcm', k, Buffer.alloc(12));
  c.setAAD(u(`${info}|${field(context)}`));
  const ct = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return `{"m":"${app}-gdata:2","set":${JSON.stringify(set)},"epoch":${epoch},"kid":"${kid}","salt":"${b64(
    salt,
  )}","ct":"${b64(ct)}"}`;
}

export function refDecrypt(
  app: string,
  set: string,
  epoch: number,
  key: Uint8Array,
  text: string,
  context: string,
): Buffer | undefined {
  const m = JSON.parse(text) as { kid: string; salt: string; ct: string };
  const info = refInfo(app, set, epoch, refKeyId(app, set, epoch, key));
  const k = Buffer.from(hkdfSync('sha256', key, Buffer.from(m.salt, 'base64url'), u(info), 32));
  const all = Buffer.from(m.ct, 'base64url');
  const d = createDecipheriv('aes-256-gcm', k, Buffer.alloc(12));
  d.setAAD(u(`${info}|${field(context)}`));
  d.setAuthTag(all.subarray(all.length - 16));
  try {
    return Buffer.concat([d.update(all.subarray(0, all.length - 16)), d.final()]);
  } catch {
    return undefined;
  }
}

export interface RefKey {
  epoch: number;
  author: string;
  key: Uint8Array;
  audience: string[];
}

const ids = (l: string[]): string => `[${l.map((x) => JSON.stringify(x)).join(',')}]`;

export interface RefGrant extends RefKey {
  from: string;
  to: string;
}

/** Texts of version 3 as docs/group.md writes them: the signed text carries the key id, not the key. */
export const refGrantSigText = (app: string, set: string, g: RefGrant): string =>
  `{"m":"${app}-gkeysig:3","set":${JSON.stringify(set)},"epoch":${g.epoch},"author":${JSON.stringify(
    g.author,
  )},"from":${JSON.stringify(g.from)},"to":${JSON.stringify(g.to)},"kid":"${refKeyId(
    app,
    set,
    g.epoch,
    g.key,
  )}","audience":${ids(g.audience)}}`;

export const refGrant = (app: string, set: string, g: RefGrant, sig: string): string =>
  `{"m":"${app}-gkey:3","set":${JSON.stringify(set)},"epoch":${g.epoch},"author":${JSON.stringify(
    g.author,
  )},"from":${JSON.stringify(g.from)},"to":${JSON.stringify(g.to)},"kid":"${refKeyId(
    app,
    set,
    g.epoch,
    g.key,
  )}","key":"${b64(g.key)}","audience":${ids(g.audience)},"sig":"${sig}"}`;

export interface RefRequest {
  epoch: number;
  from: string;
  to: string;
}

export const refRequestSigText = (app: string, set: string, r: RefRequest): string =>
  `{"m":"${app}-greqsig:3","set":${JSON.stringify(set)},"epoch":${r.epoch},"from":${JSON.stringify(
    r.from,
  )},"to":${JSON.stringify(r.to)}}`;

export const refRequest = (app: string, set: string, r: RefRequest, sig: string): string =>
  `{"m":"${app}-greq:3","set":${JSON.stringify(set)},"epoch":${r.epoch},"from":${JSON.stringify(
    r.from,
  )},"to":${JSON.stringify(r.to)},"sig":"${sig}"}`;

const ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** ECDSA P-256 / SHA-256, P1363, low-s: the signature as the package spells it. */
export function refSign(privateKey: KeyObject, text: string): string {
  const sig = Buffer.from(sign('sha256', u(text), { key: privateKey, dsaEncoding: 'ieee-p1363' }));
  const s = BigInt(`0x${sig.subarray(32).toString('hex')}`);
  if (s > ORDER / 2n) {
    sig.set(Buffer.from((ORDER - s).toString(16).padStart(64, '0'), 'hex'), 32);
  }
  return b64(sig);
}

/** The public point (65 bytes, 87 characters) as a node key. */
export function refPublicKey(point: string): KeyObject {
  const raw = Buffer.from(point, 'base64url');
  return createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: raw.subarray(1, 33).toString('base64url'),
      y: raw.subarray(33, 65).toString('base64url'),
    },
    format: 'jwk',
  });
}

/** Verifies as the document says: 64 bytes, canonical spelling, low-s, valid. */
export function refVerify(point: string, text: string, sig: string): boolean {
  const raw = Buffer.from(sig, 'base64url');
  if (raw.length !== 64 || raw.toString('base64url') !== sig) return false;
  if (BigInt(`0x${raw.subarray(32).toString('hex')}`) > ORDER / 2n) return false;
  return verify('sha256', u(text), { key: refPublicKey(point), dsaEncoding: 'ieee-p1363' }, raw);
}

export const refState = (app: string, set: string, floor: number, keys: RefKey[]): string =>
  `{"m":"${app}-gstate:2","set":${JSON.stringify(set)},"floor":${floor},"keys":[${keys
    .map(
      (k) =>
        `{"epoch":${k.epoch},"author":${JSON.stringify(k.author)},"key":"${b64(k.key)}","audience":${ids(k.audience)}}`,
    )
    .join(',')}]}`;
