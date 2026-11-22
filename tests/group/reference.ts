// An independent derivation of the group layer with node:crypto only, written from docs/group.md
// (no import from src/): key id, message key, message text, state text, grant text.
import { createCipheriv, createDecipheriv, createHash, hkdfSync } from 'node:crypto';

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

export const refGrant = (app: string, set: string, k: RefKey): string =>
  `{"m":"${app}-gkey:2","set":${JSON.stringify(set)},"epoch":${k.epoch},"author":${JSON.stringify(
    k.author,
  )},"key":"${b64(k.key)}","audience":${ids(k.audience)}}`;

export const refState = (app: string, set: string, floor: number, keys: RefKey[]): string =>
  `{"m":"${app}-gstate:2","set":${JSON.stringify(set)},"floor":${floor},"keys":[${keys
    .map(
      (k) =>
        `{"epoch":${k.epoch},"author":${JSON.stringify(k.author)},"key":"${b64(k.key)}","audience":${ids(k.audience)}}`,
    )
    .join(',')}]}`;
