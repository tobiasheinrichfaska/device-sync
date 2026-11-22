// An independent derivation of the sealed group state with node:crypto only, written from docs/group.md
// ("The state at rest"): marker, AAD, text. No import from src/.
import { createCipheriv, createDecipheriv } from 'node:crypto';

const u = (s: string): Buffer => Buffer.from(s, 'utf8');
const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const field = (s: string): string => `${u(s).length}:${s}`;

export const refRestMarker = (app: string): string => `${app}-grest:1`;
export const refRestAad = (app: string, set: string): Buffer =>
  u(`${refRestMarker(app)}|${field(set)}`);

export function refSealState(
  app: string,
  set: string,
  key: Uint8Array,
  iv: Uint8Array,
  stateText: string,
): string {
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(refRestAad(app, set));
  const ct = Buffer.concat([c.update(u(stateText)), c.final(), c.getAuthTag()]);
  return `{"m":"${refRestMarker(app)}","set":${JSON.stringify(set)},"iv":"${b64(iv)}","ct":"${b64(ct)}"}`;
}

/** Opens a text of the documented shape; throws on any failure (the caller expects success). */
export function refOpenState(app: string, key: Uint8Array, text: string): string {
  const o = JSON.parse(text) as { m: string; set: string; iv: string; ct: string };
  if (o.m !== refRestMarker(app)) throw new Error('marker');
  const iv = Buffer.from(o.iv, 'base64url');
  const all = Buffer.from(o.ct, 'base64url');
  const d = createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(refRestAad(app, o.set));
  d.setAuthTag(all.subarray(all.length - 16));
  return Buffer.concat([d.update(all.subarray(0, all.length - 16)), d.final()]).toString('utf8');
}
