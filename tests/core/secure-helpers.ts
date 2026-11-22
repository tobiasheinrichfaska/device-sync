import {
  createHello,
  generateDeviceKeys,
  openSession,
  publicKeys,
  type DeviceKeys,
  type EncryptedSession,
  type Hello,
  type SessionLimits,
} from '../../src/core/index.ts';
import type { PrivateJwk } from './reference.ts';

export const APP = 'demo';
export const A = `device-${'a'.repeat(32)}`;
export const B = `device-${'b'.repeat(32)}`;
export const C = `device-${'c'.repeat(32)}`;

export const text = (s: string): Uint8Array => new TextEncoder().encode(s);
export const show = (b: Uint8Array): string => new TextDecoder().decode(b);

export interface Party {
  readonly device: string;
  readonly keys: DeviceKeys;
  readonly agreement: CryptoKeyPair;
  /** The agreement public key as it travels (a point). */
  readonly dh: string;
}

export async function party(device: string): Promise<Party> {
  const keys = await generateDeviceKeys();
  return { device, keys, agreement: keys.agreement, dh: (await publicKeys(keys)).dh };
}

/** Throw-away keys with a private half that can be exported (for the vectors and the attacker tests). */
export async function extractablePair(): Promise<{ pair: CryptoKeyPair; jwk: PrivateJwk }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const jwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as unknown as PrivateJwk;
  return { pair, jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d } };
}

/** A key pair from a private JWK (the private half is not extractable again). */
export async function pairFromJwk(jwk: PrivateJwk): Promise<CryptoKeyPair> {
  const algorithm = { name: 'ECDH', namedCurve: 'P-256' } as const;
  const privateKey = await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['deriveBits']);
  const raw = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
  const publicKey = await crypto.subtle.importKey('raw', raw, algorithm, true, []);
  return { privateKey, publicKey };
}

export interface Connection {
  readonly a: EncryptedSession;
  readonly b: EncryptedSession;
  readonly helloA: Hello;
  readonly helloB: Hello;
  readonly ephemeralA: CryptoKeyPair;
  readonly ephemeralB: CryptoKeyPair;
}

/** Both sides open a session with each other (both hellos fresh). */
export async function connect(
  a: Party,
  b: Party,
  appId = APP,
  limits?: Partial<SessionLimits>,
  limitsB: Partial<SessionLimits> | undefined = limits,
): Promise<Connection> {
  const ea = await createHello(a.device);
  const eb = await createHello(b.device);
  const open = async (
    me: Party,
    you: Party,
    mine: typeof ea,
    theirs: typeof eb,
    lim: Partial<SessionLimits> | undefined,
  ) => {
    const result = await openSession({
      appId,
      own: { device: me.device, agreement: me.agreement },
      peer: { device: you.device, dh: you.dh },
      ephemeral: mine.ephemeral,
      ownHello: mine.hello,
      peerHello: theirs.hello,
      ...(lim ? { limits: lim } : {}),
    });
    if (!result.ok) throw new Error(`openSession: ${result.reason}`);
    return result.session;
  };
  return {
    a: await open(a, b, ea, eb, limits),
    b: await open(b, a, eb, ea, limitsB),
    helloA: ea.hello,
    helloB: eb.hello,
    ephemeralA: ea.ephemeral,
    ephemeralB: eb.ephemeral,
  };
}

/** Seeded generator (mulberry32): the same seed always gives the same numbers. */
export function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALPHABET = 'ABCxyz019-_{}[]",:|# ä\u0007\\/.';

/** One to three random edits (replace, insert, delete, cut) of a text. */
export function mutate(rnd: () => number, source: string): string {
  let s = source;
  for (let k = 0, n = 1 + Math.floor(rnd() * 3); k < n; k += 1) {
    const i = Math.floor(rnd() * (s.length + 1));
    const op = rnd();
    const ch = ALPHABET[Math.floor(rnd() * ALPHABET.length)] as string;
    if (op < 0.4) s = s.slice(0, i) + ch + s.slice(i + 1);
    else if (op < 0.6) s = s.slice(0, i) + ch + s.slice(i);
    else if (op < 0.8) s = s.slice(0, i) + s.slice(i + 1);
    else s = s.slice(0, i);
  }
  return s;
}

/** A random JSON-like value, including hostile member names. */
export function randomJson(rnd: () => number, depth = 0): unknown {
  const r = rnd();
  const leaves: unknown[] = [
    null,
    true,
    false,
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
    'constructor',
    [],
    {},
  ];
  if (depth > 2 || r < 0.5) return leaves[Math.floor(rnd() * leaves.length)];
  if (r < 0.7)
    return Array.from({ length: Math.floor(rnd() * 3) }, () => randomJson(rnd, depth + 1));
  const names = [
    'm',
    'device',
    'eph',
    'n',
    'ct',
    'from',
    'to',
    'iv',
    '__proto__',
    'constructor',
    'x',
  ];
  return Object.fromEntries(
    Array.from({ length: Math.floor(rnd() * 5) }, () => [
      names[Math.floor(rnd() * names.length)],
      randomJson(rnd, depth + 1),
    ]),
  );
}
