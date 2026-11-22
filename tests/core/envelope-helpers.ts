import {
  generateDeviceKeys,
  openEnvelope,
  publicKeys,
  sealEnvelope,
  type DeviceKeys,
  type Envelope,
  type EnvelopeLimits,
} from '../../src/core/index.ts';
import { jwkToPoint, type PrivateJwk } from './reference.ts';
import { extractablePair, rng } from './secure-helpers.ts';

export const APP = 'demo';
export const DAY = '2026-11-10';

/** A device with all four halves of its keys; the agreement private half can be exported. */
export interface Member {
  readonly device: string;
  readonly keys: DeviceKeys;
  readonly sig: string;
  readonly dh: string;
}

export async function member(device: string): Promise<Member> {
  const keys = await generateDeviceKeys();
  const pub = await publicKeys(keys);
  return { device, keys, sig: pub.sig, dh: pub.dh };
}

/** A reader with an extractable agreement key (for the independent reference). */
export interface Reader {
  readonly pair: CryptoKeyPair;
  readonly jwk: PrivateJwk;
  readonly dh: string;
}

export async function reader(): Promise<Reader> {
  const { pair, jwk } = await extractablePair();
  return { pair, jwk, dh: jwkToPoint(jwk) };
}

/** Random bytes from a seeded generator: the same seed always gives the same bytes. */
export function seededRandom(seed: number): (length: number) => Uint8Array {
  const next = rng(seed);
  return (length) => Uint8Array.from({ length }, () => Math.floor(next() * 256));
}

export const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);
export const show = (b: Uint8Array): string => new TextDecoder().decode(b);

export interface SealOptions {
  appId?: string;
  channel?: string;
  day?: string;
  body?: Uint8Array | string;
  random?: (length: number) => Uint8Array;
  limits?: Partial<EnvelopeLimits>;
}

let seed = 1;
/** Seals as `author` for the readers' agreement points; throws when it is refused. */
export async function seal(
  author: Member,
  recipients: readonly string[],
  options: SealOptions = {},
): Promise<Envelope> {
  seed += 1;
  const body = options.body ?? 'hello';
  const result = await sealEnvelope({
    appId: options.appId ?? APP,
    author: { device: author.device, signing: author.keys.signing.privateKey },
    recipients,
    channel: options.channel ?? 'chan-1',
    day: options.day ?? DAY,
    body: typeof body === 'string' ? bytes(body) : body,
    random: options.random ?? seededRandom(seed),
    ...(options.limits ? { limits: options.limits } : {}),
  });
  if (!result.ok) throw new Error(`sealEnvelope: ${result.reason}`);
  return result.envelope;
}

/** Opens with a pair and a table of author signing keys (by device id). */
export function open(
  me: { pair: CryptoKeyPair } | { keys: DeviceKeys },
  envelope: string | Envelope,
  authors: Readonly<Record<string, string>>,
  options: { appId?: string; limits?: Partial<EnvelopeLimits> } = {},
) {
  const agreement = 'pair' in me ? me.pair : me.keys.agreement;
  return openEnvelope({
    appId: options.appId ?? APP,
    own: { agreement },
    envelope,
    authorKey: (from) => (Object.hasOwn(authors, from) ? authors[from] : undefined),
    ...(options.limits ? { limits: options.limits } : {}),
  });
}
