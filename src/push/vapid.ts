// VAPID (RFC 8292): an ES256 JWT over {aud, exp, sub?} and the header `vapid t=<jwt>, k=<key>`.
// Time is a parameter (whole seconds); the signature is WebCrypto's. Never throws on bad input.
import { base64url } from '../core/encoding.ts';
import { importPublicKey, isPoint } from '../core/keys.ts';
import { isPlain, ownPoint, readBytes, decodeUtf8, parseJson } from '../core/secure.ts';
import { splitVapidHeader, vapidAudience } from './endpoint.ts';
import { fail, pass, PUSH_LIMITS, type PushResult } from './limits.ts';

const utf8 = new TextEncoder();
const JWT_HEADER = '{"typ":"JWT","alg":"ES256"}';
const SIGNING = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ES256 = { name: 'ECDSA', hash: 'SHA-256' } as const;
const SUBJECT =
  /^(?:mailto:[\x21-\x3b\x3d\x3f-\x7e]+@[\x21-\x3b\x3d\x3f-\x7e]+|https:\/\/[\x21-\x7e]+)$/;

export interface VapidKeys {
  /** The signing key (ECDSA P-256), not extractable. */
  readonly privateKey: CryptoKey;
  /** The public point (87 base64url characters): the `applicationServerKey` a receiver subscribes with. */
  readonly publicKey: string;
}

/** A new VAPID key pair. */
export async function generateVapidKeys(): Promise<VapidKeys> {
  const pair = await crypto.subtle.generateKey(SIGNING, false, ['sign', 'verify']);
  const point = (await ownPoint(pair)) as string;
  return { privateKey: pair.privateKey, publicKey: point };
}

export interface VapidParams {
  /** The push endpoint the request goes to (only its origin is signed). */
  readonly endpoint: string;
  readonly privateKey: CryptoKey;
  readonly publicKey: string;
  /** Now, whole seconds since 1970. */
  readonly nowS: number;
  /** Seconds until `exp`, 1 to 86 400 (default 43 200). */
  readonly lifetimeS?: number;
  /** Optional contact: `mailto:` or `https:` URI. */
  readonly subject?: string;
}

export type VapidRefusal =
  'audience' | 'time' | 'lifetime' | 'subject' | 'vapid-key' | 'key-mismatch' | 'crypto';

export interface Vapid {
  /** `vapid t=<jwt>, k=<key>`: the value the relay's `vapid` member takes. */
  readonly header: string;
  readonly audience: string;
  readonly expiresS: number;
}

const isSeconds = (v: unknown): v is number =>
  typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

/** The `sub` claim must be a mailto: or https: URI of printable ASCII, at most 200 characters. */
export const isSubject = (v: unknown): v is string =>
  typeof v === 'string' && v.length <= PUSH_LIMITS.subjectMax && SUBJECT.test(v);

/** The text a JWT carries for these claims (the one spelling: key order aud, exp, sub; no spaces). */
const claimsText = (aud: string, exp: number, sub: string | undefined): string =>
  JSON.stringify(sub === undefined ? { aud, exp } : { aud, exp, sub });

/** Builds and signs the authorisation of one push request. */
export async function buildVapid(p: VapidParams): Promise<PushResult<Vapid, VapidRefusal>> {
  try {
    const audience = vapidAudience(p.endpoint);
    if (audience === undefined) return fail('audience');
    if (!isSeconds(p.nowS)) return fail('time');
    const lifetime = p.lifetimeS ?? PUSH_LIMITS.vapidLifetimeDefaultS;
    if (
      typeof lifetime !== 'number' ||
      !Number.isSafeInteger(lifetime) ||
      lifetime < 1 ||
      lifetime > PUSH_LIMITS.vapidLifetimeMaxS
    )
      return fail('lifetime');
    if (p.subject !== undefined && !isSubject(p.subject)) return fail('subject');
    if (!isPoint(p.publicKey) || !(p.privateKey instanceof CryptoKey)) return fail('vapid-key');
    const publicKey = await importPublicKey(p.publicKey, 'sig');
    if (!publicKey) return fail('vapid-key');
    const expiresS = p.nowS + lifetime;
    const input = `${base64url(utf8.encode(JWT_HEADER))}.${base64url(
      utf8.encode(claimsText(audience, expiresS, p.subject)),
    )}`;
    const signature = new Uint8Array(
      await crypto.subtle.sign(ES256, p.privateKey, utf8.encode(input)),
    );
    if (signature.length !== 64) return fail('crypto');
    // A private key that does not belong to the public one would give a token the push service refuses.
    if (!(await crypto.subtle.verify(ES256, publicKey, signature, utf8.encode(input))))
      return fail('key-mismatch');
    return pass({
      header: `vapid t=${input}.${base64url(signature)}, k=${p.publicKey}`,
      audience,
      expiresS,
    });
  } catch {
    return fail('crypto');
  }
}

export interface VapidCheckParams {
  readonly header: string;
  readonly endpoint: string;
  readonly nowS: number;
}

export type VapidCheckRefusal =
  | 'header'
  | 'token'
  | 'claims'
  | 'audience'
  | 'expired'
  | 'lifetime'
  | 'key'
  | 'signature'
  | 'crypto';

export interface VapidChecked {
  readonly publicKey: string;
  readonly expiresS: number;
  readonly subject?: string;
}

/**
 * What a push service (or a test server) does with the header: reads the one spelling this package writes
 * (stricter than RFC 8292: fixed order of `t` and `k`, claims `aud`, `exp` and optionally `sub` only, the
 * JWT header exactly `{"typ":"JWT","alg":"ES256"}`), checks audience, expiry (not later than `exp`, not more
 * than 24 h ahead) and the signature.
 */
export async function checkVapid(
  p: VapidCheckParams,
): Promise<PushResult<VapidChecked, VapidCheckRefusal>> {
  try {
    const parts = splitVapidHeader(p.header);
    if (!parts) return fail('header');
    const headerBytes = readBytes(parts.header, 1, 100);
    const claimBytes = readBytes(parts.claims, 1, 1024);
    const signature = readBytes(parts.signature, 64, 64);
    if (!headerBytes || !claimBytes || !signature || !isPoint(parts.key)) return fail('token');
    if (decodeUtf8(headerBytes) !== JWT_HEADER) return fail('token');
    const text = decodeUtf8(claimBytes);
    const claims = text === undefined ? undefined : parseJson(text);
    if (!isPlain(claims)) return fail('claims');
    const { aud, exp, sub } = claims as { aud?: unknown; exp?: unknown; sub?: unknown };
    if (typeof aud !== 'string' || !isSeconds(exp)) return fail('claims');
    if (sub !== undefined && !isSubject(sub)) return fail('claims');
    if (text !== claimsText(aud, exp, sub)) return fail('claims');
    if (!isSeconds(p.nowS)) return fail('expired');
    if (aud !== vapidAudience(p.endpoint)) return fail('audience');
    if (p.nowS > exp) return fail('expired');
    if (exp - p.nowS > PUSH_LIMITS.vapidLifetimeMaxS) return fail('lifetime');
    const key = await importPublicKey(parts.key, 'sig');
    if (!key) return fail('key');
    const input = utf8.encode(`${parts.header}.${parts.claims}`);
    if (!(await crypto.subtle.verify(ES256, key, new Uint8Array(signature), input)))
      return fail('signature');
    return pass(
      sub === undefined
        ? { publicKey: parts.key, expiresS: exp }
        : { publicKey: parts.key, expiresS: exp, subject: sub },
    );
  } catch {
    return fail('crypto');
  }
}
