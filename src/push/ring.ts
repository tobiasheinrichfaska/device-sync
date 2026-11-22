// The ring request: exactly what `RelayClient.ring` takes (docs/relay-protocol.md, `klingeln`). Built from a
// browser push subscription; the push is content-free (an encrypted empty message, optionally padded).
import { isPoint } from '../core/keys.ts';
import { isPlain, readBytes } from '../core/secure.ts';
import type { RingRequest } from '../relay/client.ts';
import { isRingEndpoint, isRingVapid } from './endpoint.ts';
import { fail, pass, PUSH_LIMITS, type PushResult } from './limits.ts';
import { encryptPushMessage } from './message.ts';
import { buildVapid, isSubject } from './vapid.ts';

export type Urgency = RingRequest['urgency'];
export const URGENCIES: readonly Urgency[] = ['very-low', 'low', 'normal', 'high'];

/** Exactly these own members in any order (`__proto__` is just an unknown key). */
const sameKeys = (value: Record<string, unknown>, names: readonly string[]): boolean => {
  const keys = Object.keys(value);
  return keys.length === names.length && names.every((n) => keys.includes(n));
};

/** A subscription as `PushSubscription.toJSON()` gives it. */
export interface Subscription {
  readonly endpoint: string;
  readonly p256dh: string;
  readonly auth: string;
}

export type SubscriptionRefusal = 'subscription' | 'endpoint' | 'receiver-key' | 'auth-secret';

/**
 * Reads `{endpoint, keys: {p256dh, auth}}` (and the optional `expirationTime`, which is ignored): no other
 * member, no `__proto__`/`constructor`/`prototype` key, one spelling per key. The endpoint must be one a
 * relay hands a ring to.
 */
export function readSubscription(value: unknown): PushResult<Subscription, SubscriptionRefusal> {
  try {
    if (!isPlain(value)) return fail('subscription');
    const keys = Object.keys(value);
    if (keys.some((k) => k !== 'endpoint' && k !== 'keys' && k !== 'expirationTime'))
      return fail('subscription');
    const exp = Object.hasOwn(value, 'expirationTime') ? value['expirationTime'] : null;
    if (exp !== null && !(typeof exp === 'number' && Number.isFinite(exp)))
      return fail('subscription');
    const inner = value['keys'];
    if (!isPlain(inner) || !sameKeys(inner, ['p256dh', 'auth'])) return fail('subscription');
    if (!isRingEndpoint(value['endpoint'])) return fail('endpoint');
    if (!isPoint(inner['p256dh'])) return fail('receiver-key');
    if (!readBytes(inner['auth'], PUSH_LIMITS.authBytes, PUSH_LIMITS.authBytes))
      return fail('auth-secret');
    return pass({
      endpoint: value['endpoint'],
      p256dh: inner['p256dh'],
      auth: inner['auth'] as string,
    });
  } catch {
    return fail('subscription');
  }
}

export interface RingParams {
  /** The receiving device's subscription (anything: it is read strictly). */
  readonly subscription: unknown;
  readonly vapid: {
    readonly privateKey: CryptoKey;
    readonly publicKey: string;
    readonly subject?: string;
  };
  /** Now, whole seconds. */
  readonly nowS: number;
  /** Seconds the VAPID token lives (default 43 200, at most 86 400). */
  readonly lifetimeS?: number;
  /** Seconds the push service keeps the push, 0 to 86 400. */
  readonly ttl: number;
  readonly urgency: Urgency;
  /** Zero octets of padding inside the encrypted push (default 0). */
  readonly padding?: number;
  /** Returns n fresh random bytes (used for the 16-byte salt). */
  readonly random: (n: number) => Uint8Array;
  /** The sender's ephemeral agreement pair; drawn from WebCrypto when absent (tests pass a fixed one). */
  readonly ephemeral?: CryptoKeyPair;
}

export type RingRefusal =
  | SubscriptionRefusal
  | 'vapid'
  | 'subject'
  | 'time'
  | 'lifetime'
  | 'ttl'
  | 'urgency'
  | 'padding'
  | 'random'
  | 'key-mismatch'
  | 'crypto'
  | 'internal';

/** Whether a value is a ring request a relay accepts (the same checks the client and the relay make). */
export function isRingRequest(r: unknown): r is RingRequest {
  if (!isPlain(r)) return false;
  const q = r as Partial<Record<keyof RingRequest, unknown>>;
  return (
    sameKeys(r, ['endpoint', 'vapid', 'ttl', 'urgency', 'content']) &&
    isRingEndpoint(q.endpoint) &&
    isRingVapid(q.vapid) &&
    typeof q.ttl === 'number' &&
    Number.isSafeInteger(q.ttl) &&
    q.ttl >= 0 &&
    q.ttl <= PUSH_LIMITS.ringTtlMax &&
    URGENCIES.includes(q.urgency as Urgency) &&
    q.content instanceof Uint8Array &&
    q.content.length >= 1 &&
    q.content.length <= PUSH_LIMITS.ringContentMax
  );
}

/**
 * Builds the request `RelayClient.ring` takes. Every input is checked before any cryptography runs, and a
 * bad input is a reason code, never an exception. The result is checked once more with `isRingRequest`.
 */
export async function buildRingRequest(
  p: RingParams,
): Promise<PushResult<RingRequest, RingRefusal>> {
  try {
    const sub = readSubscription(p.subscription);
    if (!sub.ok) return sub;
    if (
      !isPlain(p.vapid) ||
      !isPoint(p.vapid.publicKey) ||
      !(p.vapid.privateKey instanceof CryptoKey)
    )
      return fail('vapid');
    if (p.vapid.subject !== undefined && !isSubject(p.vapid.subject)) return fail('subject');
    if (!Number.isSafeInteger(p.ttl) || p.ttl < 0 || p.ttl > PUSH_LIMITS.ringTtlMax)
      return fail('ttl');
    if (!URGENCIES.includes(p.urgency)) return fail('urgency');
    const padding = p.padding ?? 0;
    const room = PUSH_LIMITS.ringContentMax - PUSH_LIMITS.headerBytes - PUSH_LIMITS.recordOverhead;
    if (!Number.isSafeInteger(padding) || padding < 0 || padding > room) return fail('padding');
    if (typeof p.random !== 'function') return fail('random');
    const salt = p.random(PUSH_LIMITS.saltBytes);
    if (!(salt instanceof Uint8Array) || salt.length !== PUSH_LIMITS.saltBytes)
      return fail('random');

    const vapid = await buildVapid({
      endpoint: sub.value.endpoint,
      privateKey: p.vapid.privateKey,
      publicKey: p.vapid.publicKey,
      nowS: p.nowS,
      ...(p.lifetimeS === undefined ? {} : { lifetimeS: p.lifetimeS }),
      ...(p.vapid.subject === undefined ? {} : { subject: p.vapid.subject }),
    });
    if (!vapid.ok) {
      const r = vapid.reason;
      return fail(r === 'audience' ? 'endpoint' : r === 'vapid-key' ? 'vapid' : r);
    }
    const content = await encryptPushMessage({
      plaintext: new Uint8Array(0),
      receiverPublic: sub.value.p256dh,
      authSecret: sub.value.auth,
      salt,
      padding,
      ...(p.ephemeral ? { ephemeral: p.ephemeral } : {}),
    });
    if (!content.ok) {
      return fail(
        content.reason === 'receiver-key' || content.reason === 'auth-secret'
          ? content.reason
          : content.reason === 'padding'
            ? 'padding'
            : 'crypto',
      );
    }
    const request: RingRequest = {
      endpoint: sub.value.endpoint,
      vapid: vapid.value.header,
      ttl: p.ttl,
      urgency: p.urgency,
      content: content.value,
    };
    return isRingRequest(request) ? pass(request) : fail('internal');
  } catch {
    return fail('crypto');
  }
}
