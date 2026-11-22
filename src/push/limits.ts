import { RELAY_LIMITS } from '../relay/limits.ts';

/** Numbers of the push layer (the four ring limits are the relay's, repeated here so the layer reads alone). */
export const PUSH_LIMITS = {
  /** RFC 8188 salt. */
  saltBytes: 16,
  /** RFC 8291 authentication secret. */
  authBytes: 16,
  /** An uncompressed P-256 point. */
  pointBytes: 65,
  /** aes128gcm header of a Web Push message: salt 16 + record size 4 + key id length 1 + key id 65. */
  headerBytes: 86,
  /** AES-GCM tag plus the one delimiter octet every record carries. */
  recordOverhead: 17,
  /** Smallest record size RFC 8188 allows. */
  recordSizeMin: 18,
  /** Record size used when none is given, and the largest this package writes or reads (RFC 8291: 4096). */
  recordSizeMax: 4096,
  /** RFC 8292: `exp` is at most 24 hours after the request. */
  vapidLifetimeMaxS: 86_400,
  /** `exp` distance used when none is given. */
  vapidLifetimeDefaultS: 43_200,
  /** Longest `sub` claim. */
  subjectMax: 200,
  /** Longest push endpoint the relay accepts for a ring. */
  ringEndpointMax: RELAY_LIMITS.ringEndpointMax,
  /** Longest push authorisation header the relay accepts. */
  ringVapidMax: RELAY_LIMITS.ringVapidMax,
  /** Longest encrypted push the relay accepts. */
  ringContentMax: RELAY_LIMITS.ringContentMax,
  /** Longest TTL the relay accepts, seconds. */
  ringTtlMax: RELAY_LIMITS.ringTtlMax,
  /** Longest endpoint any helper reads (VAPID audience). */
  endpointMax: 2048,
  /** Service worker template: longest title. */
  workerTitleMax: 100,
  /** Service worker template: longest body text. */
  workerBodyMax: 300,
  /** Service worker template: longest URL (app, icon, badge). */
  workerUrlMax: 500,
  /** Service worker template: most languages in the text table. */
  workerLanguagesMax: 40,
} as const;

export type PushLimits = typeof PUSH_LIMITS;

/** Result of a push helper: a value or a code (never an exception for bad input). */
export type PushResult<T, R extends string> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly reason: R };

export const fail = <R extends string>(reason: R): { readonly ok: false; readonly reason: R } => ({
  ok: false,
  reason,
});
export const pass = <T>(value: T): { readonly ok: true; readonly value: T } => ({
  ok: true,
  value,
});
