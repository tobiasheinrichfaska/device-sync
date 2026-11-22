import { PUSH_LIMITS } from './limits.ts';

/** The relay's form of a ring endpoint (docs/relay-protocol.md): https, no port, no login, printable ASCII path. */
const RING_ENDPOINT = /^https:\/\/([A-Za-z0-9.-]+)\/[\x21-\x7e]*$/;

/** The push services a relay hands a ring to: two exact hosts and two suffixes with at least one more label. */
function isKnownPushHost(host: string): boolean {
  if (host === 'fcm.googleapis.com' || host === 'updates.push.services.mozilla.com') return true;
  for (const suffix of ['.push.apple.com', '.notify.windows.com']) {
    if (host.endsWith(suffix)) {
      const rest = host.slice(0, host.length - suffix.length);
      return rest.split('.').every((label) => label.length > 0);
    }
  }
  return false;
}

/** Whether a relay accepts this text as `endpunkt` of a ring (length, form and host, case-sensitive). Never throws. */
export function isRingEndpoint(text: unknown): text is string {
  if (typeof text !== 'string' || text.length < 1 || text.length > PUSH_LIMITS.ringEndpointMax)
    return false;
  const m = RING_ENDPOINT.exec(text);
  return m !== null && isKnownPushHost(m[1] as string);
}

const HTTPS_ENDPOINT = /^https:\/\/([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?(?:\/[\x21-\x7e]*)?$/;

/**
 * The origin of a push endpoint as RFC 8292 wants it in `aud` (`https://host`, lower case, the default
 * port left out); undefined for anything that is not an https URL of this plain form. Never throws.
 */
export function vapidAudience(endpoint: unknown): string | undefined {
  if (
    typeof endpoint !== 'string' ||
    endpoint.length < 1 ||
    endpoint.length > PUSH_LIMITS.endpointMax
  )
    return undefined;
  const m = HTTPS_ENDPOINT.exec(endpoint);
  if (!m) return undefined;
  const host = (m[1] as string).toLowerCase();
  if (host.split('.').some((label) => label.length === 0)) return undefined;
  const port = m[2];
  if (port === undefined) return `https://${host}`;
  if (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65_535) return undefined;
  return port === '443' ? `https://${host}` : `https://${host}:${port}`;
}

const VAPID_HEADER =
  /^vapid t=([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+), k=([A-Za-z0-9_-]{87})$/;

/** Whether a relay accepts this text as `vapid` of a ring (length and form; the token itself is not read). */
export function isRingVapid(text: unknown): text is string {
  return (
    typeof text === 'string' &&
    text.length >= 1 &&
    text.length <= PUSH_LIMITS.ringVapidMax &&
    VAPID_HEADER.test(text)
  );
}

export interface VapidParts {
  readonly header: string;
  readonly claims: string;
  readonly signature: string;
  readonly key: string;
}

/** The parts of a `vapid t=<jwt>, k=<key>` header (the one spelling this package writes), or undefined. */
export function splitVapidHeader(text: unknown): VapidParts | undefined {
  if (typeof text !== 'string' || text.length > PUSH_LIMITS.ringVapidMax) return undefined;
  const m = VAPID_HEADER.exec(text);
  if (!m) return undefined;
  return {
    header: m[1] as string,
    claims: m[2] as string,
    signature: m[3] as string,
    key: m[4] as string,
  };
}
