// The error kinds of the relay protocol, version 1, as DATA: wire token (a German word on the wire),
// English name for the API, HTTP status, what a client does about it. docs/relay-protocol.md lists
// the same rows (tests/relay/kinds.test.ts keeps both in step). A client acts on the kind, never on
// the text the relay sends along.

/**
 * What a client does:
 * - `fatal`: this request can never succeed as built (fix the input, the app id, the origin); no retry.
 * - `retry`: transient; the same request may succeed a little later (bounded retries with backoff).
 * - `reenrol`: the access is of no use any more; enrol again (new device id).
 * - `refused`: the relay says no for now and asking again at once is useless; the caller decides
 *   (wait for the other device to collect, ring it, tell the user).
 */
export type KindClass = 'fatal' | 'retry' | 'reenrol' | 'refused';

export interface RelayKind {
  /** The word on the wire (`art`). */
  readonly token: string;
  /** The name of the kind in this package's API. */
  readonly name: string;
  /** HTTP status of the answer; `null` for a refusal of one recipient inside a 200 answer of a drop. */
  readonly status: number | null;
  readonly class: KindClass;
  /** How long to wait before a retry, in ms, when the class is `retry` or the caller chooses to retry. */
  readonly retryAfterMs: number | null;
}

const k = (
  token: string,
  name: string,
  status: number | null,
  cls: KindClass,
  retryAfterMs: number | null = null,
): RelayKind => ({ token, name, status, class: cls, retryAfterMs });

export const RELAY_KINDS: readonly RelayKind[] = [
  k('unbekannt', 'unknown-endpoint', 404, 'fatal'),
  k('methode', 'wrong-method', 405, 'fatal'),
  k('herkunft', 'origin-refused', 403, 'fatal'),
  k('typ', 'wrong-content-type', 415, 'fatal'),
  k('zu-gross', 'body-too-large', 413, 'fatal'),
  k('zu-langsam', 'body-too-slow', 408, 'retry', 1_000),
  k('unlesbar', 'unreadable', 400, 'fatal'),
  k('zugang-fehlt', 'access-missing', 401, 'fatal'),
  k('zugang-ungueltig', 'access-invalid', 401, 'reenrol'),
  k('zugang-abgelaufen', 'access-expired', 401, 'reenrol'),
  k('app-unbekannt', 'app-unknown', 403, 'fatal'),
  k('gesperrt', 'device-blocked', 403, 'fatal'),
  k('zu-viele-anfragen', 'rate-limited', 429, 'retry', 15_000),
  k('beschaeftigt', 'relay-busy', 503, 'retry', 2_000),
  k('nachweis-ungueltig', 'proof-malformed', 400, 'fatal'),
  k('nachweis-nicht-eingerichtet', 'proof-not-set-up', 403, 'fatal'),
  k('nachweis-unterschrift', 'proof-signature', 403, 'fatal'),
  k('nachweis-abgelaufen', 'proof-expired', 403, 'fatal'),
  k('einladung-ungueltig', 'invitation-invalid', 403, 'fatal'),
  k('einladung-abgelaufen', 'invitation-expired', 403, 'fatal'),
  k('einladen-aus', 'invitations-off', 403, 'fatal'),
  k('verbraucht', 'already-used', 409, 'fatal'),
  k('zu-viele-einschreibungen', 'enrol-rate-limited', 429, 'refused', 300_000),
  k('zu-viele-einladungen', 'invite-rate-limited', 429, 'refused', 300_000),
  k('klingeln-ungueltig', 'ring-invalid', 400, 'fatal'),
  k('klingeln-zu-oft', 'ring-rate-limited', 429, 'refused', 300_000),
  k('push-dienst', 'push-service-unreachable', 502, 'retry', 5_000),
  k('neue-fassung-noetig', 'client-update-needed', 426, 'fatal'),
  k('relay-voll', 'relay-full', 503, 'refused', 300_000),
  k('geraete-voll', 'devices-full', 409, 'refused'),
  k('aufnahme-geschlossen', 'admission-closed', 403, 'fatal'),
  k('intern', 'internal', 500, 'retry', 5_000),
  // Revision 2 (admission), docs/relay-protocol.md "Revision 2".
  k('besitz-fehlt', 'possession-missing', 401, 'fatal'),
  k('besitz-ungueltig', 'possession-invalid', 401, 'fatal'),
  k('besitz-zeit', 'possession-time', 401, 'fatal'),
  k('rolle-nicht-erlaubt', 'role-not-allowed', 403, 'fatal'),
  k('geraet-unbekannt', 'device-unknown', 404, 'fatal'),
  k('sperrliste-voll', 'blocklist-full', 503, 'refused', 300_000),
  k('entwickler-nicht-eingerichtet', 'developer-not-set-up', 403, 'fatal'),
  k('entwickler-ungueltig', 'developer-invalid', 403, 'fatal'),
  k('entwickler-abgelaufen', 'developer-expired', 403, 'fatal'),
  k('entwickler-belegt', 'developer-group-taken', 403, 'fatal'),
  // Refusals of ONE recipient inside the 200 answer of a drop (nothing was stored for it).
  k('voll', 'storage-full', null, 'retry', 3_000),
  k('app-voll', 'app-full', null, 'retry', 3_000),
  k('absender-voll', 'sender-full', null, 'refused'),
  k('empfaenger-voll', 'recipient-full', null, 'refused'),
];

const BY_TOKEN: ReadonlyMap<string, RelayKind> = new Map(RELAY_KINDS.map((x) => [x.token, x]));

/** The row of a wire token, or undefined for a word this version does not know. */
export function kindOfToken(token: unknown): RelayKind | undefined {
  return typeof token === 'string' ? BY_TOKEN.get(token) : undefined;
}

/** The refusal tokens of one recipient of a drop. */
export const DROP_REFUSAL_TOKENS: readonly string[] = RELAY_KINDS.filter(
  (x) => x.status === null,
).map((x) => x.token);

/** Kinds that arise on the client without an answer from the relay. */
export const LOCAL_KINDS = {
  network: { class: 'retry', retryAfterMs: 2_000 },
  timeout: { class: 'retry', retryAfterMs: 2_000 },
  aborted: { class: 'fatal', retryAfterMs: null },
  /** The answer was not what the protocol says (also: an unknown error word, a status that does not fit). */
  malformed: { class: 'fatal', retryAfterMs: null },
  /** A gateway or proxy answered (408, 429, 5xx) without a protocol body. */
  unavailable: { class: 'retry', retryAfterMs: 5_000 },
  'no-credentials': { class: 'reenrol', retryAfterMs: null },
  /** A certificate is stored but the device key that signs for it is missing, unusable or another key: the device is lost, enrol again. */
  'key-missing': { class: 'reenrol', retryAfterMs: null },
  /** This device was told it is blocked (the blocked mark is stored): it does not enrol itself back. Forget the mark to start again. */
  'blocked-mark': { class: 'fatal', retryAfterMs: null },
  /** The credential store refused to read or write. */
  storage: { class: 'fatal', retryAfterMs: null },
  'bad-argument': { class: 'fatal', retryAfterMs: null },
} as const;

export type LocalKind = keyof typeof LOCAL_KINDS;
