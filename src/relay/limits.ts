// Every number of the relay protocol, version 1, in one place. The table "Limits" in
// docs/relay-protocol.md lists exactly these names with exactly these values (tests/relay/docs.test.ts).
// They are the limits of the relay SERVER; a client keeps to them and bounds what it reads by them.

export const RELAY_LIMITS = {
  /** A message waits at most this long (RAM only), then it is gone. */
  waitMs: 30_000,
  /** A device counts as present this long after its last collect. */
  presenceMs: 30_000,
  /** One message: bytes after decoding. */
  maxContentBytes: 65_536,
  /** Recipients in one drop. */
  maxRecipients: 50,
  /** Device ids a collect may ask presence for. */
  maxPresenceAsk: 200,
  /** What one collect hands out at most (content bytes); the rest stays and `more` says so. */
  collectBytes: 2_097_152,
  /** Messages and bytes waiting for one recipient. */
  mailboxMessages: 100,
  mailboxBytes: 2_097_152,
  /** Every message weighs at least this much in the byte limits below. */
  minMessageWeight: 1024,
  /** Waiting bytes (weighted) per sender, per app and in total. */
  senderBytes: 4_194_304,
  appBytes: 33_554_432,
  totalBytes: 67_108_864,
  /** Largest request body per endpoint. */
  maxBodyBytes: 16_384,
  maxBodyRing: 8_192,
  maxBodyDrop: 6_291_456,
  /** Requests per device and minute. */
  requestsPerMinute: 300,
  /** Per device and hour. */
  ringPerHour: 60,
  invitePerHour: 10,
  /** Enrolments per app and hour: with a proof, with an invitation. */
  enrolProofPerHour: 120,
  enrolInvitePerHour: 60,
  /** Devices known per app, and in all. */
  devicesPerApp: 50,
  devicesTotal: 300,
  /** Lifetimes. */
  accessDays: 90,
  renewBelowDays: 30,
  invitationSeconds: 600,
  proofMaxSeconds: 300,
  proofSkewSeconds: 60,
  /** Time limits of the HTTP layer. */
  headTimeoutMs: 10_000,
  bodyTimeoutMs: 14_000,
  requestTimeoutMs: 30_000,
  /** Ring request: endpoint text, push authorisation header, encrypted push bytes, TTL seconds. */
  ringEndpointMax: 900,
  ringVapidMax: 1_024,
  ringContentMax: 4_096,
  ringTtlMax: 86_400,
} as const;

export type RelayLimits = { readonly [K in keyof typeof RELAY_LIMITS]: number };

/** The documented polling cadence of a collecting client: about every second while an exchange is
 * running, otherwise at most every 10 seconds, and only while the app is in front. */
export const RECOMMENDED_POLL = { busyMs: 1_000, idleMs: 10_000, minMs: 250 } as const;

/** The paths and member names of version 1 are German words; the API of this package is English. */
export const ENDPOINTS = {
  enrol: 'einschreiben',
  ping: 'ping',
  renew: 'erneuern',
  invite: 'einladen',
  drop: 'ablegen',
  collect: 'abholen',
  ring: 'klingeln',
  health: 'gesund',
} as const;

/** Wire member name for each English name used in the TypeScript API. */
export const WIRE_MEMBERS = {
  proof: 'nachweis',
  invitation: 'einladung',
  device: 'geraet',
  access: 'zugang',
  until: 'bis',
  to: 'an',
  content: 'inhalt',
  results: 'ergebnisse',
  ok: 'ok',
  present: 'anwesend',
  messages: 'nachrichten',
  from: 'von',
  ageMs: 'alterMs',
  more: 'mehr',
  validForS: 'gueltigS',
  endpoint: 'endpunkt',
  vapid: 'vapid',
  ttl: 'ttl',
  urgency: 'dringlichkeit',
  service: 'dienst',
  ms: 'ms',
  error: 'fehler',
  kind: 'art',
} as const;
