# Push layer: ring request, Web Push encryption, VAPID, service worker

**New, not yet reviewed.** This document says what `src/push/` builds, what it does not protect, and the
numbers and codes the tests hold the code to (`tests/push/docs.test.ts`).

A sleeping device cannot read a relay. The relay layer therefore lets a device ring another one: the
ringing device builds a Web Push request for the other device's browser subscription and hands it to the
relay (`RelayClient.ring`), which forwards it to the push service because a browser may not
(`docs/relay-protocol.md`, "`POST /v1/klingeln`"). The push layer builds that request, and the script the
woken device runs.

The layer is pure: time (`nowS`, whole seconds) and the salt (`random(n)`) are parameters; WebCrypto is the
only other source. One ephemeral agreement key per message is drawn from WebCrypto unless the caller passes
one (tests do). Every function answers `{ ok: true, value }` or `{ ok: false, reason }` and never throws on
bad input; the reason is a code, not a sentence.

## What is built

| Function                                         | What it does                                                                                                                                               |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `buildRingRequest(params)`                       | the `RingRequest` the client takes: `endpoint`, `vapid`, `ttl`, `urgency`, `content`, nothing else                                                         |
| `readSubscription(value)`                        | strict reader of `PushSubscription.toJSON()`: `endpoint`, `keys.p256dh`, `keys.auth`, `expirationTime` (ignored)                                           |
| `isRingRequest`, `isRingEndpoint`, `isRingVapid` | the relay's own conditions for a ring request, endpoint and authorisation header                                                                           |
| `encryptPushMessage`, `decryptPushMessage`       | RFC 8291 / RFC 8188 `aes128gcm`, exactly one record, padding parameter; decrypt is for tests and receivers                                                 |
| `generateVapidKeys`, `buildVapid`, `checkVapid`  | RFC 8292: ES256 JWT with `aud`, `exp` (at most 24 h), optional `sub`; the header `vapid t=<jwt>, k=<key>`; the check a push service or a test server makes |
| `buildServiceWorkerSource(options)`              | the JavaScript text of a service worker for a content-free push                                                                                            |

### The ring request

`buildRingRequest` checks every input before any cryptography runs, builds the VAPID token for the origin
of the endpoint, encrypts an **empty** message (plus `padding` zero octets) for the subscription's `p256dh`
key and `auth` secret, and checks the result with `isRingRequest` once more. A ring carries no content by
design: the woken device learns only that something is waiting and asks the relay.

The endpoint must be one the relay hands a ring to: `https`, no port, no login, at most 900 characters, the
host exactly `fcm.googleapis.com` or `updates.push.services.mozilla.com`, or ending with `.push.apple.com`
or `.notify.windows.com` with at least one more label before the ending (case-sensitive, as in the
protocol document). The package is stricter in one point: an empty label (`a..push.apple.com`) is refused.

The shape of `p256dh` (one canonical spelling of an uncompressed P-256 point) is checked by
`readSubscription`; that it lies on the curve is checked when the message is encrypted, as `receiver-key`.

### Message encryption

Header (86 octets): salt (16), record size `rs` (4, big endian), key id length (1, always 65), the sender's
ephemeral public point (65). Then one record: plaintext, the delimiter octet `0x02`, zero padding, and the
AES-128-GCM tag (16). Keys follow RFC 8291 section 3.3 and 3.4 (`WebPush: info`, `Content-Encoding:
aes128gcm`, `Content-Encoding: nonce`). `tests/vectors/push.json` holds the RFC 8291 appendix A vector with
every intermediate value; the code reproduces it byte for byte, and an implementation written with
`node:crypto` alone (`tests/push/reference.ts`) agrees with the code on 300 seeded random messages in both
directions.

`rs` is 4096 by default and 18 to 4096 on request; this package reads no larger one. A message that is
longer than one record is refused (`multiple-records`) rather than read in part. The relay takes at most
4096 octets of encrypted push, so a ring has room for 3993 octets of padding.

### VAPID

The token is `base64url({"typ":"JWT","alg":"ES256"}) . base64url({"aud":..,"exp":..,"sub":..}) . signature`
(raw 64-octet signature), exactly one spelling: key order `aud`, `exp`, `sub`, no spaces. `aud` is the origin
of the endpoint (`https://host`, default port left out). `exp` is `nowS + lifetimeS`; the lifetime is 1 to
86 400 seconds (RFC 8292: at most 24 hours), 43 200 by default. The builder signs, then verifies the
signature with the public key it was given, so a private key that does not belong to it is `key-mismatch`
instead of a token the push service refuses with 403. The RFC 8292 section 2.4 token is in the vectors; its
signature verifies with the published key.

`checkVapid` is stricter than RFC 8292 on purpose (one spelling, `t` before `k`, only the claims above, the
JWT header exactly as written). A push service may be more liberal; a token built here passes both.

### Service worker template

`buildServiceWorkerSource({ texts, fallback, appUrl, tag, icon?, badge? })` returns the text of a script
the app serves itself. On a `push` event it shows one notification from the table (title and body by the
primary subtag of `navigator.language`, else the fallback) and keeps the event alive until it is shown
(browsers require a visible notification for every push). On `notificationclick` it closes the notification
and focuses a window of the app (same origin, same path or below it) or opens `appUrl`. A URL is an absolute
`https` URL without fragment or a path starting with one `/`; **a backslash is refused anywhere in it**, because
a browser reads `/\host` as `//host` (another origin).

The script never reads the push event's `data`, never reads the notification's `data`, uses no network API
and no `eval`; the tests run the generated text in a `node:vm` sandbox with a fake scope and look for those
words in the text. The texts are checked (printable, no control, format, surrogate or line separator
characters; title at most 100, body at most 300 characters), written as JSON with `<` and the two line
separators escaped, so a hostile text stays text.

## What is NOT protected

- **The push service sees timing and endpoint.** It sees who is rung when, how often, and the size of the
  encrypted body (padding hides the size only within one value of `padding`). The relay sees the push
  endpoint of every ring while it forwards it (`docs/relay-protocol.md`).
- **The payload is content-free by design.** Nothing a sender writes into the push is shown or trusted: the
  template ignores the payload completely, and `buildRingRequest` encrypts an empty message. Anyone who
  holds the subscription (the endpoint with its keys) can send a push to that device; the push service
  cannot tell a ring from a forgery, and neither can the receiver. A forged ring only makes the device
  look at its relay, which is authenticated.
- **No forward secrecy beyond the ephemeral key** and no replay protection: a push may be delivered twice or
  late (`ttl` bounds how late). The salt must be fresh for every message; the package takes it as a
  parameter and cannot check it.
- **VAPID identifies the sender to the push service**, not to the receiver. A VAPID key that leaks lets
  others ring the subscriptions that were made with it.
- **The text table is shown on the lock screen** in the browser's language; keep it neutral.
- **Not run against a real push service.** Vectors and the reference implementation come from the RFCs; no
  Firebase, Mozilla, Apple or Windows push service was contacted.
- Browser support for `renotify`, `badge` and background delivery differs; the template uses only widely
  implemented members.

## Limits

| Name                    | Value  |
| ----------------------- | ------ |
| `saltBytes`             | 16     |
| `authBytes`             | 16     |
| `pointBytes`            | 65     |
| `headerBytes`           | 86     |
| `recordOverhead`        | 17     |
| `recordSizeMin`         | 18     |
| `recordSizeMax`         | 4096   |
| `vapidLifetimeMaxS`     | 86_400 |
| `vapidLifetimeDefaultS` | 43_200 |
| `subjectMax`            | 200    |
| `ringEndpointMax`       | 900    |
| `ringVapidMax`          | 1_024  |
| `ringContentMax`        | 4_096  |
| `ringTtlMax`            | 86_400 |
| `endpointMax`           | 2_048  |
| `workerTitleMax`        | 100    |
| `workerBodyMax`         | 300    |
| `workerUrlMax`          | 500    |
| `workerLanguagesMax`    | 40     |

The four `ring...` values are the relay's (`RELAY_LIMITS`); a test checks that they stay equal.

## Codes

Each code is a `reason`. The test checks that every code listed here exists in the source and every code
the source writes is listed.

| Function                   | Codes                                                                                                                        |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `readSubscription`         | `subscription` `endpoint` `receiver-key` `auth-secret`                                                                       |
| `buildRingRequest`         | the four above and `vapid` `subject` `time` `lifetime` `ttl` `urgency` `padding` `random` `key-mismatch` `crypto` `internal` |
| `encryptPushMessage`       | `plaintext` `receiver-key` `auth-secret` `salt` `padding` `record-size` `too-long` `crypto`                                  |
| `decryptPushMessage`       | `body` `receiver-key` `auth-secret` `header` `record-size` `key-id` `multiple-records` `decrypt` `delimiter` `crypto`        |
| `buildVapid`               | `audience` `time` `lifetime` `subject` `vapid-key` `key-mismatch` `crypto`                                                   |
| `checkVapid`               | `header` `token` `claims` `audience` `expired` `lifetime` `key` `signature` `crypto`                                         |
| `buildServiceWorkerSource` | `options` `texts` `language` `text` `fallback` `url` `tag`                                                                   |
