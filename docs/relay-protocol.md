# Relay protocol, version 1 and revision 2 (admission)

This is the exact protocol of a small store-and-forward message relay, written so that a server and any
port of it (Node, PHP, other) can be implemented without reading code, and a client can be tested
against any of them. It is the contract of `src/relay/` (client, strict readers, error-kind table,
conformance runner) and of the cases in `tests/relay/conformance/cases.json`.

Words in capitals (MUST, MUST NOT, MAY, SHOULD) are meant as in RFC 2119.

**Status: version 1 as the existing relay servers speak it, and revision 2 (admission), which the existing
servers also speak and which adds to version 1 without taking anything away** (see "Revision 2: what changes";
a client of version 1 keeps working against a relay of revision 2, and the cases of version 1 pass against one).
Revision 2 was written from the written interface and the source of the existing server and checked by running
the conformance cases against it (see "Verification against the existing relay"). The rest of this paragraph
is about version 1. The endpoint names, member names and error
kinds of version 1 are German words. They are the wire format and are written here exactly as they are
sent; every identifier of the TypeScript API is English and the two are mapped by the tables in
"English names in this package". Where the written interface document of the existing servers is silent
or ambiguous and the server source settles the point, this document records what the server does and says
so; where neither settles it, the point is listed in "Open points of version 1" and is NOT decided here.

## What the relay is, and what it does not protect

A relay hands a message from one device to another. A device drops a message for one or more other
devices of the same app; the relay keeps it in RAM for at most 30 seconds and hands it over, once, when the
recipient collects it. The relay never decrypts anything: the content is opaque bytes that the sending
app has already encrypted for exactly one recipient. A relay may also pass on a finished push request to a
push service so that a sleeping device can be rung.

What the relay **sees**: the app and device id of every request, sender and recipient ids of every
message, message sizes, the time of every request, who collected recently (presence), the IP address at
the edge (the protocol itself needs no IP address and a server SHOULD NOT read or keep it), and the push
endpoint of a ring while it forwards it. It does NOT see message content.

What the relay (or whoever operates it) **can do**: drop, delay, duplicate or reorder messages; refuse
service; tell a device that another device is or is not present (presence is a statement of the relay and
not proven). Whoever holds the signing secret of the relay can enrol devices and make accesses for any
device id, and so can drop messages as any device and collect the messages of any device. Clients MUST
therefore protect content and authenticity end to end and MUST treat every message as something that may
arrive twice, late, out of order or not at all. The relay is no authority on who a device is.

The admission revision (device certificates with a proof of possession on every request, groups, roles,
listing and blocking of devices, more ways to enrol) is revision 2, described in "Revision 2: what changes" and
the sections after it. Its tokens and endpoints are not accepted by a relay of version 1. A relay of revision 2
may answer a version-1 client with refusals of that revision (`neue-fassung-noetig`, `gesperrt`,
`aufnahme-geschlossen`, `geraete-voll`, and a refusal because the whole relay is full, see open point 9), which
are listed in "Error kinds".

## Transport rules

- **Address:** `https://<host>/v1/<endpoint>`, plus `GET https://<host>/gesund`. The address carries no
  ids, no access and no content. An address containing `?` or `#` is refused (`unlesbar`, 400), also for
  `/gesund`.
- **Method and body:** every endpoint except `/gesund` takes `POST` with a JSON body and the header
  `Content-Type: application/json` (the part before `;` is compared in lower case after trimming, so
  `Application/JSON; charset=utf-8` is accepted). `OPTIONS` is the browser's preflight. Every other method
  is refused (`methode`, 405).
- **Origin:** every request to an endpoint carries an `Origin` header that is one of the allowed origins
  of the app it concerns (exact string comparison, for example `https://app.example`, no path, no port
  unless it is part of the origin). The answer then carries `Access-Control-Allow-Origin` with exactly that
  origin. A request without `Origin`, or with another one, is refused (`herkunft`, 403) **without** an
  `Access-Control-Allow-Origin` header. A client that is not a browser MUST send an allowed `Origin` itself.
- **Access:** `Authorization: Bearer <access>` (an access of the form `z1...`, see "Tokens"; in revision 2 also a
  certificate `c1...` together with a signature header, see "Revision 2: what changes"). No cookies
  are used or set; a browser client sends `credentials: 'omit'` and `redirect: 'error'` (the package client also
  refuses an answer that a fetch reports as `redirected` or whose `url` is not the relay's origin).
- **Every answer** (every status, also refusals of the HTTP layer and the empty answer of a preflight)
  carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `Vary: Origin`. Every answer
  except the 204 of a preflight is JSON with `Content-Type: application/json; charset=utf-8`. An answer
  carries `Access-Control-Allow-Origin` (the request's origin) whenever the request's origin is an allowed
  origin of some app the relay serves, except for the refusals `herkunft` and `unbekannt` and for `methode`
  on `/gesund`, which never carry it. (A caching proxy that rewrites `no-store` is a deployment problem,
  not part of the protocol.)
- **Head before body:** path, method, origin, content type and access are decided before a byte of the
  body is read. What fails there is refused without reading the body. Only then is the body read, up to the
  limit of the endpoint (see "Limits"); a body over it is refused at once with `zu-gross` (413), also when no
  `Content-Length` was announced, and an announced length over the limit is refused before the body is read.
  A client that is still writing a body of several megabytes when the relay answers and closes may see a
  reset instead of the 413 (RFC 9112, 9.6); the real server does exactly that on a fast local connection, so
  the one conformance step with a 6 MB body accepts a closed connection (`mayCloseConnection`). A client of
  this protocol never sends more than 4.4 MB (50 recipients of 64 KiB), so it cannot run into it.
- **Time limits of the HTTP layer:** the head must be complete within 10 s (otherwise the connection is
  ended, possibly with a bare 408 without CORS: a client treats that as a network error), the body within
  14 s (otherwise `zu-langsam`, 408), the whole request within 30 s.
- **Refusal body:** `{"fehler": "<short reason, German text>", "art": "<kind>"}` with the status of the
  kind. A client decides by `art` and never by `fehler`. `fehler` is at most 200 characters.
- **Strictness:** unknown members, wrong types and oversize values are refused (the whole request), never
  trimmed or completed. Every success body has exactly the members listed here, no others.
- **Version marker:** the version is the path prefix `/v1`; revision 2 keeps it. A client announces the revision it
  speaks in an optional header and a relay says its own in the answers ("Negotiation"); a request without the
  header is judged exactly as version 1 judges it.

## English names in this package

The wire words in the first table are exact. `ENDPOINTS` and `WIRE_MEMBERS` in `src/relay/limits.ts`
hold the same mapping (checked by `tests/relay/docs.test.ts`). The two request headers of revision 2 are not
members of a body; their names are configuration (open point 15).

| API name  | Wire path/word |
| --------- | -------------- |
| `enrol`   | `einschreiben` |
| `ping`    | `ping`         |
| `renew`   | `erneuern`     |
| `invite`  | `einladen`     |
| `devices` | `geraete`      |
| `block`   | `sperren`      |
| `drop`    | `ablegen`      |
| `collect` | `abholen`      |
| `ring`    | `klingeln`     |
| `health`  | `gesund`       |

| API member     | Wire member        |
| -------------- | ------------------ |
| `proof`        | `nachweis`         |
| `invitation`   | `einladung`        |
| `device`       | `geraet`           |
| `access`       | `zugang`           |
| `until`        | `bis`              |
| `to`           | `an`               |
| `content`      | `inhalt`           |
| `results`      | `ergebnisse`       |
| `ok`           | `ok`               |
| `present`      | `anwesend`         |
| `messages`     | `nachrichten`      |
| `from`         | `von`              |
| `ageMs`        | `alterMs`          |
| `more`         | `mehr`             |
| `validForS`    | `gueltigS`         |
| `endpoint`     | `endpunkt`         |
| `vapid`        | `vapid`            |
| `ttl`          | `ttl`              |
| `urgency`      | `dringlichkeit`    |
| `service`      | `dienst`           |
| `ms`           | `ms`               |
| `error`        | `fehler`           |
| `kind`         | `art`              |
| `certificate`  | `zertifikat`       |
| `founder`      | `gruender`         |
| `password`     | `passwort`         |
| `group`        | `mandant`          |
| `role`         | `rolle`            |
| `deviceKey`    | `geraetSchluessel` |
| `app`          | `app`              |
| `revision`     | `v`                |
| `abilities`    | `faehigkeiten`     |
| `procedures`   | `verfahren`        |
| `offered`      | `angeboten`        |
| `preferred`    | `bevorzugt`        |
| `enrolWays`    | `einschreiben`     |
| `protocol`     | `p`                |
| `deviceList`   | `geraete`          |
| `maxDevices`   | `hoechstens`       |
| `introducedBy` | `von`              |
| `since`        | `seit`             |
| `last`         | `zuletzt`          |
| `procedure`    | `verfahren`        |
| `blocked`      | `gesperrt`         |
| `commit`       | `stand`            |
| `oldOff`       | `altAbgeschaltet`  |
| `intakeOpen`   | `aufnahmeOffen`    |

## Identifiers and values

| Value          | Form                                                                          | Who makes it                              |
| -------------- | ----------------------------------------------------------------------------- | ----------------------------------------- |
| app id         | `^[a-z][a-z0-9]{1,15}$`                                                       | the relay's configuration                 |
| device id      | `geraet-` followed by 32 lower-case hex digits (128 random bits)              | the relay, at enrolment                   |
| access         | `z1.<app>.<device>.<bis>.<mac>`                                               | the relay, at enrolment and renewal       |
| invitation     | `e1.<app>.<bis>.<random>.<mac>`                                               | the relay, at `einladen`                  |
| proof          | `n1.<payload>.<signature>`                                                    | the login script of a test zone           |
| content        | base64url without `=`, canonical, 1 to 65 536 bytes after decoding            | the app (already encrypted)               |
| end day        | `YYYY-MM-DD`, UTC date of the end second of an access                         | the relay                                 |
| certificate    | `c1.<app>.<group>.<device>.<role>.<key>.<bis>.<mac>` (revision 2)             | the relay, at enrolment and renewal       |
| invitation e2  | `e2.<app>.<group>.<inviter>.<role>.<bis>.<random>.<mac>` (rev. 2)             | the relay, at `einladen`                  |
| founder ticket | `g1.<app>.<group>.<bis>.<random>.<signature>` (revision 2)                    | the developer                             |
| group          | `^(?!standard$)[a-z0-9-]{1,20}$`; `1` for everything old (revision 2)         | the relay's configuration, the invitation |
| role           | `buero`, `ohne` or `lb:<id>` with `<id>` of 1 to 40 of `A-Za-z0-9_-` (rev. 2) | the inviter, the ticket                   |

"Canonical base64url" means the characters `A-Z a-z 0-9 - _` only, no padding, and the text re-encodes to
itself (so a value has one spelling; for example `AB` is not canonical because its last character has
non-zero unused bits). A content of zero bytes is refused.

## Tokens

All times are whole seconds since 1970-01-01 UTC, judged by the relay's clock; `now` below is that clock
truncated to seconds. A token is valid while `bis > now`.

### Access

`z1.<app>.<device>.<bis>.<mac>`

- `<bis>`: end time in seconds since 1970, 1 to 12 decimal digits, no leading zero.
- `<mac>`: base64url (43 characters; clients and tests treat the canonical spelling as the only one, see open
  point 12) of `HMAC-SHA-256(secret, UTF-8("zugang:" + head))`, where
  `head` is the text `z1.<app>.<device>.<bis>` and `secret` is the relay's secret (at least 32 random
  bytes). The relay keeps no device list for accesses: possession of a valid access is the credential.
- Lifetime: 90 days (7 776 000 s) from the moment of issue, at enrolment and at every renewal.
- A client renews when fewer than 30 days remain. An old access stays valid until its own end. After the
  end the device enrols again (it gets a new device id).
- Compared in constant time. A new secret makes every access and invitation invalid at once, unless the relay is
  configured with a previous secret for a transition period: the existing relay then keeps accepting tokens
  signed with the previous secret until their own end (open point 12).

### Invitation

`e1.<app>.<bis>.<random>.<mac>`

- `<random>`: 16 random bytes, base64url (22 characters, canonical).
- `<mac>`: as above over `UTF-8("einladung:" + head)` with `head` = `e1.<app>.<bis>.<random>`. The label differs,
  so an access can never pass as an invitation or the other way round.
- Valid while `now < bis <= now + 600`; the relay makes it with `bis = now + 600`. A `bis` further ahead is
  `einladung-ungueltig`, a `bis` in the past is `einladung-abgelaufen`.
- **Single use:** the relay records the used invitation (by its random part) until `bis` and refuses a
  second enrolment with it (`verbraucht`).

### Proof

`n1.<payload>.<signature>`

- `<payload>`: base64url (1 to 400 characters) of the UTF-8 JSON text of exactly
  `{"v":1,"app":"<app>","bis":<seconds>,"n":"<22 characters>"}`, with `n` the base64url of 16 random bytes.
  The relay accepts the members in any order but exactly these four, `v` the number 1, `bis` a safe integer.
  No name of a person is in it.
- `<signature>`: base64url (86 characters) of an ECDSA P-256 / SHA-256 signature in the IEEE P1363 format
  (64 bytes, as Web Crypto produces) over the ASCII text `n1.<payload>`.
- The relay holds, per app, zero or more public keys as the raw uncompressed point (65 bytes, 87 characters
  base64url). The proof is genuine when any of them verifies it. An app with no key refuses every proof.
- Valid while `now < bis <= now + 360` (300 seconds plus 60 seconds of clock difference).
- **Single use:** recorded by `n` until `bis`; a second enrolment with it is `verbraucht`.
- The app a proof (or an access, or an invitation) names is judged **before** its signature: a text that
  names an app of the relay and arrives from an origin of another app is `herkunft` (403, no CORS header),
  valid or not, so the page of another app learns nothing about it.

## Endpoints

Success statuses are exact. A body that is not exactly as written is not an answer of the relay.

### `GET /gesund`

No access. `200 {"ok": true, "stand": "<text, at most 64 characters>"}` where `stand` names the running
build (`"unbekannt"` when it does not know). The relay MAY add the members `v` (integer), `faehigkeiten`
(list of words), `verfahren` (an object `angeboten`, `bevorzugt`, `einschreiben`) and, for a known origin,
`app`, `altAbgeschaltet`, `aufnahmeOffen` of the later admission revision. With an allowed `Origin` the
answer carries CORS headers; otherwise it does not. Any other method: `methode`, 405, without CORS.

### `POST /v1/einschreiben` (enrol)

No access. Body: exactly one of `{"nachweis": "<proof>"}` or `{"einladung": "<invitation>"}`; nothing else.
Answer `201`:

```json
{
  "geraet": "geraet-3f2a...",
  "zugang": "z1.alpha.geraet-3f2a....1802476800.<mac>",
  "bis": "2027-02-13"
}
```

The app of the new device is the app the proof or invitation names, never something the device says. The
`zugang` is shown only here; the client keeps it. The origin MUST belong to that app.

Refusals (see the order of checks): `unlesbar`, `nachweis-ungueltig`, `nachweis-nicht-eingerichtet`,
`nachweis-unterschrift`, `nachweis-abgelaufen`, `einladung-ungueltig`, `einladung-abgelaufen`,
`einladen-aus` (invitations are off for the app), `app-unbekannt`, `herkunft`, `verbraucht`,
`aufnahme-geschlossen`, `geraete-voll`, `zu-viele-einschreibungen`.

A device counts as **known** to the relay when it enrols, and also when a request with its access has a
readable body; at most twice `devicesPerApp` devices per app are remembered. The device limits
(`devicesPerApp`, `devicesTotal`) count the known devices. A relay holds no persistent device list: after a
restart the count fills again as devices ask.

### `POST /v1/ping`

Body `{}` (nothing else). Answer `200 {"geraet": "<device>", "app": "<app>", "bis": "<end day>"}`: the device
and app of the access and the end day of that access.

### `POST /v1/erneuern` (renew)

Body `{}`. Answer `200 {"zugang": "<new access>", "bis": "<end day>"}`: a new access for the same device and
app, valid 90 days from now. The old access stays valid until its own end. An expired access cannot
renew (`zugang-abgelaufen`).

### `POST /v1/einladen` (invite)

Body `{}`. Needs `einladen` to be on for the app (else `einladen-aus`). Answer `201`
`{"einladung": "<invitation>", "gueltigS": 600}`. Any known device of the app may invite; whether the app
lets it is the app's decision. Refusals: `einladen-aus`, `zu-viele-einladungen` (more than 10 per device and
hour).

### `POST /v1/ablegen` (drop)

```json
{ "an": [{ "geraet": "geraet-...", "inhalt": "<base64url>" }] }
```

- 1 to 50 entries; each recipient at most once; not the sending device; each `inhalt` canonical base64url
  of 1 to 65 536 bytes. One unreadable entry refuses the whole request (`unlesbar`, nothing is stored).
- Each entry is judged on its own: the answer is `200` with one result per entry in the order asked.
  `{"geraet", "ok": true, "anwesend": <bool>}` means stored; `anwesend` is whether the recipient collected
  within the last 30 s. `{"geraet", "ok": false, "art": "<reason>", "fehler": "<text>"}` means NOT stored;
  the reasons are `voll`, `app-voll`, `absender-voll`, `empfaenger-voll`. Other entries of the same request
  are still stored.
- A message is put into the mailbox of the **app of the sender** for the recipient id. A device of another
  app never receives it, even if the sender knows its id (apps are separate).
- The message waits at most 30 s, in RAM only, and is deleted when collected. A recipient the relay has
  never seen is a valid recipient.
- Every message weighs `max(its bytes, minMessageWeight)` in the byte limits. The reasons are checked in
  this order for each entry: `voll` (total), `app-voll`, `absender-voll`, then `empfaenger-voll` (messages
  or bytes in the recipient's mailbox).

### `POST /v1/abholen` (collect)

```json
{ "anwesend": ["geraet-...", "..."] }
```

`anwesend` is optional (omitted = empty): at most 200 distinct device ids whose presence the device asks
about. Any other member, a `null`, a duplicate or a bad id is `unlesbar`. Answer `200`:

```json
{
  "nachrichten": [{ "von": "geraet-...", "inhalt": "<base64url>", "alterMs": 1500 }],
  "anwesend": ["geraet-..."],
  "mehr": false
}
```

- `nachrichten`: the device's waiting messages in the order they were dropped (see "Ordering"), each
  deleted from the relay by this answer. `von` is the sender's id as the relay knows it from the sender's
  access (it cannot be forged by the sender's body). `alterMs` is the whole number of milliseconds since the
  relay accepted the message, between 0 and 30 000 (a message of 30 s or more is gone).
- At most 2 097 152 content bytes per answer: messages are taken while the sum stays within it, always at
  least the first. When messages remain, `mehr` is `true` and the client SHOULD collect again at once.
- `anwesend`: only ids that were asked about, each at most once, that collected within the last 30 s, and
  never the asking device. There is no directory and no list of all devices.
- A collect with nothing waiting is `200` with `"nachrichten": []`, the asked-and-present ids, `"mehr": false`.
- Every collect, also an empty one, makes the collecting device **present** from that moment.

### `POST /v1/klingeln` (ring)

```json
{
  "endpunkt": "https://fcm.googleapis.com/...",
  "vapid": "vapid t=<jwt>, k=<87 characters>",
  "ttl": 900,
  "dringlichkeit": "high",
  "inhalt": "<base64url>"
}
```

The ringing device built and encrypted the push request itself; the relay only hands it to a known push
service, because a browser may not. All five members, nothing else:

- `endpunkt`: at most 900 characters, matching `^https://[A-Za-z0-9.-]+/[\x21-\x7e]*$`, `https` with no port
  and no login in the address, and the host is exactly `fcm.googleapis.com` or
  `updates.push.services.mozilla.com`, or ends with `.push.apple.com` or `.notify.windows.com` with at least
  one more label before that ending. No redirect is followed; TLS is verified.
- `vapid`: at most 1024 characters, matching `^vapid t=<b64url>.<b64url>.<b64url>, k=<87 base64url characters>$`.
- `ttl`: an integer 0 to 86 400 (seconds).
- `dringlichkeit`: `very-low`, `low`, `normal` or `high`.
- `inhalt`: canonical base64url of 1 to 4096 bytes.

Answer `200 {"dienst": <push service HTTP status, 100 to 599>, "ms": <integer>}`: only the status of the push
service, which is passed on whatever it is. The relay waits at most 10 s for the head of the push service's
answer. Refusals: `klingeln-ungueltig` (400: any member does not fit), `klingeln-zu-oft` (more than 60 per
device and hour; counted by time only, never by target), `push-dienst` (502: not reached).

## Revision 2: what changes (admission)

Revision 2 adds to version 1; it takes nothing away. A relay of revision 2 answers every version-1 request
exactly as written above (the version-1 conformance cases pass against it unchanged), and a client of
version 1 keeps working against it. What revision 2 adds:

- **Certificates.** At enrolment a device can give its own public key (`geraetSchluessel`) and get a
  certificate (`c1...`) instead of, or beside, the old access. A certificate names the app, the group, the
  device, the role and the key. Whoever takes it cannot use it without the key.
- **Proof of possession.** Every request that carries a certificate is signed with the device's private key
  (a header with `<t>.<signature>` over method, path, time, hash of the body and the certificate). A stolen
  certificate is worth nothing without the key, and a signature is taken once.
- **Groups and roles.** Devices, presence, mailboxes, the device list and blocks belong to a group of an app
  (a school, a club: `mandant` on the wire). Every device has a role: `buero` (the office), `lb:<id>` (the
  devices of one member) or `ohne` (none). The role is set by the invitation of the inviting device, by the
  founder ticket and the developer password (always `buero`), or, with the old ways only, claimed by the
  device itself, which the relay cannot check.
- **More ways to enrol.** An invitation `e2` (made by a device with a certificate: it carries the group and
  the role of the new device), a founder ticket `g1` (signed by the developer, makes the first device of a
  group) and a developer password (the same, from a list of hashes in the relay's configuration).
- **The device list and blocking.** `geraete` lists the devices of the caller's group as its role may see
  them; `sperren` blocks a device. A blocked device is refused with `gesperrt` on every request, with a
  certificate or an old access.
- **Strict groups.** The relay can switch the old procedure off for a group, by hand, once every device of
  it has a certificate (`neue-fassung-noetig`, 426).
- **Negotiation.** A client finds out what the relay can do before it relies on it.
- **An evaluation endpoint** `auswertung` for the developer alone (counts per group, never an id). It is not
  used by a client and not described further.

The words `mandant`, `rolle`, `gruender`, `passwort`, `zertifikat` and so on are the wire words of the
existing relay servers, kept exactly (see "English names in this package").

### Negotiation

A client that wants to use revision 2 asks the relay what it can do. The relay says so in three members that
a version-1 relay never sends:

- `v`: the revision as an integer (2 for this document), `faehigkeiten`: a list of words (the existing relay
  sends `mandant`, `zertifikat`, `besitznachweis`, `einladung2`, `gruender`, `sperren`, `geraete`; a client
  treats a word it does not know as nothing) and `verfahren`: what the relay serves and prefers for the
  group the answer is about:

```json
{
  "angeboten": ["zugang", "zertifikat"],
  "bevorzugt": "zertifikat",
  "einschreiben": ["nachweis", "einladung", "einladung2", "gruender", "passwort"]
}
```

`angeboten` are the techniques of authentication: `zugang` is the old access (a bearer value, only in
group `1`, and not where the group is strict), `zertifikat` the certificate with the proof of possession. In
every group but `1`, and where the group is strict, only `["zertifikat"]`. `bevorzugt` is always
`zertifikat`. `einschreiben` are the ways a device can enrol; where the old procedure is off only
`einladung2`, `gruender` and `passwort`.

They come in three places: `GET /gesund` (without access; for the first group `1` of the app of the request's
origin, or for what the code serves at all when the origin is unknown), `ping` (with a certificate always,
with an old access only when the request announces the revision in the version header) and the answers of
enrolment and renewal that carry a certificate. A relay of version 1 sends none of them; a client that sees
no `v` speaks version 1.

The version header (open point 15 for its name) carries the revision the client speaks as 1 to 3 digits. It
is optional; a relay of version 1 refuses an unknown header already at the preflight, which a browser shows as
a network failure, so a client that announces it and fails that way MAY try once more without it. A client
sends it with every request that carries a certificate. The relay notes the value per device (`p` in the
device list).

### Tokens of revision 2

All times are whole seconds since 1970 as in "Tokens"; a token is valid while `bis > now`. Every MAC is
`HMAC-SHA-256(secret, UTF-8(label + ":" + head))` in canonical base64url (43 characters), compared as text
(open point 12), with the same secret as the access; a new secret makes every certificate and invitation
invalid at once, unless a previous secret is configured.

**Certificate** `c1.<app>.<group>.<device>.<role>.<key>.<bis>.<mac>`

- `<group>`: `^(?!standard$)[a-z0-9-]{1,20}$`. `<role>`: `buero`, `ohne` or `lb:<id>` with `<id>` of 1 to 40
  of `A-Z a-z 0-9 _ -`. `<key>`: the device's public key, the raw uncompressed P-256 point (65 bytes, the first
  one 4), 87 characters of canonical base64url. `<bis>` and `<mac>` as for the access; the label is
  `zertifikat` and the head is the text up to and including `<bis>`.
- Lifetime: 60 days (5 184 000 s) from issue, at enrolment and at every renewal. A client renews when fewer
  than 30 days remain (the same rule as for the access). A renewed certificate has the same key, group and
  role; the old one stays valid until its own end.
- It is judged like the access: head checks first (see "Order of checks, revision 2"), the proof of
  possession with the body.

**Proof of possession.** A request with a certificate carries `Authorization: Bearer <certificate>` and the
possession header with `<t>.<signature>`:

- `<t>`: whole seconds, 1 to 12 digits without a leading zero. It must differ from the relay's clock by at
  most 120 seconds (`possessionSkewSeconds`), either way.
- `<signature>`: base64url, 86 characters, of an ECDSA P-256 / SHA-256 signature in the IEEE P1363 form (64
  bytes, as Web Crypto gives it) by the key in the certificate over the UTF-8 text

```
v1\n<method>\n<path>\n<t>\n<SHA-256 of the body, base64url>\n<certificate>
```

with `\n` a line feed, `<method>` as sent (`POST`), `<path>` the path of the address (for example
`/v1/abholen`), the hash over the exact body bytes (the empty body gives `47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU`)
and the certificate text exactly as in `Authorization`. ECDSA signatures are randomised, so two signatures of
one request are two different values; the relay takes each `(device, signature)` once, until `<t>` plus 121
seconds. The relay does not demand a low-s form.

**Invitation** `e2.<app>.<group>.<inviter>.<role>.<bis>.<random>.<mac>`: the inviting device, the role the new
device gets, `<random>` 16 random bytes (22 characters), the MAC label `einladung` over the head up to the
random part. Valid while `now < bis <= now + 600`, taken once (`verbraucht`), invalid (`einladung-ungueltig`)
once the inviter is blocked. Like `e1` it is single use by its random part until `bis`.

**Founder ticket** `g1.<app>.<group>.<bis>.<random>.<signature>`: signed by the developer's private key with
ECDSA P-256 / SHA-256 (P1363, 86 characters) over `g1.<app>.<group>.<bis>.<random>`; the relay holds only the
public key. Valid while `now < bis <= now + 3660` (one hour plus 60 seconds of clock difference), taken once.

### Enrolment, revision 2

`POST /v1/einschreiben`, no access. The body has **exactly one** way, as before, and optional other members:

| Member             | Meaning                                                                                 |
| ------------------ | --------------------------------------------------------------------------------------- |
| `nachweis`         | a proof (old way, group `1`)                                                            |
| `einladung`        | an invitation `e1` (old way, group `1`) or `e2` (new)                                   |
| `gruender`         | a founder ticket                                                                        |
| `passwort`         | a developer password, then `app` and `mandant` too                                      |
| `geraetSchluessel` | the device's public key (raw, 87 characters, a point on the curve); optional, see below |
| `rolle`            | the role the device claims; only with `nachweis` or `einladung` `e1`; optional          |
| `app`, `mandant`   | only with `passwort`: the app and the group; with any other way they are `unlesbar`     |

- `geraetSchluessel` is optional in group `1` where the old access is still served and **required** (`unlesbar`
  without it) in every other group, where the old procedure is strict and for `gruender` and `passwort`. A
  value that is not exactly 87 characters of base64url or not a point of the curve is `unlesbar`.
- `rolle` must be one of the three forms. With `e2`, `gruender` and `passwort` the role comes from the invitation
  or is `buero`; a member `rolle` there is `unlesbar` (and uses nothing up). With the old ways it is a claim of
  the new device that the relay cannot check (default `ohne`): a device with a claimed role gets no right
  beyond what the role rules give it, so an app that needs a role it can trust enrols by `e2`.
- A **password** is looked up by `(app, mandant)` in the relay's list (the existing relay keeps scrypt hashes
  with an end time, a most number of uses and whether the group may already have devices). Refusals:
  `entwickler-nicht-eingerichtet` (no passwords or no developer key at all), `entwickler-ungueltig` (no
  entry matches), `entwickler-abgelaufen` (ended or used up), `entwickler-belegt` (the group already has devices
  and the entry does not allow it); at most 20 tries per app and hour (`zu-viele-einschreibungen`). A founder
  ticket gives `entwickler-nicht-eingerichtet`, `entwickler-ungueltig` (malformed or wrong signature) or
  `entwickler-abgelaufen`.
- The answer is `201`. Without a key it is the version-1 answer. With a key:

```json
{
  "geraet": "geraet-3f2a...",
  "zugang": "z1.alpha.geraet-3f2a....1802476800.<mac>",
  "zertifikat": "c1.alpha.1.geraet-3f2a....ohne.<key>.1802476800.<mac>",
  "mandant": "1",
  "rolle": "ohne",
  "v": 2,
  "faehigkeiten": ["..."],
  "verfahren": { "angeboten": ["..."], "bevorzugt": "zertifikat", "einschreiben": ["..."] },
  "bis": "2027-01-21"
}
```

`zugang` is there only in group `1` where the old access is still served; a client that has a certificate
ignores it (the certificate rules). `bis` is the end day of the certificate. A client checks that the
certificate is for its app, names the device the answer names, carries exactly the key it sent, that
`mandant` and `rolle` are the ones in it and that `bis` is its end day, and otherwise treats the answer as
unreadable.

- The group of a new device is the one the invitation, ticket or password names; the old ways mean group
  `1`. A group that is strict (below) refuses the old ways with `neue-fassung-noetig`.
- **Intake:** an app may open at most as many groups as its configuration says (`groups`; `0` = no new
  group). A device that would start a further group is refused with `aufnahme-geschlossen`, for every way and
  **before** anything is used up, so a refused ticket or password works again once the limit is raised. A
  group that exists keeps taking devices up to `devicesPerApp` (**per group**, `geraete-voll`); the relay as
  a whole knows at most `devicesTotal` devices (the existing relay's word for that refusal is open point 9).
  What the relay counts is what it has seen since it started.

### Renewal, ping, invitation, revision 2

- **`erneuern`.** Body `{}` with a certificate: `200 {"zertifikat", "bis"}` plus `v`, `faehigkeiten`, `verfahren`;
  the same key, group and role, 60 days from now; any member in the request is `unlesbar`. With an old access the
  body is `{}` as before, or `{"geraetSchluessel", "rolle"?}`: `rolle` only together with the key. Then the
  answer holds the new access and the certificate (`{"zugang", "bis", "zertifikat", "mandant", "rolle", ...}`,
  `bis` the end of the NEW access): the device has made the step to a certificate. A relay of version 1
  refuses the unknown member (`unlesbar`) and keeps the access.
- **`ping`.** Body `{}`. The answer is `{"geraet", "app", "bis"}`; with a certificate it also has `mandant` and
  `rolle` and the three members of the negotiation; with an old access and the announced revision it has the
  three members. `bis` is the end day of the access or certificate used.
- **`einladen`.** Body `{}` or `{"rolle"}`. With a certificate the answer is an `e2` for the group of the
  inviter; the role is the inviter's choice (`rolle`; default: `ohne` for the office, its own for a device of
  the form `lb:<id>`): the office may give any role, a device `lb:<id>` only its own, a device with the role
  `ohne` none (`rolle-nicht-erlaubt`). The order of the checks is: invitations on for the app
  (`einladen-aus`), the form of `rolle`, the permission, the hourly limit. With an old access the answer is an
  `e1` as before and any member is `unlesbar`.

### The device list, `geraete`

`POST /v1/geraete`, body `{}`, certificate only (an old access gets `rolle-nicht-erlaubt`). Answer `200`:

```json
{
  "geraete": [
    {
      "geraet": "geraet-...",
      "rolle": "buero",
      "von": "alt",
      "seit": "2026-11-22T10:00:00.000Z",
      "zuletzt": "2026-11-22T10:05:00.000Z",
      "verfahren": "neu",
      "p": 2
    }
  ],
  "hoechstens": 50
}
```

The devices of the caller's group that its role may see: the office sees all, a device `lb:<id>` the ones with
its own role, any other device only itself. `von` is `alt` (seen with an old access or first met as a request),
`nachweis`, `entwickler` or the id of the inviting device. `seit` and `zuletzt` are `toISOString` times of the
relay's clock; `verfahren` is `neu` (certificate) or `alt` (old access); `p` is the last revision the device
announced, when it did. The list is what the relay has seen since its start. It holds at most twice
`hoechstens` entries (the relay remembers up to twice `devicesPerApp` devices of a group).

### Blocking, `sperren`

`POST /v1/sperren`, body `{"geraet": "geraet-..."}` (exactly this member), certificate only (an old access gets
`rolle-nicht-erlaubt`). Answer `200 {"geraet", "gesperrt": true}`.

- **Who may block:** every device itself; the office every device of its group (also an id the relay does not
  know); a device `lb:<id>` the devices of its own role it knows (itself included). Anything else:
  `rolle-nicht-erlaubt`, and a device `lb:<id>` learns nothing about devices of other roles. The order is: the
  form of the id (`unlesbar`), the permission, the hourly limit, the size of the list.
- **Effect:** the blocked id is refused with `gesperrt` (403) on **every** request, with a certificate or an old
  access, before any body is read; it cannot renew, and an invitation `e2` its device made is invalid. A block
  is for the group of the blocker: the same id in another group is not blocked.
- **Holding:** a block is kept in the relay's RAM for 90 days (`blockHoldDays`: the longest an old access
  lives), at most 500 ids per group (`blocklistPerGroup`; blocking an id again is no new entry; a new one at the
  limit is `sperrliste-voll`, 503) and at most 30 blocks per device and hour (`blocksPerHour`; the existing
  relay answers `zu-viele-einladungen`, open point 18). A restart loses the list. A certificate lives only 60
  days and a blocked device cannot renew, so whoever blocks **repeats the block**: once when blocking, then at
  every start of the app and once a day, for 60 days (90 for a device that held an old access). `blockplan.ts`
  keeps that plan. When exactly a block disappears is the relay's business and is not pinned by the cases.
- The relay's static configuration may also list blocked ids per app (`gesperrt`), which hold for every group.

### Strict groups

A relay can switch the old procedure off for a group (`streng` in the existing relay's configuration; by hand,
never automatically). There a request with an old access, a proof or an `e1` is refused `neue-fassung-noetig`
(426), which is not `gesperrt`: the app must be updated or the device enrolled by invitation. `GET /gesund`
says it with `altAbgeschaltet` (for group `1` of the app of the origin).

### What the client does with it

`RelayClient` (`src/relay/client.ts`) speaks revision 2 when it has a `signer` (its device key). Without a signer
it speaks version 1 and nothing else. With it: `enrol` sends the key (and for the old ways the claimed role; a
`unlesbar` answer makes it ask once more as version 1, for a relay that does not know the key), stores the
certificate, signs every request of a certificate, `renew` and `renewIfDue` renew it, `upgrade` makes the step
from an old access to a certificate, `negotiate` finds the revision, `invite`, `devices` and `block` are the new
calls, and a certificate whose key is not the signer's is refused locally (`key-missing`, class `reenrol`).

**Blocked.** A `gesperrt` answer to a request that carried this device's own current credential makes the
client store a blocked mark in the credential store (it replaces the credentials) and call `onBlocked` once;
the same when the relay confirms that this device blocked itself. It never happens for a network failure, a
timeout, another refusal, a `gesperrt` that answers an enrolment (no credential was sent) or an answer to a
credential that is no longer the stored one. With the mark stored the client refuses to enrol (`blocked-mark`)
until `forget()`; the package wipes nothing (keys, data, screens are the app's, in the hook).

## Order of checks, revision 2

This extends "Order of checks"; 1 to 7 are as written. For every endpoint except `einschreiben` and
`auswertung`:

8. The access. a. No `Bearer`: `zugang-fehlt`. b. A text that begins `c1.`, `e1.`, `e2.`, `z1.` or `g1.` and
   names an app of the relay from another app's origin: `herkunft` (no CORS). c. A certificate: malformed or wrong
   MAC `zugang-ungueltig`, `bis` in the past `zugang-abgelaufen`; the old access as before. d. The app is served
   (`app-unbekannt`), the origin is its own (`herkunft`), the device (certificate, access) is not blocked
   (`gesperrt`; also by the app's static list), an old access in a strict group (`neue-fassung-noetig`). e. The
   request counter of the minute.
9. The body is larger than the limit of the endpoint: `zu-gross`.
10. **With a certificate:** the possession header. Missing `besitz-fehlt`; not `<t>.<86 characters>` or the
    signature does not verify (also for another body, another path, another certificate, another key)
    `besitz-ungueltig`; `<t>` more than 120 s from the clock `besitz-zeit`; the same signature of the device
    seen before `besitz-ungueltig`. A signature is remembered only when all of this passed.
11. The body is not JSON: `unlesbar`.
12. The device is noted as known (with its role, procedure and announced revision).
13. The endpoint's own rules. For `einschreiben`: the members and the form of key and role (`unlesbar`); the app
    the text names is judged against the origin (`herkunft`); the text itself (proof, `e1`, `e2` as before; a
    founder ticket: shape, `entwickler-nicht-eingerichtet`, signature `entwickler-ungueltig`, time
    `entwickler-abgelaufen`, then the key is required `unlesbar`; a password: `entwickler-nicht-eingerichtet`,
    the try counter, `entwickler-ungueltig`, `entwickler-abgelaufen`, `entwickler-belegt`), the blocked inviter
    of an `e2` (`einladung-ungueltig`), `einladen-aus` for the invitation ways; then the app must be served and the
    origin its own, the old way in a strict group `neue-fassung-noetig`, the key where it is required
    (`unlesbar`), the single-use mark (`verbraucht`), `aufnahme-geschlossen`, the relay-wide limit,
    `geraete-voll`; the counter of the hour last, so a refused attempt uses up nothing.

## Error kinds

Each row: the wire word (`art`), the name in this package, the HTTP status, the class a client acts on, and
when the relay answers it. Classes: `fatal` (this request can never succeed as built), `retry` (transient,
bounded retries with backoff), `reenrol` (the access is of no use: enrol again), `refused` (the relay says
no for now; retrying at once is useless, the caller decides). The refusals of one recipient in a drop have
no status of their own (they are inside a 200) and are marked `—`. The table is data in
`src/relay/kinds.ts` (`RELAY_KINDS`); `tests/relay/kinds.test.ts` keeps both in step.

| Wire word                       | Name                       | Status | Class   | When                                                                                               |
| ------------------------------- | -------------------------- | ------ | ------- | -------------------------------------------------------------------------------------------------- |
| `unbekannt`                     | `unknown-endpoint`         | 404    | fatal   | the path is not `/gesund` or `/v1/<endpoint>`                                                      |
| `methode`                       | `wrong-method`             | 405    | fatal   | not POST (GET for `/gesund`)                                                                       |
| `herkunft`                      | `origin-refused`           | 403    | fatal   | no or foreign `Origin`; a token naming another app; also a refused preflight                       |
| `typ`                           | `wrong-content-type`       | 415    | fatal   | not `application/json`                                                                             |
| `zu-gross`                      | `body-too-large`           | 413    | fatal   | the body (announced or read) is over the limit of the endpoint                                     |
| `zu-langsam`                    | `body-too-slow`            | 408    | retry   | the body did not arrive within 14 s                                                                |
| `unlesbar`                      | `unreadable`               | 400    | fatal   | address with `?`, body not JSON, not an object, unknown or missing member, wrong type, bad value   |
| `zugang-fehlt`                  | `access-missing`           | 401    | fatal   | no `Authorization: Bearer ...`                                                                     |
| `zugang-ungueltig`              | `access-invalid`           | 401    | reenrol | the access is malformed or its MAC is wrong                                                        |
| `zugang-abgelaufen`             | `access-expired`           | 401    | reenrol | `bis` is in the past                                                                               |
| `app-unbekannt`                 | `app-unknown`              | 403    | fatal   | the app of the access or proof is not served                                                       |
| `gesperrt`                      | `device-blocked`           | 403    | fatal   | the device id is blocked (the app's list, or by `sperren` in revision 2; any request of it)        |
| `zu-viele-anfragen`             | `rate-limited`             | 429    | retry   | more than 300 requests per device and minute (a server MAY add body-load limits, see "Overload")   |
| `beschaeftigt`                  | `relay-busy`               | 503    | retry   | too many bodies on the way at the moment (server load)                                             |
| `relay-voll`                    | `relay-full`               | 503    | refused | the relay already knows its maximum number of devices (`devicesTotal`); a new enrolment is refused |
| `nachweis-ungueltig`            | `proof-malformed`          | 400    | fatal   | the proof or its payload is not shaped as written                                                  |
| `nachweis-nicht-eingerichtet`   | `proof-not-set-up`         | 403    | fatal   | the app has no proof key                                                                           |
| `nachweis-unterschrift`         | `proof-signature`          | 403    | fatal   | no key of the app verifies the signature                                                           |
| `nachweis-abgelaufen`           | `proof-expired`            | 403    | fatal   | `bis` in the past or more than 360 s ahead                                                         |
| `einladung-ungueltig`           | `invitation-invalid`       | 403    | fatal   | malformed, wrong MAC, or `bis` more than 600 s ahead                                               |
| `einladung-abgelaufen`          | `invitation-expired`       | 403    | fatal   | `bis` in the past                                                                                  |
| `einladen-aus`                  | `invitations-off`          | 403    | fatal   | invitations are off for the app                                                                    |
| `verbraucht`                    | `already-used`             | 409    | fatal   | the proof or invitation was used before                                                            |
| `zu-viele-einschreibungen`      | `enrol-rate-limited`       | 429    | refused | more than 120 enrolments with a proof or 60 with an invitation per app and hour                    |
| `zu-viele-einladungen`          | `invite-rate-limited`      | 429    | refused | more than 10 invitations per device and hour                                                       |
| `klingeln-ungueltig`            | `ring-invalid`             | 400    | fatal   | a ring request that does not fit                                                                   |
| `klingeln-zu-oft`               | `ring-rate-limited`        | 429    | refused | more than 60 rings per device and hour                                                             |
| `push-dienst`                   | `push-service-unreachable` | 502    | retry   | the push service did not answer within 10 s                                                        |
| `neue-fassung-noetig`           | `client-update-needed`     | 426    | fatal   | the old procedure is switched off for the group (revision 2, `streng`): update the app             |
| `geraete-voll`                  | `devices-full`             | 409    | refused | the app already has 50 known devices                                                               |
| `aufnahme-geschlossen`          | `admission-closed`         | 403    | fatal   | the app may not start a (further) group of devices                                                 |
| `intern`                        | `internal`                 | 500    | retry   | an internal error (the text never quotes the request)                                              |
| `besitz-fehlt`                  | `possession-missing`       | 401    | fatal   | revision 2: a certificate without the possession header                                            |
| `besitz-ungueltig`              | `possession-invalid`       | 401    | fatal   | revision 2: the header is malformed, the signature does not verify, or it was taken before         |
| `besitz-zeit`                   | `possession-time`          | 401    | fatal   | revision 2: the signed time is more than 120 s from the relay's clock (check the device's clock)   |
| `rolle-nicht-erlaubt`           | `role-not-allowed`         | 403    | fatal   | revision 2: the role of the device does not allow it (invite, block, list; an old access)          |
| `geraet-unbekannt`              | `device-unknown`           | 404    | fatal   | revision 2: in the existing relay's table, never sent (open point 18)                              |
| `sperrliste-voll`               | `blocklist-full`           | 503    | refused | revision 2: the group's list of blocks already holds 500 ids                                       |
| `entwickler-nicht-eingerichtet` | `developer-not-set-up`     | 403    | fatal   | revision 2: no developer key or no password is configured                                          |
| `entwickler-ungueltig`          | `developer-invalid`        | 403    | fatal   | revision 2: a founder ticket that is malformed or wrongly signed, or no password matches           |
| `entwickler-abgelaufen`         | `developer-expired`        | 403    | fatal   | revision 2: a founder ticket out of time, or a password that has ended or is used up               |
| `entwickler-belegt`             | `developer-group-taken`    | 403    | fatal   | revision 2: the group of the password already has devices                                          |
| `voll`                          | `storage-full`             | —      | retry   | drop, one recipient: the relay's total waiting bytes are full                                      |
| `app-voll`                      | `app-full`                 | —      | retry   | drop, one recipient: the app's waiting bytes are full                                              |
| `absender-voll`                 | `sender-full`              | —      | refused | drop, one recipient: the sender already has too much waiting                                       |
| `empfaenger-voll`               | `recipient-full`           | —      | refused | drop, one recipient: its mailbox holds 100 messages or 2 MiB                                       |

A client that reads a wire word it does not know on a status below 500 (other than 429) treats the answer as
unreadable (`malformed`, fatal): it MUST NOT guess a meaning. On 429 or 5xx it treats it as `unavailable`
(retry later), because only the status tells it what to do. A status that does not fit the word is treated the same way. An answer without a
protocol body (a gateway's 408, 429 or 5xx) is `unavailable` (retry).

## Order of checks

This is the order the existing relay server applies; two simultaneous faults are reported by the earlier
one. The conformance cases pin only the pairs they name.

1. Address contains `?` or `#`: `unlesbar` (400).
2. Path `/gesund`: method must be GET (`methode`); otherwise 200.
3. Path is not `/v1/<endpoint>` of a version-1 endpoint: `unbekannt` (404, no CORS).
4. Method `OPTIONS`: an allowed `Origin` and `Access-Control-Request-Method: POST` give the 204 preflight
   answer (`Access-Control-Allow-Origin`, `Access-Control-Allow-Methods: POST`, `Access-Control-Max-Age: 600`,
   `Access-Control-Allow-Headers` naming at least `authorization` and `content-type`, plus the three fixed
   headers); anything else is `herkunft` (403).
5. Method is not POST: `methode` (405; with CORS when the origin is allowed).
6. No allowed `Origin`: `herkunft` (403, no CORS).
7. Content type is not JSON: `typ` (415).
8. For every endpoint except `einschreiben`: the access.
   a. No `Authorization` header starting with `Bearer `: `zugang-fehlt`.
   b. If the text begins `z1.<app>.` (or `c1.`, `e1.`, `e2.`, `g1.`) and `<app>` is served but the origin is not one of
   its origins: `herkunft` (403, no CORS), before anything else is judged.
   c. Malformed or wrong MAC: `zugang-ungueltig`. `bis` in the past: `zugang-abgelaufen`.
   d. App not served: `app-unbekannt`. Origin not of that app: `herkunft` (no CORS). Device blocked: `gesperrt`.
   e. The device's request count for the minute is taken; over 300: `zu-viele-anfragen`. (A request that
   is refused later still counted.)
9. The body is larger than the endpoint's limit: `zu-gross`.
10. The body is not valid JSON: `unlesbar`.
11. The device is remembered as known (not for `einschreiben`).
12. The endpoint's own rules. For `einschreiben`: the object must have only `nachweis`/`einladung` and
    exactly one of them as a text (`unlesbar`); then the app the text names is judged against the origin
    (`herkunft`); then the text itself (proof: shape, `app-unbekannt`, `nachweis-nicht-eingerichtet`,
    signature, time; invitation: shape and MAC, time, then `einladen-aus`); then the app must be served
    (`app-unbekannt`) and the origin must be its origin (`herkunft`); then the single-use mark
    (`verbraucht`); then `aufnahme-geschlossen`, the relay-wide device limit (open point 9), `geraete-voll`; the hourly enrolment
    counter is taken last, only when everything else passed (`zu-viele-einschreibungen`), so a refused
    attempt uses up nothing.

## Limits

One table; `RELAY_LIMITS` in `src/relay/limits.ts` has exactly these names and values (checked by
`tests/relay/docs.test.ts`). Byte values are exact.

| Name                    | Value      | Meaning                                                        |
| ----------------------- | ---------- | -------------------------------------------------------------- |
| `waitMs`                | 30_000     | a message waits at most this long (RAM only)                   |
| `presenceMs`            | 30_000     | a device counts as present this long after its last collect    |
| `maxContentBytes`       | 65_536     | one message, bytes after decoding                              |
| `maxRecipients`         | 50         | recipients in one drop                                         |
| `maxPresenceAsk`        | 200        | device ids a collect may ask presence for                      |
| `collectBytes`          | 2_097_152  | content bytes one collect hands out at most                    |
| `mailboxMessages`       | 100        | messages waiting for one recipient                             |
| `mailboxBytes`          | 2_097_152  | weighted bytes waiting for one recipient                       |
| `minMessageWeight`      | 1_024      | every message weighs at least this in the byte limits          |
| `senderBytes`           | 4_194_304  | weighted bytes waiting from one sender                         |
| `appBytes`              | 33_554_432 | weighted bytes waiting for one app                             |
| `totalBytes`            | 67_108_864 | weighted bytes waiting in the relay                            |
| `maxBodyBytes`          | 16_384     | request body of every endpoint except `ablegen` and `klingeln` |
| `maxBodyRing`           | 8_192      | request body of `klingeln`                                     |
| `maxBodyDrop`           | 6_291_456  | request body of `ablegen`                                      |
| `requestsPerMinute`     | 300        | requests per device and minute                                 |
| `ringPerHour`           | 60         | rings per device and hour                                      |
| `invitePerHour`         | 10         | invitations per device and hour                                |
| `enrolProofPerHour`     | 120        | enrolments with a proof per app and hour                       |
| `enrolInvitePerHour`    | 60         | enrolments with an invitation per app and hour                 |
| `devicesPerApp`         | 50         | known devices per app (per group in revision 2)                |
| `devicesTotal`          | 300        | known devices in all                                           |
| `accessDays`            | 90         | lifetime of an access                                          |
| `renewBelowDays`        | 30         | a client renews when fewer days remain                         |
| `invitationSeconds`     | 600        | lifetime of an invitation                                      |
| `proofMaxSeconds`       | 300        | longest lifetime of a proof ...                                |
| `proofSkewSeconds`      | 60         | ... plus this much for clocks that differ                      |
| `headTimeoutMs`         | 10_000     | time for the head of a request                                 |
| `bodyTimeoutMs`         | 14_000     | time for the body                                              |
| `requestTimeoutMs`      | 30_000     | time for the whole request                                     |
| `certificateDays`       | 60         | revision 2: lifetime of a certificate                          |
| `possessionSkewSeconds` | 120        | revision 2: largest difference of the signed time              |
| `founderMaxSeconds`     | 3_600      | revision 2: longest lifetime of a founder ticket ...           |
| `founderSkewSeconds`    | 60         | ... plus this much for clocks that differ                      |
| `blocksPerHour`         | 30         | revision 2: blocks per device and hour                         |
| `blocklistPerGroup`     | 500        | revision 2: blocked ids held per group                         |
| `blockHoldDays`         | 90         | revision 2: how long a block is held                           |
| `passwordTriesPerHour`  | 20         | revision 2: developer password tries per app and hour          |
| `ringEndpointMax`       | 900        | longest push endpoint, characters                              |
| `ringVapidMax`          | 1_024      | longest push authorisation header, characters                  |
| `ringContentMax`        | 4_096      | longest encrypted push, bytes                                  |
| `ringTtlMax`            | 86_400     | longest push TTL, seconds                                      |

**Rate counters** are sliding windows over the relay's clock: the events of the last window length count;
an event is refused when the count already equals the limit. They use only times, never content or targets.
A refused event does not count (except the per-minute request counter, which counts every request that got
that far).

**Overload:** a relay MAY answer `beschaeftigt` (503) while it holds too many request bodies; the class is
retry. Which bodies and how many is a server matter; the reference server never answers it. The existing
relay also limits, per device and per app, the number and the bytes of request bodies that are on the way at
the same time and the large-body bytes per minute (two bodies in flight per device, 32 MiB of large bodies per
device and minute are its defaults) and answers `zu-viele-anfragen` (429) when a device exceeds them; these
are load protections, not part of the protocol, and a client treats them like any other 429.

## Presence, waiting, ordering, the `mehr` flag

- **Waiting:** a message dropped at time `t` is delivered to a collect at time `u` when `t > u - waitMs`
  (age below 30 000 ms); otherwise it is gone. Messages are kept in RAM only; a restart loses what waits.
- **Delete on collect:** a message is handed out once and deleted by the same step. A relay MUST NOT hand a
  message to two collects, also under concurrency.
- **Presence:** the collect at time `u` makes the device present; a device is present at time `v` when its
  last collect was at `u > v - presenceMs`. A drop answers `anwesend` from that rule for the recipient; a
  collect answers it for the ids asked.
- **Ordering:** a recipient's messages come out in the order they were accepted. Across senders the order
  is the order of acceptance by the relay; there is no order across recipients and none is promised by the
  network: a message may be late, duplicated by the client's own retry, or missing.
- **`mehr`:** true exactly when messages of the collecting device remain after the answer.
- **Retention of single-use marks:** until their end time; after a restart of the relay they are gone (see
  open points).

## Retry guidance for clients

- Act on the kind's class only. Retry `retry` kinds with exponential backoff (a base of about 1 s, doubling,
  jitter, capped, at most 3 attempts for one call) and never faster than the kind's hint. A relay sends no
  `Retry-After`; the hints in `RELAY_KINDS` are the package's own.
- A request that is not safe to repeat (`ablegen`, `einschreiben`, `einladen`, `klingeln`) is repeated only
  when the relay certainly did not process it: `zu-viele-anfragen`, `beschaeftigt`, `zu-langsam`. After a
  network error or a 5xx the outcome is unknown; the caller decides. `abholen` and `ping` and `erneuern`
  are safe to repeat (note that a collect whose answer is lost has already deleted its messages).
- On `reenrol` the client enrols again once (with a new proof or invitation it obtains) and retries; it does
  not loop.
- **Polling:** the documented cadence is about every second while an exchange runs, otherwise at most
  every 10 seconds, and only while the app is in front. The relay allows 300 requests per device and minute.
  After a failure wait 2, 4, 8 ... at most 60 seconds. `RECOMMENDED_POLL` has the defaults.
- On `mehr` collect again at once, within a bound (the client's `collectAll` stops after a fixed number of
  calls, messages or bytes).

## Message framing (a client convention, not part of the relay protocol)

The relay carries one opaque message of at most 65 536 bytes. To send more, a client cuts the payload into
parts and puts each into one message. `src/relay/framing.ts` does this; the relay never looks at it.

A frame is UTF-8 JSON in exactly this spelling: `{"m":"<app>-frame:1","t":"part","id":"<16 hex>","i":<index>,"n":<count>,"d":"<base64url>"}`
(members in this order, `m` the marker with the app id and the version 1, `id` 16 fresh lower-case hex digits
per payload, `i` from 0, `n` from 1, `d` canonical base64url of 1 to `partBytes` bytes). A reader refuses any
other spelling. The payload itself is opaque and is sealed by the app before cutting.

Reassembly is per sender (the device id the relay names) and `id`: parts may come in any order; an identical
repeat is ignored; a repeat of the same part with other bytes is refused and the first stays; a part whose
`n` differs from the first is refused; a refusal never changes the state. Time is a parameter: an incomplete
payload is dropped `holdMs` after its first part. A fifth incomplete payload from one sender pushes out the
oldest. All limits below are `FRAMING_LIMITS` (checked by `tests/relay/docs.test.ts`).

| Name                    | Value      | Meaning                                                               |
| ----------------------- | ---------- | --------------------------------------------------------------------- |
| `partBytes`             | 40_000     | payload bytes in one frame (base64url and the head stay under 65 536) |
| `maxParts`              | 210        | most parts of one payload                                             |
| `maxPayloadBytes`       | 8_388_608  | most payload bytes of one payload                                     |
| `maxTransfersPerSender` | 4          | incomplete payloads kept per sender                                   |
| `maxSenders`            | 64         | senders with an incomplete payload                                    |
| `maxBufferedBytes`      | 16_777_216 | payload bytes held for all incomplete payloads together               |
| `holdMs`                | 120_000    | an incomplete payload is dropped this long after its first part       |

## Test interface (optional for servers)

A server MAY offer a way for a test to move its clock, reset its counters and stores, lower its limits and
stand in for the push service. How it does so is the server's business (a function in the Node reference
server, an administration script for a port); the conformance runner only calls the four operations of
`ConformanceControl` (`src/relay/conformance.ts`):

| Operation               | Meaning                                                                                                                  |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `reset()`               | empty every mailbox, counter, presence, single-use mark and device list; restore the default limits; move the clock back |
| `advanceTime(ms)`       | move the relay's clock forward by `ms` (for the 30-second rules and token lifetimes)                                     |
| `setLimits(overrides)`  | replace the named values of "Limits" (until `reset`)                                                                     |
| `setPushResult(result)` | what the stand-in push service answers: an HTTP status, or `unreachable`                                                 |

A case lists in `needs` what it needs: `clock` (`advanceTime`), `limits` (`setLimits`), `push-stub`
(`setPushResult`), `reset`. The runner skips (and reports as skipped, never as passed) a case whose
operation is missing. Without any control a server can still be tested with the rest; the cases are
arranged so that cases which enrol come first and the number of devices a run makes stays under the
device limits. When `reset` exists the runner calls it before every case.

## Conformance case format

`tests/relay/conformance/cases.json` (format `relay-conformance/1`) is language neutral JSON:

```
{ "format": "relay-conformance/1",
  "fixture": { "secrets": {...}, "proofKeys": {...}, "apps": {...} },
  "cases": [ { "name", "spec", "needs"?, "steps": [ ... ] } ] }
```

- `fixture` is what the server under test MUST be configured with: HMAC secrets by name (`main` is the
  server's secret, `other` is a wrong one used to forge tokens), proof key pairs by name (`publicRaw` goes
  into the server, the private JWK signs proofs; **throw-away test keys, never real ones**), and the apps
  with their origins, proof key, invitation switch, number of groups and blocked devices.
- A **step** is `{ "name"?, "control"?, "request"?, "expect"?, "capture"?, "repeat"? }`. A request is
  `{ "method", "path", "headers"?, "body"? }`; a body is `{ "json": value }`, `{ "text": string }` or
  `{ "generate": { "prefix", "fill", "count", "suffix" } }` (prefix, then `fill` repeated `count` times,
  then suffix, for oversize bodies).
- **Placeholders** in strings, `{{kind:arg:arg}}`: `device:NAME` (a fresh device id per case, remembered
  by name; `NAME#` is fresh at every use; a literal device id is kept), `access:APP:DEVICE:OFFSET:SECRET[:NAME]`
  (an access signed with the named secret, ending `OFFSET` seconds after the server's now, made once under
  `NAME` when given), `invitation:APP:OFFSET:SECRET:NAME` and `proof:APP:OFFSET:KEY:NAME` (made once per
  case under their name, so the second use is the same token), `var:NAME` (a value captured earlier or a
  device id). The runner mints tokens itself: they need no help from the server.
- `capture` maps a name to a JSON pointer into the answer body; the string found is kept for later steps.
- `repeat: N` runs a step N times.
- **Expectation:** `{ "status", "headers"?, "body"?, "empty"?, "mayCloseConnection"? }`. `headers` maps lower-case names to the
  required value, or `null` for "must be absent". On every answer the runner also checks the three fixed
  headers and, except for 204, the JSON content type. A `body` is exact JSON: an object must have exactly
  the members given (add `"$open": true` to allow others), arrays must have the given length, and a
  value may be a pattern `{ "$type": "string", "pattern": regex, "maxLength"? }`, `{ "$type": "integer",
"min"?, "max"? }`, `{ "$type": "boolean" }`, `{ "$type": "array", "length"?, "maxLength"? }` or
  `{ "$type": "any" }`.
  `mayCloseConnection: true` (used by the one case that sends a body of 6 MB and more) lets a server end the
  connection instead of answering: a server that answers 413 at once and closes while the client is still
  writing megabytes can make the client see a reset (RFC 9112, 9.6), as the existing server does on a fast
  local connection. An answer that does arrive must match; the step counts as passed otherwise.
- A `control` step member is `{ "advanceTime": ms }`, `{ "setLimits": {...} }` or `{ "setPushResult": ... }`.

**Revision 2** has its own file, `tests/relay/conformance/cases-r2.json` (the same format; every case's `spec`
begins `Revision 2`, every case needs `reset`, two need `limits`). Its fixture adds `developerKeys` (key pairs
by name: `main` is the one the server holds the public half of, `other` a wrong one), `developerPasswords` (the
passwords the server must hold: app, group, text, end, most uses, whether the group may have devices), `headers`
(the two header names; for a server that spells them differently the caller changes this member) and, per app,
`strictGroups`. More placeholders: `devicekey:NAME` (the raw public key of a key pair the runner made; the
private half never leaves the runner), `certificate:APP:GROUP:DEVICE:ROLE:KEY:OFFSET:SECRET[:NAME]` and
`invitation2:APP:GROUP:INVITER:ROLE:OFFSET:SECRET:NAME` (in a role `~` stands for `:`),
`founder:APP:GROUP:OFFSET:DEVELOPERKEY:NAME` and `header:possession` or `header:version`. A request may carry
`possession: { key, certificate, offset?, name?, signPath?, signBody? }` (the runner signs the request it sends,
or another one, and adds the header; a `name` makes the value once and reuses it, a replay), and
`version: N` (the version header). An expectation may add `headersInclude` (every token is in a list-valued
header). The runner needs nothing from the server for any of it.

`runConformance(baseUrl, fetch, { cases, control?, now?, only?, timeoutMs? })` returns per case `pass`,
`fail` (with reasons) or `skip`. It is exported from `device-sync/conformance`. In this repository CI runs
it against the in-memory reference server in `tests/relay/reference-server.ts`, which implements exactly
this document and nothing hidden, and shows that the runner fails against twelve deliberately broken
variants of it. Opt-in, outside CI, `npm run test:relay-real` runs the same
cases and the client against the real Node relay server (see "Verification against the existing relay").

## Verification against the existing relay

On 2026-11-22 the conformance cases and the client were run against the REAL Node relay server (its own
source, unmodified, over real HTTP with the real `fetch`), not only against the reference server. What was
run (`npm run test:relay-real`, opt-in, outside `npm test` and CI; `RELAY_REAL_PATH` names the directory of
the server's source; `tests/relay-real/`):

- **The server as deployed** (`node src/server.ts` with its own environment variables, real clocks, real
  limits, no test interface): all 61 cases that need no test interface pass; the 9 that need one are skipped.
- **The same server code with a test interface.** The real server has none, so a small harness
  (`tests/relay-real/harness.ts`) builds it from its own modules with the clock, the limits and the push
  service that its constructor already takes as parameters (a clock that moves, lowered limits, a stand-in
  for the push service) and a control port. HTTP layer, checks, tokens and counters are the real code. All
  70 cases pass.
- **Unusual requests** (94 probes: JSON shapes, header spellings, paths, methods, preflights, every endpoint
  with malformed members) went to the real server and to the reference server; the answers (status,
  kind, CORS and fixed headers) are identical. The only differences are the extra `/gesund` members and the
  value of `Access-Control-Allow-Headers` (open points 6 and 10), and `HEAD`, which has no body.
- **The package's own client** (`RelayClient`) end to end against the real server: enrolment with a proof and
  with an invitation (both once), `ping`, `renew` and `renewIfDue` across a moved clock, an expired access
  with and without the re-enrolment hook, a forged access, `invite` and its hourly limit, `drop` (1, 50
  recipients, 64 KiB each = about 4.4 MB of JSON, 100 messages per mailbox, the sender and app limits),
  `collect`/`collectAll` following `more` and with the bound of one call, presence, a ring through the
  stand-in push service (status passes through, unreachable is 502, the hourly limit), `poll`, the rate limit
  with backoff, and the origin and app mix-ups.
- **Real time:** a message and presence last 30 seconds, a body that does not arrive in 14 seconds gets the
  readable 408 `zu-langsam` with CORS, a head that does not arrive in 10 seconds gets Node's bare 408 without
  CORS.

What this found: the document, the reference server and the real server agree. In the package, one
conformance step was too strict (the step "drop 6 MB" expected a 413 that a client still writing megabytes may
not be able to read: the real server answers at once and closes; see `mayCloseConnection` above), and the
open points 5, 6 and 12 below said "probable" or guessed; they now say what the real server does (open point
12 had guessed wrong). One difference is the
real server's, not the document's: the wire word for "the relay is full" (open point 9).

**Revision 2 against the real server (2026-11-22).** The 55 cases of `cases-r2.json` pass against the real
server through the same harness (HTTP layer, checks, tokens, certificates, possession, counters and block list
are the real code; apps, developer key and passwords from the fixture; header names read from the server's
own source): 55 of 55, none skipped. The reference server passes the same cases and the runner fails eight
broken variants of it. The package's client was run against the real server for revision 2 as well (see
`tests/relay-real/admission.real.test.ts`). The cases were written from the interface document and the source,
and the real server agreed with them without a change of the document; the points where the source and the
interface document were silent are open points 15 to 25.

What is still NOT verified: a PHP port (none exists yet), the real push services (the stand-in answers; the
real server's own call to a push service was not exercised), a real browser (CORS is checked by headers, not
by a browser), the deployed instance behind its CDN, the behaviour under real load and the overload answer
`beschaeftigt` (not provoked), the server's restart behaviour, and, for revision 2, the restart behaviour,
the expiry of a block after 90 days, the possession memory after a restart and the evaluation endpoint.

## Provenance of the rules

Most rules come from the written interface document of the existing relay servers: the transport rules,
the endpoints and their members, the limits table, the error table, the 30-second waiting and presence
rules, the token families and their lifetimes. The server source settled these points the document leaves
open or states loosely: the exact formats of the access (the `bis` unit is seconds, 1 to 12 digits, MAC
over a labelled text, base64url, 43 characters), of the invitation (random part 16 bytes, 22 characters)
and of the proof (payload members, P1363 signature, skew 60 s, single use by nonce), the status of each
proof and invitation error kind, the answer to an empty collect, the order of the head checks and of the
enrolment checks, the weights of messages in the byte limits and the order of the four drop reasons, the
rule that a device is known after any readable request, the meaning of `mehr` and of the collect byte
limit, the exact conditions for a ring request, and the rule that an access of another app from a foreign
origin is refused before its signature. Everything else is listed below.

## Open points of version 1

A port to PHP on ordinary web hosting is planned by one consumer, to be built only if that hosting stays
without Node (decision pending there). Points 2, 3, 4 and 8 matter only for such a second server; points 5
to 7 apply to the existing one. Neither the written document nor the server source settles these; a server owner decides them, and until
then a client and a conformance run MUST NOT rely on any particular answer.

1. **Version negotiation.** Version 1 has no version header and no negotiation. Revision 2 negotiates by the
   members `v`, `faehigkeiten`, `verfahren` and an optional request header (see "Negotiation"); how a still
   later revision shares the address `/v1` with these is undecided (a new path prefix is the likely answer),
   and so is whether a client may rely on the members other than `v`.
2. **A server without shared memory (for example PHP).** The protocol requires counters, single-use marks,
   mailboxes and presence to behave as if there were one process with shared state, and a message to be
   handed to at most one collect. How a stateless web server achieves this (a shared store, locks, one
   worker) and what it may do under concurrent requests (two collects at the same instant) is not decided.
3. **Restart.** After a restart the existing server loses waiting messages (intended), counters, presence,
   the device list and the single-use marks, so a proof (about 5 minutes) or an invitation (10 minutes) can
   be taken a second time within its life. Whether a port must keep the marks is not decided.
4. **Several simultaneous errors.** The order in "Order of checks" is the existing server's. Whether it is
   normative for other servers beyond the pairs the conformance cases pin is not decided.
5. **Unusual JSON and headers.** Duplicate members in a body (the existing server keeps the last: checked
   2026-11-22 with a duplicated `anwesend`), nesting depth, escapes, the length of the `Authorization`
   header and of other headers, a `Content-Length` that does not match, and a missing `Content-Length` are
   not specified. The existing server and the reference server answered 94 such probes alike (see
   "Verification against the existing relay"); that is an observation, not a rule.
6. **The exact `Access-Control-Allow-Headers` value** of the preflight answer (the existing server sends
   `authorization, content-type` and the names of two headers of its later revision; the reference server
   sends the first two), and the status of a preflight for an unknown path (the existing server answers 404
   before it looks at the method). A version-1 client needs only `authorization` and `content-type` to be
   listed.
7. **Retry hints.** The relay sends no `Retry-After`; the delay hints of `RELAY_KINDS` are the package's own
   choice, not the relay's.
8. **Clock rules of the relay.** The existing server never judges a token earlier than its own start plus
   the monotonic time since, so a clock set back revives nothing, and it judges invitations by that clock
   alone. Whether a port must do the same is not decided; the protocol only says tokens are judged by "the
   relay's clock".
9. **Admission, and the wire word of "the relay is full".** `aufnahme-geschlossen` and `geraete-voll` depend
   on how many groups an app may open and on a device count that the existing server derives from what it
   has seen since its start. The protocol states the answers, not how a server decides to be full. When the
   whole relay already knows 300 devices (`devicesTotal`) the existing servers refuse a new enrolment with
   status 503 (class: refused, retry much later) and a wire word that names the first relay implementation
   (not writable in this public repository). **Decided 2026-11-22: the neutral word is `relay-voll`**
   (`relay-full`, 503, refused). It is in the error table and the reference server answers it. The existing
   servers must be changed to send `relay-voll`; until they are, a client reads their old word on a 503 as
   `unavailable` (retry later). Confirmed against the real server
   (`tests/relay-real/client.real.test.ts`): with `devicesTotal` lowered to 1 it answers 503 with its old
   word and the client returns `unavailable` with no token. This is the one place where the real server
   differs from this document; the server owner is to change the word (the real server is not changed here).
10. **Other members.** Whether a relay of a later revision may add members to the answers of `ping`,
    `erneuern` and `einladen` (the existing server does so only for clients that announce a protocol
    version in a header the version-1 client never sends).
11. **A restart-proof device list** and the retention of known devices (the existing server drops a device
    nobody heard of for 90 days): not part of the protocol.
12. **Spelling of the access MAC, and a previous secret.** The text above calls the MAC canonical base64url, but
    the existing relay compares the text of the MAC with the one it computes, so a spelling that differs only in
    the unused bits of the last character is REFUSED (`zugang-ungueltig`; run 2026-11-22). An earlier reading
    of the source that guessed the opposite was wrong. A port should do the same, but no conformance case
    depends on it. The existing relay can also be
    given a previous secret (an environment variable) so that tokens signed with it stay valid until their end:
    a new secret then does not invalidate everything at once.
13. **The admission revision.** The existing relay implements more than version 1: extra members of
    `einschreiben` and `erneuern` (device key, role, group, passwords of founders), extra endpoints (device
    list, blocking, evaluation), the invitation family `e2`, certificates `c1` and tickets `g1`, and the error
    kinds that belong to them. It is written down as revision 2 above and its open points are listed after
    this section (15 to 25). A relay MUST answer a version-1 request exactly as written for version 1 whatever
    it adds; the cases of `cases.json` test only version 1 and pass against a relay of revision 2.
14. **Corrected finding (for the record).** A comparison of this specification with the server found that the
    app named in a token is read before the signature is checked, so a foreign origin is refused with `herkunft`
    before the token is judged; a first automated reading that claimed the opposite was wrong (the pattern
    builds correctly).

## Open points of revision 2

For the owner of the existing relay servers. Like those of version 1 they are NOT decided here; until they are, a
client and a conformance run MUST NOT rely on a particular answer. What this document does say about revision 2 is
what the existing server does (read from its source and its written interface, and checked by 55 conformance
cases against the running server, see "Verification against the existing relay").

15. **Names of the two headers.** The existing servers name the possession header and the version header after
    their own product (`x-<name>-signatur` and `x-<name>-p` in lower case, listed in their preflight answer), and
    that name cannot be written in this public repository. This document proposes the neutral
    `x-relay-signature` and `x-relay-protocol` (`DEFAULT_HEADER_NAMES`) and the client takes the two names as
    configuration (`headers`), so it can talk to either. A server that accepts both, or whichever its owner
    decides, makes a port possible. The conformance fixture names them too (`headers`).
16. **Roles of the old ways are claims.** With a proof or an `e1` the device names its own role and the relay cannot
    check it (the existing relay says so in its interface document). Such a device can invite devices of its own
    role and block devices of that role and can be listed. In group `1` that is the case until `streng` is set. An
    app that cannot accept it enrols by `e2` or `gruender`.
17. **Blocks are RAM only.** A restart of the relay loses the list of blocks, the device list, the single-use marks
    and the possession memory, so a block stands again only when it is reported again (hence the daily report).
    After a restart an `lb:<id>` device cannot block a device of its role until the relay has seen that device
    (`rolle-nicht-erlaubt`), while the office can. Whether a block must survive a restart (a dedicated store, or
    signed blocks that need none) is not decided; neither is exactly when a block ends after 90 days (the existing
    relay removes it at its next tidy-up, so not at a precise instant), which the cases do not pin.
18. **Wire words reused or unused.** The hourly limit of `sperren` answers `zu-viele-einladungen` (429) in the
    existing relay: a block limit with its own word would be clearer. `geraet-unbekannt` (404) is in the existing
    relay's table of refusals and is never sent; a client treats it like `rolle-nicht-erlaubt` for the block plan.
19. **Possession details.** (a) The relay remembers `(device, signature)` only until `t + 121` seconds and loses
    it at a restart, so a recorded request can be replayed within its time window after a restart (the same
    class as open point 3). (b) The relay checks the signature before the time, so a client with a wrong
    clock sees `besitz-ungueltig` only for a bad signature and `besitz-zeit` only when the signature was good. (c) The
    signed path is the request's path as the server sees it; a deployment that rewrites the path in front of
    the relay breaks every signature. (d) No signature form beyond P1363 is accepted; a relay need not demand low-s.
20. **What the answers say about the relay.** Whether `faehigkeiten` and `verfahren` are part of the contract, or
    only `v`, and whether an answer to `ping` of an old access without the header may carry them (the existing
    relay sends them only to a client that announces a revision); the list of abilities and of enrolment ways
    is the existing relay's today (negotiation above).
21. **Groups.** How many devices a group has, and how many groups an app has, derive from what the relay has seen
    since its start, as in open point 9. The group name `standard` is refused (`^(?!standard$)`), the group of
    everything issued before groups existed is `1`; both are decisions of the existing relay.
22. **A ticket beside the certificate.** In group `1` an answer to a keyed enrolment still holds the old access. It
    is meant for devices that migrate; whether a later revision drops it is not decided. A client ignores it.
23. **Password storage.** The existing relay keeps scrypt hashes with an end time, a most number of uses and a flag
    in an environment variable; a port may keep them anywhere. The reference server of this repository keeps the
    text (it is a test server).
24. **The evaluation endpoint** `auswertung`: a ticket `a1...` signed by the developer, no origin needed, counts
    per group (`laufzeitS`, devices, new, old, blocked, `altLetzteVorS`, `streng`, intake figures). It is the
    developer's tool, not a client call, and is not covered by the cases.
25. **Further load protections** of the existing relay (bodies on the way, large bodies per minute) apply to
    certificates as to accesses; a client treats the answers like any other 429 or 503.
