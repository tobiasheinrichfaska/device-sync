# Browser layer: key storage, one listener per device, camera and audio

**New, not yet reviewed, and never run in a real browser.** This document says what `src/browser/` builds,
what it does not protect, and the numbers and codes the tests hold the code to
(`tests/browser/docs.test.ts`). Everything was tested against small fakes written for this repository (an
in-memory IndexedDB, a Web Locks manager, a broadcast channel, a virtual clock, a `MediaDevices` with counted
tracks). No Chrome, Firefox or Safari was involved; where this text says what a browser does, it says what
the specifications say, not what was observed.

The layer touches no global at import time. Every browser API is a parameter: an `IDBFactory`, a lock manager
(`navigator.locks`), a `BroadcastChannel`, a timer pair, a clock, a `MediaDevices`. Compile-time checks in
`tests/browser/fake-idb.test.ts` show that a real `IDBFactory` and `IDBDatabase` fit the structural types used
here. Every function answers `{ ok: true, value }` or `{ ok: false, reason }`; the reason is a code, not a
sentence.

## What is built

| Part                                               | What it does                                                                                                                       |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `openKeyStore(idb, { name })`                      | opens one IndexedDB database with one object store and returns a `KeyStore`                                                        |
| `KeyStore`                                         | `getKeys`/`putKeys` (the device's key pairs), `getText`/`putText` (small named texts), `remove`, `wipe`, `close`, `isOpen`         |
| `readRecord(value, kind)`                          | the strict reader of one stored value (exported so tests and migration code can use it)                                            |
| `relayCredentialStore(store)`                      | the `CredentialStore` the `RelayClient` expects, on top of one text record                                                         |
| `createSingleListener({ name, locks \| channel })` | one tab per app and device is "the listener": Web Locks when there are any, a heartbeat election over a channel when there are not |
| `leaderStart`, `leaderTick`, `leaderMessage`, ...  | the pure state machine behind the channel election (no clock, timer or channel in it)                                              |
| `streamSource`, `cameraSource`, `microphoneSource` | adapters over `MediaDevices` that map errors to codes and always stop every track                                                  |
| `CameraSource`, `AudioSource`, `AudioSink`         | the narrow interfaces the later `transfer` layer will use (no QR or tone coding here)                                              |
| `readCameraFrame`, `readSamples`                   | strict readers of a camera frame (RGBA, whole dimensions) and of audio samples (finite, in [-1, 1])                                |

## Key storage

### Schema

One database (the app chooses its name), schema version 1, one object store `records`, key = the name of the
record. Every value is a plain object with a version member:

- `{ v: 1, kind: 'text', text }`: a text of at most 8 192 characters (device id, relay credential, ...).
- `{ v: 1, kind: 'keys', signing: { privateKey, publicKey }, agreement: { privateKey, publicKey } }`: the
  `DeviceKeys` of the core layer, stored as structured-cloned `CryptoKey` objects.

Names are 1 to 100 characters of `A-Z a-z 0-9 . _ : -`, not starting with a punctuation character. The names
this package's callers use are in `RECORD_NAMES`: `device-keys`, `device-id`, `relay-credential`.

### Reading is strict and never throws

A value that is not exactly a record of this schema is answered with a code, never an exception and never a
guess: not an object or with a foreign prototype, a member too many or too few, a version that is not 1
(`unsupported-version` for a higher one, `corrupt` for anything else), an unknown `kind`, a text over the
limit, a key that is not a P-256 key of the right kind and usage, or a private key that **is extractable**
(`corrupt`: a key that can be exported is not what this layer ever wrote). A record of the other kind is
`wrong-kind`. The record is left as it is: the app decides whether to `remove` it and enrol again.
`putKeys` refuses what `readRecord` would refuse (`bad-value`, `extractable-private-key`) and writes nothing.

An answer for a write comes **after the transaction has committed**, not after the request: a quota error
shows up at commit time and must not be reported as a success.

### Structured-cloned keys, not JWK: what the app gains and loses

`generateDeviceKeys` (core layer) makes private keys with `extractable: false`. This layer stores the
`CryptoKey` objects themselves (IndexedDB structured-clones them) and refuses to store an extractable private
key.

- **Gained:** no script, including an injected one, can read the private key bytes (`exportKey` rejects). The
  key never exists as text, so it cannot end up in a log, a crash report, a backup file or the clipboard.
  The key stays usable for exactly what it was made for: signing (ECDSA) and `deriveBits` (ECDH).
- **Lost:** **no backup and no export.** A device's identity cannot be copied to another device or restored
  from a file. A lost or cleared store means the device is gone (see "A vanished key store" below). This is
  the intended trade for this package: a device is a device; a new device gets a new id and is introduced
  again by the trust layer.

### What IndexedDB protects and what it does not

- **Same origin, any script.** Every script of the page's origin, including an XSS payload, can **use** the
  keys for as long as the page runs: it can sign as the device and derive shared secrets. It cannot export
  them. Non-extractable is a barrier of the API, not a vault: the key material is in the browser's profile on
  disk, and malware with access to the profile or the logged-in session is out of scope.
- **No encryption at rest by this layer.** The relay credential and the device id are texts in the same
  database. The credential is an access token of a few hundred characters; whoever reads the origin's
  storage reads it. Keep it short-lived (the relay renews it) and rely on the device's own disk encryption.
- **Other origins cannot read it**, subdomains included (IndexedDB is per origin).
- **The browser may delete it.** Storage is "best effort" unless the app asks for persistence
  (`navigator.storage.persist()`, not done here): it is cleared under storage pressure, by the user, in
  private windows when they close, and by some browsers after about 7 days without a visit to the site
  (script-writable storage in Safari). The app must treat a store that is gone as normal.
- **Private mode.** Some browsers refuse IndexedDB there or throw a `SecurityError`; the answer is
  `unavailable`. The app should say so instead of running without a store.

### A vanished key store means "device lost"

If `getKeys` answers `{ ok: true, value: undefined }` on a device that had keys before (the app knows it had:
it remembers a device id elsewhere, or the user says so), the keys are gone and **cannot be recovered**.
The app must not generate new keys under the old device id: the old id is known to others with the old keys,
a new pair under the same id is `other-keys` in the trust layer and looks like a forgery. The recovery is
**re-enrolment with a new device id** (new keys, new introduction); the old device is then removed by a
trusted device like any lost device. `wipe` does this on purpose: it clears every record, closes the
connection and deletes the database.

### Failures

| Situation                                             | Answer                                                                                                |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| no `indexedDB`, `open` throws, the open request fails | `unavailable`                                                                                         |
| `open` is blocked by another connection               | `blocked` (a connection that opens later is closed again at once, so it does not block the other tab) |
| the stored database is newer than this code           | `unsupported-version`                                                                                 |
| a database of that name without our store             | `foreign-database` (closed again, nothing written)                                                    |
| the quota is exhausted                                | `quota`; the transaction is aborted and the old value stays                                           |
| another transaction error                             | `aborted` or `failed`                                                                                 |
| another tab upgrades or deletes the database          | this connection is closed at once (`onversionchange`); every later call answers `closed`              |
| a value that cannot be cloned                         | `bad-value`                                                                                           |

`wipe` clears the store first, then closes and deletes the database: the data is gone even if another tab
keeps the delete from finishing (`blocked`); it answers ok when either step succeeded and the failure of the
delete only when both failed.

### The credential store

`relayCredentialStore(store, recordName?)` is the `CredentialStore` of the relay client: `get` returns the
text or `undefined`, `set` and `remove` write. A failure is **thrown** as a `KeyStoreError` with a `code`
(the interface has no result type); `RelayClient` catches it and reports `storage`, and treats an unreadable
credential as "not enrolled". A corrupt record is thrown as `corrupt`, not turned into "nothing there", so
the app can see it.

## One listener per device

Only one tab of an app should poll the relay (and later hold a connection). `createSingleListener` answers
that with `onGain`, `onLose` (each `onLose` follows exactly one `onGain`, also on `release`) and a handle:
`release()` and `isLeader()`.

### With Web Locks (preferred)

One exclusive lock named `device-sync:<name>`; a tab waits in line, holds it while it leads and releases it
on `release`. The browser frees the lock when the tab dies, so a crashed leader is replaced at once, with no
timeout. A tab that releases before it was granted aborts its request, so it never leads. No `steal`, no
`ifAvailable`: waiting in line is what makes the hand-over automatic. A rejecting lock manager is reported
as `locks-failed` through `onError`; one that throws on `request` is a result `locks-failed`. Names may not
start with `-` (reserved by Web Locks): `isName` refuses them.

### Without Web Locks: a heartbeat election over a channel

The state machine in `leader.ts` is pure; `listener.ts` connects it to a channel, a clock and timers.

- **Messages:** `beat` (the leader, every `heartbeatMs`), `claim` (with its time), `bye` (the leader lets go).
  A strict reader refuses anything else, including a member too many.
- **Leases.** A leader's lease runs from the send time of its latest beat to that plus `timeoutMs`. It is a
  leader only while the clock is inside the lease (`isLeader()` reads the clock; a frozen tab turns into a
  non-leader by itself). A leader whose timer comes late, or who receives a message after its lease is over,
  steps down **before** it does anything else.
- **Takeover.** A follower claims after `timeoutMs` without hearing anything. A new tab starts as such a
  follower, so the first tab leads after about `timeoutMs + delayMs`. A claim carries the time; the best
  claim is the smallest `(time, id)`. A candidate that hears a better claim, or a beat, becomes a follower;
  a candidate that has waited `delayMs` without hearing either becomes the leader and beats at once. A
  leader answers a claim with a beat. A follower that hears a claim remembers it (`claimHeard`) and does not
  make a second claim on a later `bye`.
- **Release.** A leader sends `bye`, loses at once and its lease is void. The followers claim at once.

**Assumptions** (the proof sketch is in the head of `leader.ts`; the simulation tests it): all tabs read the
same clock; a message reaches every tab within `delayMs` and messages of one sender arrive in order; a
timer runs at most `lateMs` late; the ids are unique. The configuration is refused (`bad-config`) unless
`timeoutMs > heartbeatMs + delayMs + lateMs` and `timeoutMs > 2 * delayMs + lateMs`. Under them there are
never two leaders at the same instant, as `isLeader()` sees it. The result:

| Event                             | Replacement                                                |
| --------------------------------- | ---------------------------------------------------------- |
| released leader                   | a new leader within `2 * delayMs + lateMs`                 |
| crashed leader (no more messages) | a new leader within `timeoutMs + 2 * delayMs + 2 * lateMs` |
| first tab of an app               | leader after `timeoutMs + delayMs + 2 * lateMs` at most    |

The tests run seeded simulations (joins, crashes, releases, pauses of 0 to 9 s, timers first or messages
first on resume, delays at 0, at the bound and in between): 400 schedules for each of three variants, plus
targeted cases, and show that the simulation sees a violation when the network is slower than the stated
bounds.

**What it does not do.** A tab paused for longer than the bounds (for example a background tab whose timers
the browser throttles to one a minute) can lose the lead and win it back later: safe, but the app sees
`onLose` and `onGain`. Tabs with wrong clocks or a delay beyond `delayMs` break the assumptions; two tabs with
the same id break the order of claims. Prefer Web Locks; this is the fallback. A new tab does not ask "is
there a leader": a paused leader would not answer while its lease still ran.

## Camera and audio

`CameraSource.start(onFrame)` and `AudioSource.start(onSamples)` resolve to `{ ok: true }` or a code;
`stop()` ends everything. Nothing here encodes or decodes a QR code or a tone.

`streamSource` is the one adapter under both: it asks `getUserMedia`, hands the stream to an `attach`
function the caller gives (a video element and a canvas, an audio graph) and always stops every track: on
`stop`, when `attach` throws, and when `stop` came before the permission prompt was answered (the stream
that arrives late is stopped at once and the start answers `stopped`). A camera frame reader or frame handler
that throws surfaces its error but does not end the polling: the next frame is scheduled first. A track that throws on `stop` does
not keep the others running. `mediaErrorCode` reads only the `name` of the error and maps it:
`NotAllowedError`, `SecurityError` to `denied`; `NotFoundError`, `OverconstrainedError` to `not-found`;
`NotReadableError`, `TrackStartError`, `AbortError` to `in-use`; anything else to `failed`. A missing
`mediaDevices` or `getUserMedia` is `unsupported`.

`cameraSource` polls a `FrameReader` supplied by the app at `intervalMs` (default 100, at least 10) and
passes on only frames that `readCameraFrame` accepts: integer `width` and `height` from 1 to 4 096 and
exactly `width * height * 4` bytes in a `Uint8ClampedArray`. `microphoneSource` passes on only buffers that
`readSamples` accepts: a `Float32Array` of 1 to 1 048 576 finite values in [-1, 1] at 8 000 to 192 000 Hz.

Permissions and secure contexts: `getUserMedia` needs HTTPS (or localhost); the prompt and its text belong to
the browser. A page that is not in a secure context gets `undefined` for `mediaDevices`: `unsupported`.

## What is NOT covered

- **Not run in a real browser.** IndexedDB transaction timing, `onversionchange` ordering, structured clone
  of `CryptoKey` in every browser (Node 24 was used for the tests), Web Locks behaviour for frozen or
  back-forward-cached pages, `BroadcastChannel` delivery, `getUserMedia` error names in every browser: all
  per specification, none observed.
- The fake IndexedDB is small (one tick per event, last commit wins between overlapping transactions); it
  checks the cases in `tests/browser/fake-idb.test.ts`, not every rule of the specification.
- No encryption at rest, no key backup, no persistent-storage request, no migration of other schemas
  (a database of another version is refused, not converted).
- The credential is stored as text; the layer does not look inside.

## Limits

| Name                 | Value     |
| -------------------- | --------- |
| `nameMax`            | 100       |
| `textMax`            | 8_192     |
| `schemaVersion`      | 1         |
| `recordVersion`      | 1         |
| `frameSideMax`       | 4_096     |
| `samplesMax`         | 1_048_576 |
| `frameIntervalMinMs` | 10        |

## Leader defaults

| Name          | Value (ms) |
| ------------- | ---------- |
| `heartbeatMs` | 1_000      |
| `timeoutMs`   | 4_000      |
| `delayMs`     | 1_000      |
| `lateMs`      | 1_000      |

The defaults satisfy both conditions on the timing (4 000 is above 3 000 for each).

## Codes

Each code is a `reason` (or a code of `onError`). The test checks that every code listed here exists in the
source and every code the source writes is listed.

| Function                            | Codes                                                                                                                                       |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `openKeyStore`                      | `bad-name` `unavailable` `blocked` `quota` `unsupported-version` `foreign-database` `failed`                                                |
| `KeyStore` (every method)           | `bad-name` `bad-value` `extractable-private-key` `corrupt` `wrong-kind` `unsupported-version` `quota` `aborted` `closed` `blocked` `failed` |
| `createSingleListener`              | `bad-config` `no-mechanism` `locks-failed`                                                                                                  |
| `onError` of the listener           | `locks-failed` `channel-failed` `callback-threw`                                                                                            |
| `leaderConfigProblem`               | `bad-config`                                                                                                                                |
| `start` of a camera or audio source | `denied` `not-found` `in-use` `unsupported` `failed` `stopped` `bad-config`                                                                 |
