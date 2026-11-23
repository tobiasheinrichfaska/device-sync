# Group keys

A shared symmetric key per app data set, handed to the trusted devices and replaced when the group
changes. Pure layer (`src/group/`): no clock, randomness is a parameter (`random(n)`), every browser
or network thing is the app's. It builds only on the core layer (encrypted file: `sealFile` /
`openFile`; HKDF-SHA-256 and AES-256-GCM through WebCrypto as the other layers use them) and takes
its idea of "who is a member" from the trust layer (`Trust`: `trusted`, `removed`, `selfRemoved`).
The package does no new cryptography: a grant is an encrypted file whose payload is signed with the
issuing device's signing key (core `signText`, ECDSA P-256, low-s), a message is AES-GCM under an
HKDF-derived key. An independent `node:crypto` derivation (`tests/group/reference.ts`) and the vectors
`tests/vectors/group.json` pin every byte.

**Not security-reviewed by a human.** No review round has covered this layer yet.

## What is built

| Piece                                                           | What it does                                                                                                    |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `rotateGroup`                                                   | Makes the key of the next epoch (highest held + 1; epoch 1 for an empty state) and one grant per trusted device |
| `issueGrants`                                                   | Passes held keys (`current` or `all`) to trusted devices that lack them (a new device, a missed grant)          |
| `acceptGrant`                                                   | Takes a grant: strict read, trusted sender, file opens, signature verifies, payload checks, state rules         |
| `needsRotation`, `isRotationLead`                               | What the current key still needs after a removal or a join; which device should act (a hint)                    |
| `sealRotationRequest`, `openRotationRequest`                    | Rotation by request: one trusted device asks another that holds the key (signed)                                |
| `encryptGroup`, `decryptGroup`                                  | Opaque bytes under the key of an epoch; epoch, key id, app, data set and context bound in                       |
| `GroupState`, `storeGroupState`, `readGroupState`, `pruneGroup` | The state as a plain storable value with a strict reader; retention                                             |
| `sealGroupState`, `openGroupState`                              | The stored state text encrypted at rest under an app-held AES-256-GCM key (see "The state at rest")             |

## Model

- **One key per epoch and author.** An epoch is a number (1 to 4 294 967 295). A key is 32 random bytes
  made by one device (`random(32)`), valid for one data set of one app. A device that holds keys keeps a
  `GroupState`: `dataSet`, `floor` and the keys (sorted by epoch, then author in UTF-8 byte order).
- **Key id** (`kid`): 16 bytes (22 characters) HKDF-expanded from the key, so it identifies the key
  without revealing it and binds app, data set and epoch.
- **Distribution.** A grant is an encrypted file (core `sealFile`) for ONE named device: sender and
  recipient ids and both static agreement keys are in the key derivation and the authenticated data of
  the file, so only the named device opens it. The payload is **signed by the issuing device's signing
  key** (the sender of the file): the signed text binds app, data set, epoch, key author, issuer,
  recipient, key id (not the raw key) and audience, so a grant cannot be moved to another recipient,
  data set, app or epoch. The recipients, their agreement keys and the issuer's signing key come from
  `Trust.trusted` (`device`, `dh`, `sig`; a removed device is not in it). `GroupOwn` carries the device's
  `signing` pair next to its `agreement` pair. The file bytes go over any channel the app has (a session
  message, an envelope payload, the relay).
- **Rotation on removal.** After the trust layer shows a removal, `needsRotation(state, trust)` lists
  `removedHolders` (removed devices that were given the current key). A device that holds the key calls
  `rotateGroup` with its own `Trust`: the new epoch goes to every trusted device and to nobody else.
  **Who rotates after a removal is the app's choice.** The recommended default: any trusted holder that
  notices a removal may rotate, and concurrent rotations converge (see below), so no election is needed
  and a removal is never stuck waiting for one device. `isRotationLead` (the holder with the lowest id)
  is only a hint that reduces duplicate rotations; an app may wait for the lead a while and then rotate
  anyway, or ignore it.
- **Rotation by request.** `sealRotationRequest` tells one holder (and signed for that holder) the highest epoch the requester has;
  `openRotationRequest` answers `stale: true` when that is below the holder's epoch (nothing to do).
  Whether to rotate is the app's decision.
- **A device that joined** gets keys from a holder with `issueGrants`: `current` only (it reads data from
  the join on) or `all` (it reads the retained history too). The audience of a forwarded key grows by the
  recipient, so `needsRotation(...).missing` empties.
- **Audience.** Every grant says which devices were given the key (sorted ids; the author, the sender
  and the recipient are in it). It is the author's own claim, used to find honest mistakes (a removal
  that came after a rotation: the removed device is in the audience of the current key; a trusted device
  that was missed). It cannot find a device a compromised author gave the key to in secret.
- **No key commitment in `gdata`.** A message carries no commitment to the key. Only holders of the
  group key can produce a message, and a holder can already write any content under the key, so a
  holder who crafts one ciphertext that opens under two keys with different plaintexts gains no power
  it did not have; outsiders cannot produce a message at all. An app that wants more adds a
  commitment of its own to the plaintext.
- **Messages.** `encryptGroup` encrypts under `preferredKey`. Each message has a fresh 16-byte salt and
  its own AES-256-GCM key (`HKDF(group key, salt, info)`) with a constant nonce, so no nonce is ever
  reused and there is no per-key message limit to count. `info` is
  `<appId>-gdata:2|<n>:<set>|<epoch>|<kid>`; the authenticated data is `info|<n>:<context>`. The
  `context` is the app's binding of a message to its object (a record id, a change id); a message moved
  to another object does not open.

## Choosing the key: concurrent rotations

Two devices that rotate at the same time both make epoch e+1 with different keys. The rule is a pure
function of the keys a device holds:

1. `preferredKey` is the key of the **highest epoch**; among the keys of that epoch the one whose
   **author id is lowest in UTF-8 byte order** (not locale order).
2. **No candidate is ever thrown away.** A device decrypts with the key the message names (epoch and key
   id), so data under the losing key stays readable by everyone who holds it. The rule only decides which
   key NEW data uses, and devices that hold the same keys choose the same key whatever the order the
   grants came in (`tests/group/convergence.test.ts`, 200 shuffled orders, and the simulations).
3. A device that was not given the winning key cannot read data under it until a holder passes it on
   (`decryptGroup` answers `unknown-key` with the epoch and key id; `issueGrants` repairs it).
4. A removal that one device has seen and another has not can produce a winning key whose audience still
   contains the removed device. `needsRotation` finds it on any device that learns the removal; the next
   rotation has a higher epoch and so wins over any id.

**The id tie-break, thought through.** The trust layer takes id tie-breaks out of removals because a
joining device chooses its own id, so an attacker can pick a low one. Here the tie-break only picks which
of several keys that were issued by trusted devices new data uses; a trusted device can already read
every current key and can already rotate. What a low id can buy: its key wins the epoch, and if the author
gave it to fewer devices (or to a removed one), the others cannot read (or the removed one can read) data
written under it. The defence is not the order but the repair: `needsRotation` shows `missing` and
`removedHolders` from the audience, a higher epoch always beats a lower id, and a device that keeps
doing this is removed through the trust layer. An attacker who keeps a rotation war going costs the group
work and availability, never the secrecy of data it could not read anyway. A trusted device can also
raise the epoch (up to `maxEpochJump` above what a device holds); that too is availability only.

## Retention of old epochs

Old keys are kept: they decrypt old data. `pruneGroup(state, keepFrom)` drops keys below an epoch,
raises the `floor` and never drops the highest epoch. A grant below the floor is refused
(`below-floor`), so a replayed old grant cannot bring a pruned key back. The package does not prune by
itself: only the app knows when everything it keeps was re-encrypted under a newer epoch (the usual
moment) or may be lost. `maxKeys` (64) bounds the state; a full state refuses new keys
(`too-many-keys`) until the app prunes.

## Wire formats

All texts are compact JSON, members in this order, strings as `JSON.stringify` writes them. A reader
accepts exactly this spelling (it re-encodes what it read and compares), canonical unpadded base64url,
and refuses everything else, never throws.

Grant payload (the plaintext of the encrypted file for one device; format version 3, signed):

```
{"m":"<appId>-gkey:3","set":"<set>","epoch":<n>,"author":"<device>","from":"<device>","to":"<device>","kid":"<16 bytes>","key":"<32 bytes>","audience":["<device>",...],"sig":"<64 bytes>"}
```

The signature is the issuer's (`from`) over this text, the same members without `key` and `sig`:

```
{"m":"<appId>-gkeysig:3","set":"<set>","epoch":<n>,"author":"<device>","from":"<device>","to":"<device>","kid":"<16 bytes>","audience":["<device>",...]}
```

Rotation request payload (also inside an encrypted file; signed):

```
{"m":"<appId>-greq:3","set":"<set>","epoch":<n>,"from":"<device>","to":"<device>","sig":"<64 bytes>"}
{"m":"<appId>-greqsig:3","set":"<set>","epoch":<n>,"from":"<device>","to":"<device>"}
```

The second text is what `from` signs. A signature is ECDSA P-256 / SHA-256 over the UTF-8 bytes of the
text, 64 bytes (P1363), low-s only, canonical unpadded base64url (core `signText` / `verifyText`). The
markers `gkey`, `greq`, `gkeysig` and `greqsig` carry version 3 (a version 2 grant, which had no
signature, is refused as `bad-payload`); `gdata` and `gstate` stay at version 2. `from` must be the
sender named in the file header and `to` the recipient, `from` and `to` differ, `kid` is the key id of
`key`.

Encrypted message:

```
{"m":"<appId>-gdata:2","set":"<set>","epoch":<n>,"kid":"<16 bytes>","salt":"<16 bytes>","ct":"<ciphertext || 16-byte tag>"}
```

Stored state (SECRET: it holds the keys):

```
{"m":"<appId>-gstate:2","set":"<set>","floor":<n>,"keys":[{"epoch":<n>,"author":"<device>","key":"<32 bytes>","audience":["<device>",...]},...]}
```

Derivations (`H` = HKDF-SHA-256, `S` = SHA-256):

```
<appId>-group:2|<n>:<set>                       hashed with S: the HKDF salt of the key id
kid  = H(ikm = key, salt = S(<appId>-group:2|<n>:<set>), info = "<appId>-group:2|kid|<epoch>", 16 bytes)
info = <appId>-gdata:2|<n>:<set>|<epoch>|<kid>
mkey = H(ikm = key, salt = <message salt>, info = info, 32 bytes)       AES-256-GCM key of one message
AAD  = <info>|<n>:<context>                                              nonce = 12 zero bytes
```

The text a signature covers contains the key id and not the key: the id is derived from the key, so the
signature covers the key and an opened grant is checked by deriving the id again.

`<n>:` is the UTF-8 byte length of the field after it (as everywhere in the package). A state read
checks the key ids by deriving them again. Strictness: the audience is strictly increasing in UTF-8
order and holds the author; keys are strictly increasing by (epoch, author); epochs are at least the
floor; there are at most `maxPerEpoch` keys per epoch and `maxKeys` in all.

## The state at rest

`storeGroupState` gives a text that holds the raw keys. `sealGroupState(state, wrapKey, { appId, random })`
turns it into a text that is safe to put in storage, and `openGroupState(text, wrapKey, { appId, dataSet? })`
reads it back. The wrap key is an AES-256-GCM `CryptoKey` that the app keeps non-extractable (the browser
layer generates it and keeps it in the key store, see `docs/browser.md`); the group layer only checks that
it is such a key (`bad-key` otherwise, an extractable key included).

```
{"m":"<appId>-grest:1","set":"<set>","iv":"<12 bytes>","ct":"<state text as UTF-8, encrypted, with the 16-byte tag>"}
```

- Compact JSON, members in this order, canonical unpadded base64url; the reader re-encodes what it read and
  compares, so there is one spelling. The version is the number after `grest:`: a higher one is
  `unsupported-version`, which is not a format to guess at.
- The IV is 12 bytes from the injected `random(12)`, fresh for every sealing (never derived, never counted).
- Authenticated data: `<appId>-grest:1|<byte length>:<set>`, so the app, the version and the data set cannot be
  changed without the text failing to open; the data set in the clear is the one that was authenticated.
- The plaintext is exactly the text of `storeGroupState`; after the one decryption it is read by the strict
  state reader (`readGroupState`, which derives and checks every key id), and its data set must be the one in
  the header (`bad-state` otherwise). Only a state that the strict reader accepts is sealed.
- **Message budget.** A random 96-bit IV under one key is safe for far fewer than 2^32 sealings (NIST SP
  800-38D). An app seals once per change of the state, which never comes near that; an app that seals in a
  loop re-seals under a new wrap key long before. Nothing here counts sealings.
- **Bounded work.** Before the one `decrypt` (no other WebCrypto call precedes it): the text length
  (`maxSealedStateChars`, about 4 times `maxStateChars`: a state is at most 3 bytes per character), the
  marker and version, the exact members and spelling, the length of IV and ciphertext, the data set when the
  caller names one. A refusal costs no WebCrypto call (`tests/group/rest.test.ts` counts them). After the
  decryption: `readGroupState` (key id derivations, one per key, at most `maxKeys`).
- Codes: `bad-input`, `bad-key`, `bad-random` (not exactly 12 bytes, or it threw), `too-large`,
  `crypto-failure` when sealing. When opening: `bad-input`, `bad-key`, `not-sealed` (not this format or not
  this app), `truncated` (cut off, or less than a tag of ciphertext), `unsupported-version`,
  `wrong-data-set`, `cannot-open` (a wrong key and a changed text give the same answer: GCM cannot tell
  them apart), `bad-state`.
- Independent derivation: `tests/group/rest-reference.ts` (`node:crypto`, written from this section) agrees
  byte for byte; a sweep changes every character of a sealed text and every bit of IV and ciphertext.

**What it protects.** A copy of the IndexedDB (or another storage) without access to the browser profile's
key store: the text is ciphertext, and the key behind it is a non-extractable `CryptoKey` that never leaves
the browser's key handling. Also the group keys leaking by accident into a backup, a log or a sync of the
storage only.

**What it does NOT protect.**

- **A script running in the origin.** It can ask the browser to decrypt with the stored wrap key exactly as the
  app does, and read the state. Non-extractable stops copying the key, not using it.
- **Malware with the logged-in profile or session**, or a person using the unlocked browser: they use the key
  as the app does.
- **A rollback.** An older sealed text of the same data set is a valid sealed text and opens fine: whoever can
  write the storage can put an earlier state back (an old epoch's keys, a lost key, an undone pruning). The
  floor in a rolled-back state is lower again; the app learns of newer keys only when grants come again. The
  seal is not a version counter and this layer has none.
- **Metadata**: the data set, the number of keys (through the length) and the time of writing show; there is
  no padding.
- **Deletion of the wrap key without the state** (a cleared key store with the sealed text left) makes the
  state unreadable for good (`cannot-open`): the app asks the other devices for the keys again, like for a
  lost key store.
- Memory: the opened state is a plain value; JavaScript cannot wipe it.

## Limits

| Limit               | Default (`GROUP_LIMITS`) | Meaning                                                                          |
| ------------------- | ------------------------ | -------------------------------------------------------------------------------- |
| `maxKeys`           | 64                       | keys in one state                                                                |
| `maxPerEpoch`       | 8                        | concurrent keys (different authors) of one epoch                                 |
| `maxAudience`       | 128                      | devices in the audience of one key; a rotation to more is refused                |
| `maxEpochJump`      | 1000                     | a grant more than this above the highest epoch held is refused (state not empty) |
| `maxPlaintextBytes` | 1 048 576                | the largest plaintext of `encryptGroup`                                          |

A grant file is read only up to `3 * maxGrantChars` payload bytes (about 160 kB at the defaults; a
request payload at most 1900 characters), a
message up to `ceil((maxPlaintextBytes + 16) * 4 / 3)` plus a header, a state up to `maxStateChars`;
longer texts are refused before any WebCrypto call. The context is at most 512 characters.

## Order of checks (grants), bounded work

`acceptGrant`: (1) the file is a file of this app within the size bound (strict reader, no crypto);
(2) it is addressed to this device; (3) the sender is in `trust.trusted` and not in `trust.removed`
(no crypto yet); (4) the file opens (two ECDH, one HKDF, one decrypt: the only expensive step, once per
file); (5) the payload is read strictly as a grant whose `from` is the sender and whose `to` is this
device (a grant meant for another device is `wrong-recipient`, one that names another issuer is
`bad-payload`); (6) the key id is derived from the key (one HKDF) and must equal `kid`; (7) the sender's
signature is verified with the signing key `Trust.trusted` lists for it (one key import, one
verification): nothing is decided or stored before this passes (`bad-signature`); (8) the payload is for
this data set; (9) the author is not removed; (10) author, sender and this device are in the audience;
(11) the state's own rules apply (floor, epoch jump, one key per author and epoch, caps). A replayed grant of a held key changes nothing
(`change: 'same'`). `tests/group/bounded.test.ts` counts WebCrypto calls.

## Refusal codes

| Code                                                                                           | Meaning                                                            |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `bad-input`, `bad-own`, `bad-random`, `bad-recipient`                                          | a parameter is unusable (random must return exactly `n` bytes)     |
| `self-removed`                                                                                 | this device is removed: it makes no rotation and passes nothing on |
| `epoch-exhausted`                                                                              | the next epoch would exceed 4 294 967 295                          |
| `too-many-devices`                                                                             | the audience would exceed `maxAudience`                            |
| `no-key`                                                                                       | nothing to pass on or encrypt with                                 |
| `not-a-grant`, `not-a-request`                                                                 | the bytes are not a file of this app within the bound              |
| `wrong-recipient`                                                                              | the file (or the signed payload) is for another device             |
| `sender-not-trusted`                                                                           | the sender is not trusted or is removed                            |
| `cannot-open`                                                                                  | the file does not open (damaged, wrong key, wrong app)             |
| `bad-signature`                                                                                | the issuer's signature does not verify (wrong, forged or no key)   |
| `bad-payload`                                                                                  | the opened payload is not exactly a grant (or request)             |
| `wrong-data-set`                                                                               | it is for another data set                                         |
| `author-removed`                                                                               | the key's author is removed                                        |
| `not-in-audience`                                                                              | author, sender or this device is missing from the audience         |
| `below-floor`, `epoch-jump`, `author-conflict`, `epoch-full`, `too-many-keys`, `audience-full` | the state refuses the key (see Limits and Retention)               |

`decryptGroup` answers `not-group-data`, `wrong-data-set`, `unknown-key` (with `epoch` and `kid`),
`cannot-open` and `bad-input`; `encryptGroup` answers `no-key`, `bad-input`, `too-large`, `bad-random`
and `crypto-failure`.

## What is NOT protected (honest limits)

- **A removed device keeps every key it already held.** Rotation protects only data written after it:
  data under old epochs stays readable by the removed device, and so does anything it copied. Removal
  without rotation protects nothing.
- **A compromised trusted device leaks the current key** (and the retained ones it holds) to the
  attacker, and can hand any key to anyone. Removal and rotation end this only for later data. There is
  no post-compromise security beyond rotation, and the audience cannot reveal a secret hand-over.
- **No forward secrecy.** A key that leaks opens everything under it, past and future of that epoch. The
  state holds raw keys: they are not non-extractable like the device keys, the stored text is secret, and
  JavaScript cannot wipe memory. The stored text can be sealed at rest (`sealGroupState`, see "The state at
  rest" for what that does and does not protect); the plain text of `storeGroupState` is secret.
- **Rotation has a window.** Until a device has seen the removal and rotated, a removed device still gets
  everything the others write under the old key; devices that see the removal at different times may
  rotate concurrently (they converge, see above); a removed device that still acts on an old view can
  hand out a key of its own to devices that have not seen the removal (they refuse it once they have;
  `needsRotation` finds what they accepted). Grants are sent once: a lost grant is found when a message
  is `unknown-key`, not by the audience.
- **All trusted devices are equally trusted for keys.** A forwarded key carries its original author as the
  forwarder reported it; the sender is authenticated, the claimed author is not. The audience is a claim.
- **The state has no integrity check of its own** (it is the app's storage): a changed key byte gives a
  different valid state whose messages simply do not open.
- **AES-GCM is not key-committing.** A device that holds two keys could craft one ciphertext that opens
  under both with different plaintexts; the epoch and key id in the text and the key derivation do not
  prevent that. This is accepted on purpose (no key commitment, see Model): only holders of the group key
  can produce a message and a holder can already write anything, so a two-key collision gives it no extra
  power. An app that needs the property adds a commitment of its own to the plaintext.
- **No replay protection of messages**, no order, no freshness: the app (its change log) is idempotent.
  A message names its epoch and key id in clear (and the data set); sizes and timing show.
- **What signing gives, and what it does not.** A grant and a rotation request are signed by the issuing
  device, so a leaked agreement key alone cannot forge a grant "from" that device (the forger would need
  its signing key), and a grant cannot be replayed to another recipient, data set, app or epoch. It gives
  **no forward secrecy** (a leaked group key still opens everything under it; the signature says who
  issued a grant, it does not hide the key), and **a compromised signer can still issue grants**: whoever
  holds a trusted device's signing key can hand any key to anyone as that device until the device is
  removed. A signature proves the issuer, not that its claims about the key are true (the author and the
  audience are the issuer's claims). There is no freshness: a genuine grant or request can be delivered
  again to the same recipient (a replayed grant of a held key changes nothing; a repeated request only
  asks again). The signature is checked against the signing key the trust layer lists; a wrong entry
  there is the trust layer's failure.
- A trusted device can make the group spend work (rotations, epoch jumps up to `maxEpochJump`, a full
  state): availability, not secrecy; remove it through the trust layer.
- Never run against a real browser or a real relay; tests use real WebCrypto, the real trust layer and an
  independent `node:crypto` derivation.
