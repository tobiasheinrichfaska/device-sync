# Group keys

A shared symmetric key per app data set, handed to the trusted devices and replaced when the group
changes. Pure layer (`src/group/`): no clock, randomness is a parameter (`random(n)`), every browser
or network thing is the app's. It builds only on the core layer (encrypted file: `sealFile` /
`openFile`; HKDF-SHA-256 and AES-256-GCM through WebCrypto as the other layers use them) and takes
its idea of "who is a member" from the trust layer (`Trust`: `trusted`, `removed`, `selfRemoved`).
The package does no new cryptography: a grant is an encrypted file, a message is AES-GCM under an
HKDF-derived key. An independent `node:crypto` derivation (`tests/group/reference.ts`) and the vectors
`tests/vectors/group.json` pin every byte.

**Not security-reviewed by a human.** No review round has covered this layer yet.

## What is built

| Piece                                                           | What it does                                                                                                    |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `rotateGroup`                                                   | Makes the key of the next epoch (highest held + 1; epoch 1 for an empty state) and one grant per trusted device |
| `issueGrants`                                                   | Passes held keys (`current` or `all`) to trusted devices that lack them (a new device, a missed grant)          |
| `acceptGrant`                                                   | Takes a grant: strict read, trusted sender, file opens, payload checks, state rules                             |
| `needsRotation`, `isRotationLead`                               | What the current key still needs after a removal or a join; which device should act (a hint)                    |
| `sealRotationRequest`, `openRotationRequest`                    | Rotation by request: one trusted device asks another that holds the key                                         |
| `encryptGroup`, `decryptGroup`                                  | Opaque bytes under the key of an epoch; epoch, key id, app, data set and context bound in                       |
| `GroupState`, `storeGroupState`, `readGroupState`, `pruneGroup` | The state as a plain storable value with a strict reader; retention                                             |

## Model

- **One key per epoch and author.** An epoch is a number (1 to 4 294 967 295). A key is 32 random bytes
  made by one device (`random(32)`), valid for one data set of one app. A device that holds keys keeps a
  `GroupState`: `dataSet`, `floor` and the keys (sorted by epoch, then author in UTF-8 byte order).
- **Key id** (`kid`): 16 bytes (22 characters) HKDF-expanded from the key, so it identifies the key
  without revealing it and binds app, data set and epoch.
- **Distribution.** A grant is an encrypted file (core `sealFile`) for ONE named device: sender and
  recipient ids and both static agreement keys are in the key derivation and the authenticated data of
  the file, so only the named device opens it and the sender is authenticated by the static keys. The
  recipients and their agreement keys come from `Trust.trusted` (a removed device is not in it). The file
  bytes go over any channel the app has (a session message, an envelope payload, the relay).
- **Rotation on removal.** After the trust layer shows a removal, `needsRotation(state, trust)` lists
  `removedHolders` (removed devices that were given the current key). A device that holds the key calls
  `rotateGroup` with its own `Trust`: the new epoch goes to every trusted device and to nobody else.
  `isRotationLead` names the holder with the lowest id so that the group does not rotate once per device.
- **Rotation by request.** `sealRotationRequest` tells one holder the highest epoch the requester has;
  `openRotationRequest` answers `stale: true` when that is below the holder's epoch (nothing to do).
  Whether to rotate is the app's decision.
- **A device that joined** gets keys from a holder with `issueGrants`: `current` only (it reads data from
  the join on) or `all` (it reads the retained history too). The audience of a forwarded key grows by the
  recipient, so `needsRotation(...).missing` empties.
- **Audience.** Every grant says which devices were given the key (sorted ids; the author, the sender
  and the recipient are in it). It is the author's own claim, used to find honest mistakes (a removal
  that came after a rotation: the removed device is in the audience of the current key; a trusted device
  that was missed). It cannot find a device a compromised author gave the key to in secret.
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

Grant payload (the plaintext of the encrypted file for one device):

```
{"m":"<appId>-gkey:2","set":"<set>","epoch":<n>,"author":"<device>","key":"<32 bytes>","audience":["<device>",...]}
```

Rotation request payload (also inside an encrypted file):

```
{"m":"<appId>-greq:2","set":"<set>","epoch":<n>}
```

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

`<n>:` is the UTF-8 byte length of the field after it (as everywhere in the package). A state read
checks the key ids by deriving them again. Strictness: the audience is strictly increasing in UTF-8
order and holds the author; keys are strictly increasing by (epoch, author); epochs are at least the
floor; there are at most `maxPerEpoch` keys per epoch and `maxKeys` in all.

## Limits

| Limit               | Default (`GROUP_LIMITS`) | Meaning                                                                          |
| ------------------- | ------------------------ | -------------------------------------------------------------------------------- |
| `maxKeys`           | 64                       | keys in one state                                                                |
| `maxPerEpoch`       | 8                        | concurrent keys (different authors) of one epoch                                 |
| `maxAudience`       | 128                      | devices in the audience of one key; a rotation to more is refused                |
| `maxEpochJump`      | 1000                     | a grant more than this above the highest epoch held is refused (state not empty) |
| `maxPlaintextBytes` | 1 048 576                | the largest plaintext of `encryptGroup`                                          |

A grant file is read only up to `3 * maxGrantChars` payload bytes (about 160 kB at the defaults), a
message up to `ceil((maxPlaintextBytes + 16) * 4 / 3)` plus a header, a state up to `maxStateChars`;
longer texts are refused before any WebCrypto call. The context is at most 512 characters.

## Order of checks (grants), bounded work

`acceptGrant`: (1) the file is a file of this app within the size bound (strict reader, no crypto);
(2) it is addressed to this device; (3) the sender is in `trust.trusted` and not in `trust.removed`
(no crypto yet); (4) the file opens (two ECDH, one HKDF, one decrypt: the only expensive step, once per
file); (5) the payload is a grant for this data set; (6) the author is not removed; (7) author, sender
and this device are in the audience; (8) the key id is derived and the state's own rules apply (floor,
epoch jump, one key per author and epoch, caps). A replayed grant of a held key changes nothing
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
| `wrong-recipient`                                                                              | the file is for another device                                     |
| `sender-not-trusted`                                                                           | the sender is not trusted or is removed                            |
| `cannot-open`                                                                                  | the file does not open (damaged, wrong key, wrong app)             |
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
  JavaScript cannot wipe memory. Keep the text where the app keeps its other secrets; nothing here
  encrypts it at rest.
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
  prevent that. Members are trusted not to do this; an app that needs the property adds a commitment of
  its own to the plaintext.
- **No replay protection of messages**, no order, no freshness: the app (its change log) is idempotent.
  A message names its epoch and key id in clear (and the data set); sizes and timing show.
- **Grants carry no signature**, only the static-key authentication of the encrypted file: a device whose
  agreement key leaked can be impersonated towards its peers, and the holder of the recipient's agreement
  key can forge a grant to it (see the file section of `docs/wire-format.md`).
- A trusted device can make the group spend work (rotations, epoch jumps up to `maxEpochJump`, a full
  state): availability, not secrecy; remove it through the trust layer.
- Never run against a real browser or a real relay; tests use real WebCrypto, the real trust layer and an
  independent `node:crypto` derivation.
