# Channels, replica at rest, rehome, key export (`src/channel/`, `src/log/readReplica.ts`, `src/log/rehome.ts`, `src/core/keyExport.ts`, `src/post/receipts.ts`)

Glue between the log, trust and post layers for content that travels as sealed envelopes through third
devices, and the small pieces an app needs around it. Pure: every function takes its clock, randomness and
keys as parameters and never throws on foreign input; refusals are codes.

**Not security-reviewed by a human.** New; tested with real keys and signatures and the repository's reference
relay, never run in a real browser.

## What a channel is

A **channel** is a data set whose changes travel sealed for named readers, not open to every device. Its
name is also the name of the data set the changes are signed for (`docs/wire-format.md`), so one name is one
replica and one signing context; a set can be exchanged open between devices (`docs/sync.md`, "Data sets") or
as a channel. Which role may write which channel, who the readers are and what the entries mean are the
app's: hooks and parameters, nothing is hard-wired.

### `sealChannel`

```ts
sealChannel({ appId, author: { device, signing }, channel, replica, readers: [dh, ...], known?, onlyOwn?, day, random })
// -> { ok: true, replica /* own changes signed */, envelopes, changes } | { ok: false, reason, replica }
```

Signs the author's own unsigned changes of the channel, takes what the readers lack (`missingFor(replica,
known)`: nothing known, everything), and seals it into as many envelopes as the envelope limit needs: one
JSON body per envelope, `{"v":1,"stand":<vector>,"changes":[...]}` (`readChannelBody` is the strict reader),
cut by size (first guess from the fan, a part that does not fit is halved again). Every envelope is sealed
for all readers at once and signed by the author inside (`docs/wire-format.md`, "Envelope"). `readers` are the
agreement keys of the devices that may read it, as the trust layer verified them (the app chooses by role).

| Code               | Meaning                                                                       |
| ------------------ | ----------------------------------------------------------------------------- |
| `no-reader`        | there is something to send but the list of readers is empty: said, not silent |
| `too-many-readers` | more readers than the envelope's fan holds (`maxFans`, 64)                    |
| `bad-reader`       | a reader that is no agreement key                                             |
| `bad-author`       | the signing key is no ECDSA private key                                       |
| `bad-channel`      | the channel is empty or not a device-like text                                |
| `bad-day`          | the day is not `YYYY-MM-DD`                                                   |
| `bad-input`        | readers is not a list                                                         |
| `wrong-device`     | the replica belongs to another device than the author                         |
| `change-too-large` | one change alone does not fit an envelope                                     |
| `crypto-failure`   | WebCrypto failed                                                              |

Nothing to send (the readers lack nothing) is `{ ok: true, envelopes: [] }`. The caller keeps the returned
`replica` (its own changes are signed now) and remembers the stand the reader reports (`ChannelEntry.stand`
of what it took) so the next call, with `known`, carries only what is new.

**Limit**: a channel is meant for soft deletion. A final deletion erases earlier changes of its record; those
and their deletion are one indivisible group, and when `sealChannel` cuts between two envelopes the earlier
one waits (`pending`) until the other arrives. Both stay in the mailbox and are tried again, so nothing is
lost, but the app should not rely on final deletions in a channel.

### `openChannel`

```ts
openChannel({ appId, own: { device, agreements: [pair, ...] }, envelopes, replicas?, channels?, already?,
              authorKey, keys, mayWrite, judge?, log? })
// -> { replicas, taken: ChannelEntry[], rejected, waiting, skipped, applied }
```

Per envelope, in this order:

1. in `already`: skipped without opening;
2. opened with one of the device's agreement pairs, **tried in order** (an archive identity's keys first, then
   the device's own): not for any of them is `skipped`;
3. the envelope layer checks the author's signature against `authorKey(device)` (the author's signing point
   from the trust layer, `channelKeys(trust).authorKey`); an author the device list does not know yet is
   **waiting** (`unknown-author`: keep the envelope, try again after the device list grew);
4. the channel is wanted (`channels`), else skipped;
5. `mayWrite(author, channel)`: the app's role rule for the envelope's author, else `author-not-allowed`;
6. the body is read strictly, else `bad-body`;
7. every NEW change (those the replica does not hold) is judged by `readChanges`: signature against
   `keys` (`channelKeys(trust).keys`), the hash chain, `mayWrite` again for the author of EACH change, and the
   per-channel hooks of `judge(channel)` (`allowFinalDelete`, `quota`, `special`, `fieldRules`, `mayWrite`).
   One false change drops the whole envelope: `bad-change` with the log's reason in `detail`. A change that
   cannot be checked yet (`pending`) or a gap makes the envelope wait (`pending`, `held`);
8. merged; the envelope is **taken** (`ChannelEntry`: id, day, channel, author, the author's stand, changes
   applied).

One bad envelope never costs the others: they are judged one by one, each against the replica as the earlier
ones left it. A hook that throws counts as "no". An envelope that waits is not in `taken`, so no receipt
covers it and carriers keep it.

| Code                 | Where    | Meaning                                                                           |
| -------------------- | -------- | --------------------------------------------------------------------------------- |
| `unknown-author`     | waiting  | the author is not in the (checkable) device list yet                              |
| `bad-signature`      | rejected | the envelope's signature does not verify (also: a forged claim of who wrote it)   |
| `damaged`            | rejected | the content does not decrypt (changed in transit)                                 |
| `key-mismatch`       | rejected | the key commitment does not match                                                 |
| `bad-point`          | rejected | the envelope's ephemeral key is no point                                          |
| `not-an-envelope`    | rejected | not an envelope of this app                                                       |
| `author-not-allowed` | rejected | the role rule refuses the author for this channel                                 |
| `bad-body`           | rejected | the content is no channel body                                                    |
| `bad-change`         | rejected | a change failed (`detail`: the log's reason, e.g. `bad-signature`, `not-allowed`) |
| `pending`            | waiting  | a change's author cannot be checked yet                                           |
| `held`               | waiting  | a change waits for an earlier one (a gap)                                         |

### Receipts

The device that took envelopes in writes a **receipt record** into data the carriers hold
(`writeReceiptRecord(replica, taken, today, origin)`, `src/post/receipts.ts`): one record per writing device in
a collection (default `receipt`), one field per DAY of the carried window with the sorted ids of that day
(at most 200 with the default log limits), days that left the window cleared (`null`), nothing written when it
stands so. `receiptsOf(replica)` reads them back in the shape `applyReceipts` takes, with `by` = **the device that
signed the write of the field**, never a name in the data. Which devices may acknowledge is the app's
(`mayAcknowledge`): a compromised allowed device can make carriers drop early, nothing worse
(`docs/wire-format.md`, "Mailbox"). The sync driver applies receipts itself (`docs/sync.md`).

### The archive as an identity of its own

An app that keeps a writer's data inside an encrypted store (an archive that signs and seals a channel) gives
that archive a **device identity of its own**: its own id and key pairs, entered into the device list by a
vouching device like any device. The keys come from `generateExportableDeviceKeys()` and are kept as the
text `exportDeviceKeys(keys)` makes; `importDeviceKeys(text, { expect })` makes non-extractable keys again and
checks they belong together and match `expect` (the public keys the device list names). Pass the identity's
agreement pair FIRST in `own.agreements`, so envelopes sealed for the archive open with its key while the
device's own key still opens what was sealed for the device.

**Decision and risk: the export is not encrypted here.** It is one plain JSON text of private keys (`v`, `sig`,
`dh`, each a JWK with `kty`, `crv`, `x`, `y`, `d`); the app wraps it with whatever its encrypted store offers (a
passphrase, a key it already holds), because only the app knows what protects the store around it and a second,
weaker wrapper in this package would be a false comfort. Whoever reads the text owns the identity: it can sign
as the archive and open everything sealed for it. Keys made by `generateDeviceKeys` are never extractable and
`exportDeviceKeys` refuses them (`not-extractable`); a device's own keys must stay that way.

## Replica at rest

`readReplica(raw, { device, limits?, deviceId?, maxChanges?, maxChars? })` reads what `replicaToStored(replica)`
wrote (`JSON.stringify` of it is the stored text; `readReplicaText` takes the text). The stored form is
`{ "v":1, "device", "clock", "vector", "log", "base"?, "approval"? }`: the collections and the conflict notices
are **rebuilt from the log** on reading, so a stored value that disagrees with its log cannot exist.

- exactly these members, no prototype keys, no duplicate keys, version 1, `device` = the reading device
  (`wrong-device`);
- every change read by the log's strict parser (`bad-change`), none twice (`duplicate-change`), at most
  `maxChanges` (1 000 000, `too-many-changes`), the text at most `maxChars` (256 000 000, `too-large`);
- **this device's own numbers run 1 to n without a gap and the stored vector names exactly n**
  (`own-numbers`): the guard against writing a number twice after a half-restored store; other devices'
  numbers must be gapless too (`gap`) and the vector must equal the one the log makes (`vector-mismatch`);
- the clock is a whole number not below any change (`bad-clock`);
- with a snapshot `base` (`docs/snapshot.md`): a vector of whole numbers, naming only devices the vector names, no
  number above the vector, the tail change at each base number present, the numbers above it gapless
  (`bad-base`);
- the approval state by `readApprovalState` (`bad-approval`), none of its changes already in the log
  (`approval-overlap`).

Signatures are **not** checked again: this is local state that was judged before it was stored, and a store an
attacker can write to is not protected here. `storeReplica(write, replica, { maxChars })` writes the text and
answers `{ ok, chars }`, `too-large` (nothing is written; the replica is never halved, it is somebody's data)
or `write-failed` (a full store: the old stored state stays). The app decides what to do with a replica that is
too large for its store (a snapshot and a new device id, `rehome`).

| Code               | Meaning                                                                 |
| ------------------ | ----------------------------------------------------------------------- |
| `not-an-object`    | not a plain object (or not JSON)                                        |
| `unknown-member`   | a member missing or too many, or a duplicate key                        |
| `bad-version`      | not version 1                                                           |
| `wrong-device`     | the store belongs to another device                                     |
| `bad-clock`        | not a whole number, or below a change's clock                           |
| `bad-vector`       | not a vector of whole numbers within the limit                          |
| `bad-base`         | the snapshot base is inconsistent                                       |
| `bad-log`          | the log is no list (or reading failed)                                  |
| `too-many-changes` | over `maxChanges`                                                       |
| `too-large`        | the text is over `maxChars`                                             |
| `bad-change`       | a change the parser refuses                                             |
| `duplicate-change` | a number twice                                                          |
| `gap`              | a number of another device missing                                      |
| `own-numbers`      | this device's own numbers are not 1 to n, or the vector does not name n |
| `vector-mismatch`  | the vector differs from the log's                                       |
| `bad-approval`     | the approval state is unreadable                                        |
| `approval-overlap` | a change is both held for approval and in the log                       |

## Rehome

`rehome(replica, newDevice)`: the same data, writing as `newDevice` from now on (a new device id means new
keys and a new entry in the device list, the app's part). Refused when the new id is no device id
(`bad-device`), when it already wrote (a number in the vector, a change in the log or in the approval state:
`already-wrote`), or when the old id has unsigned changes (`unsigned-changes`: they could never be signed under
the old id again, which would leave a gap; sign them first). The clock goes on, the old id stays an author in
the log. Re-admission after a removal is a new id (`docs/sync.md`, "Re-admission").
