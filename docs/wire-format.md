# Wire format (core layer, format version 2)

Only what the `core` layer puts on the wire or into hashes. Ported from two earlier implementations;
the vectors in `tests/core/` pin the behaviour.

## Encoding

- Binary values travel as **unpadded base64url** (RFC 4648 section 5): alphabet `A-Z a-z 0-9 - _`, no `=`.
- Decoding is **strict**: any other character (including `+`, `/`, `=`, spaces, newlines) is an error;
  a length with one left-over character is an error; the empty text decodes to no bytes.
- `sha256Text(text)` is SHA-256 over the UTF-8 bytes of the text.

## Canonical form

`canonical(value)` is the text that is hashed or signed instead of raw JSON:

- arrays: `[` members joined by `,` `]`, order kept; an `undefined` member (or a hole) throws;
- objects: members whose value is `undefined` are dropped, the remaining keys are sorted by UTF-16 code
  unit (default JavaScript sort, so `"10"` sorts before `"9"`), each written as
  `JSON.stringify(key):canonical(value)`, joined by `,` inside `{` `}`;
- null, booleans, finite numbers and strings are `JSON.stringify(value)`; a top-level `undefined` is
  `null`.

Only plain JSON is canonical. Anything else throws a `TypeError` instead of being read as something
other than what a receiver gets from the JSON text: `Date`, `Map`, `Set`, class instances (anything
whose prototype is not `Object.prototype` or null), objects with a `toJSON`, functions, symbols,
`bigint`, `NaN`, `Infinity`, `undefined` in an array, cycles, and nesting deeper than 512 levels.

`checkValue(value)` = base64url(SHA-256(UTF-8(canonical(value)))), always 43 characters.

## Markers

`marker(appId, kind, version)` = `${appId}-${kind}:${version}`. `appId` must match
`^[a-z][a-z0-9]{1,15}$`. Every marker enters hashes, key derivation and AAD, so a different `appId` never
produces the same bytes. All markers of this format use version `2` (`FORMAT_VERSION`).

## Device keys and points

- Per device: a signing pair (ECDSA P-256) and an agreement pair (ECDH P-256). Private halves are
  generated non-extractable.
- A public key travels as the **uncompressed point**: 65 bytes (first byte `0x04`, then X and Y, 32 bytes
  each), base64url, exactly **87 characters**. `isPoint` checks only format; `importPublicKey` also
  rejects points that are not on the curve.

## Check code

For comparing a device aloud: SHA-256 over the UTF-8 text

```
${marker(appId, 'device', 2)}|${n}:${deviceId}|${n}:${sig}|${n}:${dh}
```

where each `${n}` is the decimal **UTF-8 byte length** of the field after it, so no field can be shifted
into another (without the prefixes, `('a', 'b|c')` and `('a|b', 'c')` gave the same code). Both keys must
be points (`isPoint`) and the device id non-empty without a control character (U+0000 to U+001F, U+007F)
or `|`; anything else is a programming error and throws a `TypeError`. Take the first ten bytes of the
hash as five big-endian 16-bit numbers; each modulo 10000, zero-padded to four digits, joined by single
spaces: `dddd dddd dddd dddd dddd`. The five groups carry about **66 bits** (5 x log2 10000 = 66.4):
enough to catch a mistake or a casual swap, not a lasting protection against an attacker who can grind
keys; the trust layer decides how much more a meeting needs. The optional parameter `groups` (default
5, 5 to 10, else `TypeError`) takes `2 x groups` bytes: each group adds about **13.3 bits** (10 groups:
about 133 bits); the first five groups are the same for every length. Use at least **8 groups** (about
106 bits) where the code protects against a modified invitation link.

# Wire format: log layer, part 1

Ported from two earlier implementations; new format version `:2` with English field names. The
tests in `tests/log/` pin the behaviour. Signatures are described in the section "Signatures",
the messages of the exchange in "Exchange" below.

## Change

One entry of a device's log. Only its author creates it; everybody forwards it.

| Field        | Type                          | Meaning                                                                                                           |
| ------------ | ----------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `device`     | string                        | Author's device id (random, never derived from a person)                                                          |
| `seq`        | integer, 1, 2, 3 ...          | Per-device number, **gapless**                                                                                    |
| `clock`      | integer                       | Lamport clock at creation (own clock + 1, raised to the highest clock seen)                                       |
| `collection` | string                        | Name of the set of records                                                                                        |
| `id`         | string                        | Record id                                                                                                         |
| `kind`       | `set` / `delete` / `redacted` | see below                                                                                                         |
| `fields`     | object (optional)             | Only for `set`: field name to value. Values are any JSON (lists and objects count as one value)                   |
| `knew`       | object                        | Author's version vector, shortened (see below). **Required** for `set` and `delete`; a `redacted` change has none |
| `time`, `by` | number, string (optional)     | Author's own time (ms since 1970) and a label; history only, never used to order writes                           |
| `check`      | string (optional)             | `changeCheckValue(change)` = `checkValue({fields, knew, time, by})`; set by the signer, kept on erase             |
| `sig`        | string (optional)             | Author's signature over the head and `check`; kept on erase                                                       |

`kind`: `set` writes the named fields (fields not named keep their value); `delete` is the final
deletion of the record; `redacted` is a former `set` whose content was erased because the record was
deleted. A redacted change keeps `device`, `seq`, `clock`, `collection`, `id`, `check` and `sig`
(`check` is computed at that moment if the author had none) and drops `fields`, `knew`, `time`, `by`,
so numbering stays gapless and the head stays checkable. **A redacted change has exactly these
members and no other**: `time`, `by` and `knew` are not covered by the signature (it covers the head
and `check`), so the parser refuses them on a redacted change and the judge says `unknown-member`.
A `set` that arrives for an already deleted record is stored redacted from the start.

**Names.** `collection`, `id`, field names, keys inside a value and the device ids are used as keys
of objects, so `__proto__`, `constructor` and `prototype` are refused everywhere (parser and local
writing). Every other string is an ordinary name, `toString` and `valueOf` included: the log layer
keeps collections, records, fields and version vectors in objects without a prototype. Names, and the
label `by`, are NFC-normalised and contain no control character (`\p{Cc}`) and no format character
(`\p{Cf}`: bidirectional overrides, zero-width characters, byte order mark); text that is not in NFC
form is refused, not converted.

**Local writing obeys the same rules.** `write`, `softDelete`, `restore`, `undo` and `remove` check
the names, the values (plain JSON only: no `Date`, `Map`, `Set`, class instance, function, symbol,
`bigint`, `NaN`/`Infinity`, `undefined`, cycle), the limits of the table below (`limits` option as
for the parser), the origin (`time`, `by`) and the own device id with the strict parser's checks, and
answer `{ ok: false, reason }` instead of creating a change a conforming receiver would refuse
(which would block everything later from this device, the numbering being gapless). Reasons:
`invalid-name`, `invalid-value`, `too-large`, `too-many-fields`, `invalid-origin`, `invalid-device`,
`too-many-devices` (more than `maxDevices` unresolved concurrent writes to the fields: one `knew` could not
name them all), `clock-overflow`, plus
`no-fields`, `no-record`, `record-deleted`, `unknown-change`, `unchanged`. The stored value is a copy.

## Version vector (stand)

`{ [device]: highest seq received without a gap }`. A change is applied only when its `seq` is exactly
the known `seq` + 1 for its device, its `clock` is at most own clock + `MAX_CLOCK_JUMP`
(10 000 000), and the **causal hold** is met: for every device `d` named in its `knew` the replica
already holds at least `knew[d]` changes of `d`. Otherwise it is **held** (returned in `held`, not
stored) until it can be applied. A single `merge` call repeats until nothing more becomes applicable,
so changes that depend on each other (a clock raised by another device's change, a `knew` naming a
change delivered later in the same call) are taken together whatever their order. A change that
names more than its author could have known (an invented, huge `knew`) or that has no `knew` is held
for good and blocks only its own author's later changes (the numbering is gapless); it cannot
suppress a conflict notice or overwrite silently. Duplicates and already known changes are ignored;
merging is idempotent and independent of order.

## Which value wins

Per field the write with the higher `clock` wins; on equal clocks the **higher device id**
(string comparison) wins. The order is total, so all devices decide alike.

## Shortened `knew`

A change's `knew` contains, from its author's stand at write time, only the **heads** of the fields
this change writes: per such field, the devices whose last write to it (in the author's log of that
record) is not dominated by another write the author holds, i.e. no write says in its `knew` that it
knew that write. Everything else is covered transitively: a receiver that holds a head also holds
everything the head's author knew (the causal hold), and notices compare only heads. A deletion
names the heads over all fields of the record. So the number of devices named is the number of
**unresolved concurrent** writes, not the number of devices that ever wrote the field: a field written
by 80 devices one after another, each synced first, stays writable (`too-many-devices` only happens with
more than `maxDevices` unresolved heads). A record the author never held gives `{}`. Devices with
number 0 are left out; keys are sorted. Every decision of the model asks `knew` only about such
devices, so it decides exactly as with the whole stand (`tests/log/basis.test.ts`, 400 random runs).
`concurrent(a, b)`: both carry `knew`, come from different devices, and neither knew the other
(`a.knew[b.device] < b.seq` and `b.knew[a.device] < a.seq`). `knew` is required on `set` and `delete`
(the parser and `merge` refuse a change without it), and the causal hold above means a `knew` can only
name changes the receiver holds.

## Conflict notice

A pure function of the log, so devices holding the same changes find the same notices. For one field
of a live record: the writes no other write knew (a later write of the same device, or a write with
`knew[device] >= seq`, knows it) are the heads; only the last write of each device can be one, so
the work per field grows with the number of devices, not with the number of writes; those that are concurrent with another head clash; a
notice `{collection, id, field, values: [{value, device, seq}], applies}` exists when the clashing
heads carry different values (compared by canonical form). **Equal values are no notice.** A write
that knew all heads settles it; the final deletion of the record removes it. Values are sorted by
device, then seq; notices by collection, id, field.

## Soft delete

An ordinary field named `deleted` (`DELETED_FIELD`) with `true` hides a record, `false` shows it
again. It travels and decides like any field; an app must not use that name for its own data.

## Signatures

`signText` / `verifyText`: ECDSA P-256 with SHA-256 over the UTF-8 bytes of a text; the signature is
the 64-byte P1363 form (r, s), 86 base64url characters. Signing normalises to **low-s** (if s > n/2 it
becomes n - s; n is the order of the P-256 group, `FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551`),
and verification refuses a high s, because (r, n - s) also verifies and would give a signed change a
second spelling. Verification is strict: a signature that is not canonical base64url (one spelling
per signature), not 64 bytes, high-s, or not valid is simply `false`.

**Signed text of a change** (`changeSigningText(appId, change, dataSet)`):

```
${appId}-change:2|${canonical({ v: 2, set: dataSet, device, seq, clock, collection, id, kind, check })}
```

- The **marker** `${appId}-change:2` is part of the text, so a signature made for one app never
  verifies in another.
- `set` is the **data set** the change belongs to (a non-empty string; anything else is a `TypeError`,
  so the binding can never be dropped silently); it does not count in another.
- Head fields `device`, `seq`, `clock`, `collection`, `id`, `kind` are bound; `kind` `redacted` counts
  as `set`, so erasing the content keeps the signature valid.
- `check` is the content check value (`changeCheckValue`); it is taken before an erasure and kept, so
  the content (`fields`, `knew`, `time`, `by`) is bound through it.
- Example: `demo-change:2|{"check":"c1","clock":3,"collection":"items","device":"a","id":"x","kind":"set","seq":1,"set":"main","v":2}`.

**Order of verification** (`judgeChanges`; `judgeChange` is exactly `judgeChanges(context, [change])`
for that change), the first rule that applies decides. Every `false` carries a reason code
(`Rejection.reason`, `Session.refusalReason`):

1. a member other than `device`, `seq`, `clock`, `collection`, `id`, `kind`, `fields`, `knew`, `time`,
   `by`, `check`, `sig` (for a `redacted` change: other than `device`, `seq`, `clock`, `collection`,
   `id`, `kind`, `check`, `sig`): `false`, `unknown-member` (the signature does not cover it, so it
   would travel unchecked);
2. the app's special-case hook (`checked` / `false` (`not-allowed`) / `pending`; undefined = go on);
3. a device the key source says was removed (`KeySource.standing`, a `cutoff`) and `seq` above the
   cutoff: **`ignored`**, `after-removal` (not taken, not forwarded, not a refusal);
4. no `sig` or no `check`: `false`, `unsigned`;
5. a `delete` in a collection of `neverErase` (the option, or `KeySource.neverErase`): `false`,
   `never-erase`;
6. a change that is not `redacted` whose content does not match `check`: `false`, `bad-check`;
7. the author's key is not known (`KeySource.standing().key`, else `keyFor`): `pending`;
8. the signature does not verify: `false`, `bad-signature` (a change this replica already holds with
   the same signed text and the same signature was verified when it was taken: a repeat costs no
   second check);
9. a change under the receiver's own device id that is not already in its log: `false`,
   `own-history`. It is decided **only now**, after the signature verified with this device's own
   key: an unsigned or forged change under the own id is `unsigned` / `bad-signature` and must not
   tell the app to abandon its id;
10. the same `device#seq` is already known (in the log, or earlier in the batch or session) with a
    different signed text (head or check value): `false`, `equivocation`;
11. a `delete` and the app's `allowFinalDelete(author, change, state)` does not say yes (it is
    **missing by default**, so a final deletion is judged `false`, `delete-not-allowed`: it is
    irreversible, the id is dead for ever, and every member's signature makes one valid);
12. the rights hook `mayWrite(author, change, state)` says no: `false`, `not-allowed`;
13. otherwise `checked`.

A `redacted` change that is `checked` is taken only if its record's final deletion is **really
applied**: already in the replica (its data or its log), or applied by `merge` in the replica as it
would be with the batch's verified changes (the erased changes that pass included, as one fills the
gap of its own number). A deletion that is judged right but that `merge` holds back (a gap in its
author's numbering, a `knew` it cannot reach, a clock jump) does not count: the erased change is
`pending` (not taken, not forwarded), and the same when the deletion itself is `pending` or `ignored`;
without any deletion in sight it is `false`, `redacted-without-deletion` (in a partial session, see
below, it waits instead). Otherwise a forwarder could erase a signed write at a victim while the
deletion is not applied there. In `readChanges` and `receiveJudged` the verdicts do not depend on
the order of the batch, its piece structure or the order in which keys become known.

**Verdicts.** `checked`: taken. `pending`: neither taken nor forwarded, it comes again. `ignored`:
neither taken nor forwarded, and not a refusal; the session goes on and the vector of that device does
not advance past the gap, so the sender offers the changes again in every session. `false`: forgery.
`readChanges` judges the batch (`admit`, then `settle`, which repeats while taken changes make more
authors checkable); a single `false` aborts the whole batch and nothing is taken.

**Key source.** `KeySource.keyFor(device, state)` is required. Optional: `standing(device, state)`
returns `{ key?, cutoff? }` (the trust layer fills it from removal entries; `key` wins over `keyFor`,
a number `cutoff` makes every change with `seq` above it `ignored`), and `neverErase`, a list of
collections that is merged into the judge option of the same name (the device list itself must never
be finally deleted).

**What an app does with a reason.**

- `own-history`: this device is told about a change of its OWN id, correctly signed with its key,
  that it does not hold: its state is
  older than the world's (restored backup, cloned profile). It must stop writing and enrol again with
  a NEW device id; writing on would create equivocation.
- `after-removal` is never a refusal; count it (`ReadResult.ignored`, `Session.ignored`).
- `equivocation`: one device signed the same number twice with different content. Equivocation is
  only detected when the two histories meet in one replica: two devices holding different versions
  have equal stands, so a stand-based session never sends the change and only the fingerprints
  differ; a third device that meets both versions refuses the second. There is no hash chain. The
  author (`Rejection.change.device`, `Session.refusalDevice`) is faulty or malicious: the app should
  stop trusting that device (remove it from the device list) and tell the people involved. Whoever
  already took one version keeps it; the replicas do not heal by themselves. An erased change
  (`y:1 redacted`) whose deletion was the other version is refused as `redacted-without-deletion`
  for ever on a device holding the harmless version: the signal is the reason code.
- `delete-not-allowed`: pass `allowFinalDelete` if the app has final deletions at all.
- the others name the rule that failed.

**The log is unbounded.** Nothing in the package limits how many changes the members write: a member
can flood the log, and every device keeps and forwards it. An app bounds this with `mayWrite` (what an
author may write) and `quota(author, count, state)` (how many changes of one author a session takes;
`false` ends the reading of that session, see "Partial sessions"; default unlimited), and by removing
a member that floods. Replicas are immutable values: the caches kept per log array (record index,
held changes, deletions) are checked against the array's length and last element, but a replica must
never be mutated in place.

## Exchange

Over any channel (direct connection, relay, a file) two devices run one **session**: both send their
stand; each answers with the changes the other lacks, in pieces; each takes what arrives and closes
with its new stand and a fingerprint. Equal fingerprints mean both show the same data. The channel
only carries the messages; encryption belongs to the session of the `core` layer (not built yet).

### Messages

All messages are JSON objects with exactly these members; an unknown member refuses the message.

| `t`       | Members                                                                                               | Meaning                                                                                                                    |
| --------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `stand`   | `vector`                                                                                              | The sender's version vector; opens the session                                                                             |
| `changes` | `changes` (list of changes), `last` (boolean), `more` (only `true`, only with `last: true`, optional) | One piece of the changes the receiver lacks; `last` ends the list; `more` says the answer was cut (see "Partial sessions") |
| `done`    | `vector`, `fingerprint` (32 lower-case hex)                                                           | Sent once, after the other's last piece was taken                                                                          |

Flow: on a `stand` the receiver answers with the changes the other lacks in the order of its own log
(always at least one piece, the last marked `last: true`, and `more: true` when the answer was cut). On the other's last piece a device merges, then sends one
`done` with its stand and `fingerprint(replica)`. Once it has sent and received `done`, `outcome`
tells whether the fingerprints are equal. A repeated piece is harmless: merging is idempotent and
`done` is sent only once.

**Pieces** are cut at `pieceBytes` UTF-8 bytes of the JSON text of the changes (each counted with one
byte for the separator) or at `maxChanges` changes, whichever comes first; one change larger than the
piece size travels alone. Pieces must arrive **in order**: the stream of a device is gapless, and a
change behind a gap is not stored (`merge` returns it as `held`). A session that saw the last piece
early is not corrupted, but ends with different fingerprints; the next session catches up.

**Fingerprint.** SHA-256 over the canonical form of
`[[collection, [[id, 'deleted'] | [id, [[field, value], ...]], ...]], ...]` (collections and fields
sorted by name, records by id, deleted records as `'deleted'`); the first 16 bytes as 32 hex digits.
Only visible data counts (current values), not history. It is a consistency check of 128 bits, not a
proof against a peer that lies.

### Strict reading

`parseChange`, `parseVector` and `parseSyncMessage` return `undefined` for anything that is not
exactly the shape, and never throw (a throwing getter, a revoked proxy or a throwing option is
`undefined` too). They never modify their input and return fresh objects that share nothing with it.

- **Objects** must be plain (an object literal, `JSON.parse` output, or no prototype): no class
  instance, `Date`, `Map`. Members other than the listed ones refuse the object; a member that is
  `undefined` counts as absent.
- **Change:** `device` (device id), `seq` and `clock` safe integers of 1 or more, `collection` and
  `id` 1 to `maxId` characters, names as below, `kind` one of `set`/`delete`/`redacted`; `knew` (a
  vector; required for `set` and `delete`), optional `time` (safe integer, 0 or more), `by` (1 to
  `maxName` characters, no control or format character, NFC), `check` (43 base64url characters), `sig` (86 base64url characters, only with
  `check`). A `redacted` change refuses `knew`, `time` and `by`. `fields` is required, non-empty and at most `maxFields` for `set`, and refused for
  `delete` and `redacted`.
- **Vector:** at most `maxDevices` entries; keys are device ids, values safe integers of 0 or more.
- **Numbers** must be safe integers (counts) or finite (values): `NaN`, `Infinity`, `-Infinity`,
  floats where a count is expected, negatives and anything above 2^53 refuse.
- **Names and keys** (`collection`, `id`, `fields`, keys inside a value) are 1 to `maxName` (`maxId`
  for collection and id) characters without control or format characters, in NFC form, and never
  `__proto__`, `constructor` or `prototype`; the same three are refused
  as device ids even when the app's device id pattern would take them.
- **A field value** is `null`, a boolean, a finite number, a text of at most `maxText` characters, or
  a list or object of such values: at most `maxDepth` levels, `maxEntries` entries per list or object,
  and `maxValueChars` characters as JSON text per value. Reading is bounded: every node costs one
  character of that budget, so a huge or deeply nested value is refused without being read in full.
- **Device ids** are checked with the option `deviceId: (id: string) => boolean`. The default is
  `DEFAULT_DEVICE_ID`, `/^[A-Za-z0-9._-]{1,80}$/`; an app passes its own pattern (for example exactly
  16 hex digits). The package does not fix a length.

### Limits

One object, `LIMITS`, holds every default; the parsers, `pieces` and the session functions take
`{ limits: Partial<Limits> }` to override some of them for one call.

| Limit               | Default  | Meaning                                                                                  |
| ------------------- | -------- | ---------------------------------------------------------------------------------------- |
| `maxFields`         | 40       | Fields in one `set` change                                                               |
| `maxText`           | 2000     | Characters of one text inside a value                                                    |
| `maxValueChars`     | 16000    | JSON characters of one field value                                                       |
| `maxDepth`          | 6        | Nested lists/objects in one value                                                        |
| `maxEntries`        | 200      | Entries in one list or object of a value                                                 |
| `maxDevices`        | 50       | Devices in one vector (`stand`, `done`, `knew`)                                          |
| `maxChanges`        | 500      | Changes in one message                                                                   |
| `pieceBytes`        | 12000    | Size at which a piece is cut (UTF-8 bytes of JSON)                                       |
| `maxMessageChars`   | 1000000  | One `changes` message as JSON text (all its changes together); more is refused           |
| `maxSessionChanges` | 100000   | Changes one session carries: a sender cuts its answer here, a receiver ends reading here |
| `maxSessionChars`   | 16000000 | JSON characters of the changes one session carries (same: cut, not refusal)              |
| `maxPendingChanges` | 2000     | Changes still unverifiable AFTER the key-learning rounds of a session (cut, not refusal) |
| `maxName`           | 120      | Field name, `by`, keys inside a value                                                    |
| `maxId`             | 200      | Collection name and record id                                                            |

Where the two earlier implementations differed, the larger value is the default (fields per change,
text per value). The check value (43) and signature (86) lengths are fixed by the core layer.

### A rejected change ends the session

`receive` (strict reading, then `onSyncMessage`) and `receiveJudged` (strict reading, then judging
every piece AS IT ARRIVES) turn any HOSTILE input into a **refusal** of the whole session, and nothing of the
offending piece (in `receiveJudged`: of the whole session) is taken. `Session.refusal` is one of:

- `unreadable`: the message, or one change in it, is not exactly the shape (`refusalReason`
  `unparsable`).
- `forged`: a change was judged false; `Session.refusalReason` is the reason code of the section
  "Signatures" and `Session.refusalDevice` its author. Everything except the question "is there a
  deletion beside this erased change" is decided at once: an unsigned, forged, equivocating or
  not-allowed change refuses the session at the piece that carries it, not at the last piece.
- `unexpected`: a second `stand` (`repeated-stand`) or a second `done` (`repeated-done`) in one
  session. Every `stand` costs an answer, so one is enough.

**Memory.** `receiveJudged` holds verified changes (to take), verified erased changes (waiting for
their deletion) and changes whose author's key is unknown, at most `maxSessionChanges` changes and
`maxSessionChars` characters in all (`Session.bufferedChars`); nothing unverified beyond that.
Changes whose author is unknown are bounded only by this overall budget while the pieces arrive: an
author that a later change of the same batch introduces (the typical new device) must fit. Verified
changes are held, not merged, until the last piece, so one forged change anywhere means nothing is
taken. The accumulators are extended in place (private to the session), so a long session costs
linear time.

### Partial sessions

A large honest history must never make a join impossible, so size limits do not refuse; they cut.

- **Sender.** A `stand` is answered with at most `maxSessionChanges` changes and `maxSessionChars`
  characters, taken as a **prefix of the sender's own log** (the order its changes were applied in, so
  everything a change depends on comes before it, and each device's numbers stay gapless), and sent in
  that order. The last message then carries `more: true` (`Session.sentMore`). An erased change is
  never sent without its record's deletion (when the deletion is not part of the answer, the erased
  change and later changes of its author wait for the next session). The receiver continues in its
  next session, from the stand it then has.
- **Receiver.** `maxSessionChanges`, `maxSessionChars` and the `quota` hook END THE READING instead
  of refusing: a piece is cut where the limit is hit (before any signature work), later pieces are
  skipped, everything verified so far is taken after the last piece, and the session ends with
  `Session.truncated = true`. What is still unverifiable after the key-learning rounds is cut at
  `maxPendingChanges` (also `truncated`). Only hostile input is a refusal.
- **After a partial session** the fingerprints are expected to differ: `outcome(...).complete` is
  false when either side cut (`truncated`, `peerMore`, `sentMore`); run the next session. Sessions
  repeat until a session is complete. In a partial session an erased change without a deletion in
  sight is not a forgery but a cut: it waits (not refused).
- **Hostile input** is unchanged: forged, equivocating, unreadable, unexpected and not-allowed
  changes refuse the session at the piece that carries them. A hostile change AFTER the cut is not
  seen (reading had ended).

**What a device sends.** A `stand` is answered with the changes the other lacks that carry a
signature (`SessionOptions.signedOnly`, default true): the device's own changes that are not signed
yet would be judged forged by every receiver, and since numbering is gapless the sender would block
itself. From the first unsigned change of a device on, nothing of that device is sent (a later change
could not be applied without it). The same holds for an erased change whose record's deletion is
withheld (an unsigned own deletion): the erased change of the foreign author is withheld too, else
the receiver would refuse the session and blame that author. `Session.withheld` counts what was
left out. Plain, unjudged test
sessions pass `signedOnly: false`.

**Text entry and transports.** `parseSyncMessageText(text)` takes a message as text, refuses anything
longer than twice `maxMessageChars` before it reads any JSON, and then reads strictly. A transport
should also cap what it hands over; the exchange does not rely on it.

**Order of pieces.** The pieces of one session are meant to arrive in the order they were sent. The
exchange does not promise to take everything from a session whose pieces were reordered, but it never
corrupts a replica: numbering stays gapless, nothing is taken twice, nothing the sender does not hold
appears, and the next ordinary session fills what is missing (tests: `tests/log/order.test.ts`). In the
judged variant (`receiveJudged`) the pieces before the last one may come in any order; the last piece
ends the session, and pieces that arrive after it are not taken. Duplicated pieces are harmless.

A refused session sends nothing, ignores every later message and has no `outcome`. This is
deliberate: taking the valid part of a piece would leave a gap in a device's numbering, and every
later change of that device would wait for ever. `receiveJudged` decides what it can per piece and
settles the rest on the last one, because an erased write may arrive in an earlier piece than the
final deletion it needs. Changes whose author cannot be checked yet (`pending`) are neither taken
nor stored; they count as `waiting` and arrive again in a later session.

## Trust (device list, meeting code, invitation)

Everything the `trust` layer writes into the log or hands between two devices in person. Names are
English; the format version is `2`. Predicates for ids, names, roles and relay ids are the app's
(parameters); a value containing `|` is never valid for a device id, a name or a role, because `|`
separates the signed and MACed texts.

### Device entries in the log

One record per device in one reserved collection (default `device`; the app may name it). The record id
is the device id. Entries are never finally deleted: the collection belongs in `neverErase`
(`deviceNeverErase()`), so a final deletion there is judged false.

| Field     | Type    | Required | Meaning                                                                                  |
| --------- | ------- | -------- | ---------------------------------------------------------------------------------------- |
| `name`    | text    | yes      | Display name (app predicate; default 1 to 40 letters, digits, ` ._-`)                    |
| `sig`     | text    | yes      | Public signing key, a point (87 characters); must differ from `dh`                       |
| `dh`      | text    | yes      | Public agreement key, a point (87 characters)                                            |
| `role`    | text    | no       | Opaque role (app predicate; default `^[a-z][a-z0-9:_-]{0,79}$`)                          |
| `relayId` | text    | no       | The id the relay gave the device (app predicate; default 1 to 80, no control characters) |
| `removed` | boolean | no       | `true` ends trust; entries stay. Missing counts as false                                 |
| `lastSeq` | integer | no       | Written with `removed: true`: the highest number of the removed device the remover holds |
| `private` | boolean | no       | "Private device" flag; written only when true or when it replaces a differing value      |

A device id (default `device-` and 32 lower-case hex digits, `newDeviceId`) is 128 random bits. A
second id, `relayId`, is assigned by a relay; the trust layer only validates it.

### Trust derivation

Trust is derived from the log and from `direct` (the devices met in person, with the keys learned in
person), never stored (`computeTrust`, `deviceStatus`). The result is a function of the SET of changes
and of `direct`: the order changes arrived in, the order records were created in and the order of the
met list change nothing (property test over 400 random scenarios, `tests/trust/order.test.ts`). No rule
iterates until it settles, no rule looks at the shrinking result.

Terms. A **write** is one value of one field of an entry together with its writer and its change. A
write **counts** when its writer is this device (unsigned, it holds its own log) or a vouching device
of the current round, whose signature checks (check value, `changeSigningText` with the app id and the
data set, the voucher's signing key as the derivation holds it) and who is not the device the entry
belongs to. `canVouch(device, entries)` is the app's strategy (`vouchAll`, `vouchRoles`,
`vouchAnyRole`); it is asked when a device joins and again when its entry changes, and must answer
from the entry (its role); `entries` is a live view of the derivation so far.

1. **Potential trust P** (removals ignored). The least fixpoint from the devices met in person, in
   synchronous rounds: a device joins when its name, signing key and agreement key each have a valid
   counting value (the newest valid one of the writes that count), and the keys differ. Role,
   `relayId` and `private` are taken the same way when present. A round looks only at the state at its
   start, so no order of records matters. A met device keeps the entry learned in person (name,
   keys, role) and may add a role it lacks from the log (when the keys agree). A role that does not
   count (`roleCounts`) stays as `roleVouched`. The number of rounds is bounded (a derivation always
   ends). This device itself is always a root and its own writes count.
2. **Key consistency.** For every device `d`, all values ever written for its `sig` and `dh` by
   devices of P that vouch (the whole history, signatures checked, not only the newest) are collected.
   More than one distinct `sig` or `dh`: `d` is not trusted through the chain (reason `key-conflict`;
   a voucher that writes its own key into another entry is a conflict for that entry, whichever
   entry was written first). A met device keeps the keys learned in person; a conflicting vouch is
   ignored and reported (`key-mismatch`). More than one distinct `relayId`: the relay id is dropped
   (`relay-conflict`), the device stays trusted. P is then computed again without the conflicted
   devices. Keys of an id never change: a re-keyed device is a new device id.
3. **Removal.** A removal edge `r -> t` exists when the newest `removed: true` that `r` wrote into the
   entry of `t` counts (`r` is in P, vouches, signature checks) AND `r` is reachable from the met
   devices (and this device) inside P by a chain of vouching devices that does not pass through `t`
   (an edge `u -> w`: `u` vouches and wrote an identity field of `w`). Such a removal is **effective**.
   It is evaluated statically on P, never on the shrinking result, so mutual or cyclic removals
   remove everybody involved (**fail closed**: when `A` and `R` remove each other and both are
   reachable without the other, both are removed) and the result never depends on record or log
   order. What the device itself or a non-voucher wrote into `removed` counts for nothing; a later
   `removed: false` (by anybody, also by the remover) does not take a removal back. A removed device
   stays removed: re-admission means a NEW device id (`addDevice` refuses `removed`).
4. **Trust T** = what is reachable from the met devices in P restricted to the devices that are not
   effectively removed and not key-conflicted: the derivation of rule 1 run again without them, so a
   device that was vouched only through a removed device drops out, and a met device that is
   effectively removed is not trusted either. `checkable` = T plus the effectively removed devices
   whose keys were vouched for: a removal ends trust from now on, not what the device wrote before.
   Hiding ("deleting") an entry ends nothing.
5. **Cut-off.** `removeDevice` writes `lastSeq` (an integer, the highest change number of the removed
   device this device holds) together with `removed: true`. `standing(device)` of an effectively
   removed device is `{ key, cutoff }` with `cutoff` = the minimum of `lastSeq` over all its
   effective removals (smaller = stricter, the same at every device; a removal without a valid
   `lastSeq` gives no cutoff). `deviceKeySource` implements `KeySource.standing`: the judge ignores
   (verdict `ignored`, reason `after-removal`) changes of that device with `seq` above the cutoff
   without refusing the session; changes up to the cutoff stay `checked`. `deviceKeySource.neverErase`
   lists the device collection.

Reasons (`deviceStatus(replica, id, { ...options, direct })`: `{ trusted, checkable, removed,
cutoff?, reasons }`): `key-conflict`, `key-mismatch`, `relay-conflict`, `removed`, `not-vouched`.
`listDevices` is only a display of the raw entries (what some device wrote last, whoever it was);
`addDevice` and `removeDevice` decide against the derived state, not against the raw entry.

Cost. One pass over the log builds an index of the entries (kept per log array); the rounds then
touch only the entries a newly vouching device wrote, so a chain of 400 devices derives in about 10 ms
once its signatures are checked (checks are remembered per change). `deviceKeySource` derives once per
replica state and answers `keyFor` and `standing` from that result.

What the derivation does not decide (limits an app handles):

- The meeting code carries the role and the name as self-declaration, has no recipient bound and can be
  relayed by a third party within its 120 s window.
- The single use of an invitation is not enforceable offline: two replies to one code can both be
  taken; the damage is one more device of that role. An app keeps a ledger of used invitations.
  A kept `open` invitation lets a removed device answer it again only with a new device id: the old id
  stays removed.
- A voucher can always write anything into an entry; the rules above limit what survives (keys,
  relay ids, removals by unreachable devices), not a trusted administrator's choice of a name or a role.
- The check code (`checkCode`) carries about 13.3 bits per group; use `groups` of 8 or more where it
  is the only protection against a modified invitation link.

### Markers

`marker(appId, kind, 2)` = `<appId>-<kind>:2` with the kinds `meeting`, `invite` and `reply`
(`device` is the check code of the core layer). A different app id never produces the same bytes.

### Meeting code

Two people exchange it in person (QR bytes). **Layout:** compact JSON (no spaces), UTF-8, members in
exactly this order; `private` only when true:

```
{"m":"<appId>-meeting:2","device":"…","name":"…","sig":"…","dh":"…","role":"…","time":<ms>,["private":true,]"proof":"…"}
```

`proof` is the device's ECDSA signature (86 characters) over the text
`<appId>-meeting:2|device|name|sig|dh|role|time|0` (the last field `1` when private). The reader
refuses anything that is not exactly this spelling (other order, spaces, duplicates, unknown members,
escapes, more than 2000 bytes). `time` and `role` are mandatory.

Valid for **120 000 ms** after `time` (inclusive: now - time <= 120 000), renewed by the showing
device every **30 000 ms**, with a **60 000 ms** look-ahead for clocks (time - now <= 60 000).
Otherwise `expired` / `ahead`; a wrong signature is `changed`.

### Invitation

An invitation lives **24 hours** (`until` = creation time + 86 400 000 ms; at `now >= until` it is over).
It is text after `#join=` (a link, pasted text or QR); the part before is any page address.

```
<page>#join=<base64url(JSON)>
{"m":"<appId>-invite:2","device":"…","name":"…","sig":"…","dh":"…","role":"…","code":"…","until":<ms>[,"newName":"…"][,"relayId":"…"][,"private":true]}
```

`device`, `name`, `sig`, `dh` are the inviting device; `code` is the one-time code (16 random bytes,
22 characters, canonical base64url); `newName` is the name suggested for the new device; `relayId`
the inviter's. Payload at most 2000 characters; same strictness as above (one spelling only).

The new device answers with its introduction and a **proof**: HMAC-SHA-256, keyed by the 16 code bytes,
over the text

```
<appId>-invite:2|<inviter device>|<role>|<new device>|<new name>|<new sig>|<new dh>
```

(base64url, 43 characters). It binds the invitation's inviter, role, and the new device's id, name and
both keys. The reply text is base64url of
`{"m":"<appId>-reply:2","to":"<inviter device>","device":"…","name":"…","sig":"…","dh":"…","proof":"…"}`.

The inviter keeps `{role, code, until[, private]}` and checks the reply against it: not expired,
`to` is itself, introduction valid, the new device is not itself, the voucher's `mayInvite` still
allows it (when asked), and the proof matches. The invitation carries no signature: the inviter's keys
in it are only as trustworthy as the channel it travels on (compare the check codes).
`mayInvite(inviter, role)` decides who may invite which role; a private device must have a role the
app's `privateRoles` predicate allows.

# Cross-language notes

What another implementation (another language, another JSON library) must do to produce and accept
the same bytes. The committed vectors in `tests/vectors/` are meant for such ports; the tests in
`tests/vectors.test.ts` run them against this code. All vector files are JSON.

## Numbers

Canonical text of a number is the ECMAScript `Number::toString` of the **IEEE 754 double** the JSON
text rounds to (`JSON.stringify`): `1e21` is `1e+21`, `1e-7` is `1e-7`, `0.1 + 0.2` is
`0.30000000000000004`, **`-0` is `0`**, `5e-324` is `5e-324`, `1E2` is `100`, and `9007199254740993`
(2^53 + 1) is read as the double `9007199254740992` and written so. Exponent form starts at 1e21 and
below 1e-6. A port needs the shortest-round-trip printing of doubles in this exact style (a
`%g`-like printer is not enough). `NaN` and the infinities are refused. Counts (`seq`, `clock`,
vector entries, `time`) must be safe integers (at most 2^53 - 1) and are refused otherwise.

## Key order

Object keys are sorted by **UTF-16 code unit**, not by code point and not by UTF-8 bytes. A key made of
U+1F600 (UTF-16 `D83D DE00`) therefore sorts BEFORE one made of U+FF5E (`FF5E`), although its code point
is larger; `"10"` sorts before `"9"`; the empty key sorts first. A language that sorts by code point or
by UTF-8 bytes must sort by UTF-16 units here (vector: `canonical.json`, "keys sort by UTF-16").

## Strings

Written as `JSON.stringify` writes them: `"` and `\` escaped, the C0 controls (U+0000 to U+001F) as
`\b \t \n \f \r` or `\u00xx` (lower-case hex), everything else raw: U+007F, U+2028, U+2029 and all
non-ASCII characters are NOT escaped, and `/` is not escaped. Hashing is over the UTF-8 bytes of the
whole text. Text is never normalised by the canonical form (`e` + U+0301 stays two characters); the
strict readers refuse names and labels that are not in NFC form instead.

**Lone surrogates** (a UTF-16 unit of D800 to DFFF without its partner) have no UTF-8 form; an
encoder writes U+FFFD for them, so two different values would get one hash. They are refused
everywhere: `canonical` throws a `TypeError` for a text or a key that has one, and the strict readers
(`parseChange`, `parseSyncMessage`, local `write`) refuse them in names, keys and texts
(`invalid-name` / `invalid-value`). A language whose strings are UTF-8 cannot hold one and refuses the
JSON text that spells one as an escape (`"\ud800"`); a surrogate **pair** spelled as two escapes is the
one character it encodes.

## Duplicate keys

A JSON text in which an object has the same key twice (compared after decoding escapes: `"a"` and
`"` + backslash + `u0061"` are the same key) is **refused** by the text entry points (`parseSyncMessageText`,
`hasDuplicateKeys`). Parsers disagree on such texts (JavaScript keeps the last, others the first or
fail), and a signed value must not mean two things. A port must refuse them before it reads any
member. The same key in different objects is fine.

## What is signed and hashed

- Check value: `base64url(SHA-256(UTF-8(canonical(value))))` without padding, 43 characters
  (`canonical.json`).
- Signed text of a change: `<appId>-change:2|` and the canonical form of `{v: 2, set, device, seq, clock,
collection, id, kind, check}`, a `redacted` change counting as `set` (`signing-text.json`).
- Signature: ECDSA P-256 / SHA-256, 64 bytes (r, s big-endian, 32 bytes each), unpadded base64url,
  **low-s only** (s at most n/2). A signer must normalise; a verifier must refuse a high s.
- Check code of a device: `check-code.json`.
- `verification.json` holds one public key (a throw-away made for that file) and one signed change
  that every implementation must accept, with the variants it must refuse.
