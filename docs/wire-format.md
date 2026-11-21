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
`${marker(appId, 'device', 2)}|${deviceId}|${sig}|${dh}` (`sig`, `dh` as the base64url points). Take the
first ten bytes as five big-endian 16-bit numbers; each modulo 10000, zero-padded to four digits, joined by
single spaces: `dddd dddd dddd dddd dddd`.

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
so numbering stays gapless and the head stays checkable. A `set` that arrives for an already deleted
record is stored redacted from the start.

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
`too-many-devices` (more devices wrote the fields than one `knew` may name), `clock-overflow`, plus
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

A change's `knew` contains, from its author's stand at write time, only the devices that wrote the
fields this change writes (writes in the author's log of that record, devices holding a current
value of those fields). A deletion names every device that wrote the record. A record the author
never held gives `{}`. Devices with number 0 are left out; keys are sorted. Every decision of the
model asks `knew` only about such devices, so it decides exactly as with the whole stand.
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
the 64-byte P1363 form (r, s), 86 base64url characters. Verification is strict: a signature that is
not canonical base64url (one spelling per signature), not 64 bytes, or not valid is simply `false`.

**Signed text of a change** (`changeSigningText(appId, change, dataSet)`):

```
${appId}-change:2|${canonical({ v: 2, set: dataSet, device, seq, clock, collection, id, kind, check })}
```

- The **marker** `${appId}-change:2` is part of the text, so a signature made for one app never
  verifies in another.
- `set` is the **data set** the change belongs to; it does not count in another.
- Head fields `device`, `seq`, `clock`, `collection`, `id`, `kind` are bound; `kind` `redacted` counts
  as `set`, so erasing the content keeps the signature valid.
- `check` is the content check value (`changeCheckValue`); it is taken before an erasure and kept, so
  the content (`fields`, `knew`, `time`, `by`) is bound through it.
- Example: `demo-change:2|{"check":"c1","clock":3,"collection":"items","device":"a","id":"x","kind":"set","seq":1,"set":"main","v":2}`.

**Order of verification** (`judgeChange`), the first rule that applies decides:

1. a member other than `device`, `seq`, `clock`, `collection`, `id`, `kind`, `fields`, `knew`, `time`,
   `by`, `check`, `sig`: `false` (the signature does not cover it, so it would travel unchecked);
2. the app's special-case hook (`checked` / `false` / `pending`; undefined = go on);
3. a change under the receiver's own device id that is not already in its log: `false`;
4. no `sig` or no `check`: `false`;
5. a `delete` in a collection of `neverErase`: `false`;
6. a change that is not `redacted` whose content does not match `check`: `false`;
7. the author's key is not known (`KeySource.keyFor`): `pending`;
8. the signature does not verify: `false`;
9. the rights hook `mayWrite(author, change)` says no: `false`;
10. otherwise `checked`.

In a batch (`judgeChanges`) a `redacted` change that is `checked` counts only beside its record's
final deletion (in the log already, or in the batch and `checked`); beside a deletion that is
`pending` it is `pending`; otherwise `false`.

**Verdicts.** `checked`: taken. `pending`: neither taken nor forwarded, it comes again. `false`:
forgery. `readChanges` repeats the judgement while taken changes make more authors checkable; a single
`false` aborts the whole batch and nothing is taken.

## Exchange

Over any channel (direct connection, relay, a file) two devices run one **session**: both send their
stand; each answers with the changes the other lacks, in pieces; each takes what arrives and closes
with its new stand and a fingerprint. Equal fingerprints mean both show the same data. The channel
only carries the messages; encryption belongs to the session of the `core` layer (not built yet).

### Messages

All messages are JSON objects with exactly these members; an unknown member refuses the message.

| `t`       | Members                                       | Meaning                                                           |
| --------- | --------------------------------------------- | ----------------------------------------------------------------- |
| `stand`   | `vector`                                      | The sender's version vector; opens the session                    |
| `changes` | `changes` (list of changes), `last` (boolean) | One piece of the changes the receiver lacks; `last` ends the list |
| `done`    | `vector`, `fingerprint` (32 lower-case hex)   | Sent once, after the other's last piece was taken                 |

Flow: on a `stand` the receiver answers with `pieces(missingFor(replica, vector))` (always at least
one piece, the last marked `last: true`). On the other's last piece a device merges, then sends one
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
sorted by name, records by id, deleted records as `'deleted'`); the first four bytes as 8 hex digits.
Only visible data counts (current values), not history. It is a consistency check of 32 bits, not a
proof.

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
  `check`). `fields` is required, non-empty and at most `maxFields` for `set`, and refused for
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

| Limit               | Default | Meaning                                                                        |
| ------------------- | ------- | ------------------------------------------------------------------------------ |
| `maxFields`         | 40      | Fields in one `set` change                                                     |
| `maxText`           | 2000    | Characters of one text inside a value                                          |
| `maxValueChars`     | 16000   | JSON characters of one field value                                             |
| `maxDepth`          | 6       | Nested lists/objects in one value                                              |
| `maxEntries`        | 200     | Entries in one list or object of a value                                       |
| `maxDevices`        | 50      | Devices in one vector (`stand`, `done`, `knew`)                                |
| `maxChanges`        | 500     | Changes in one message                                                         |
| `pieceBytes`        | 12000   | Size at which a piece is cut (UTF-8 bytes of JSON)                             |
| `maxMessageChars`   | 1000000 | One `changes` message as JSON text (all its changes together); more is refused |
| `maxSessionChanges` | 100000  | Changes `receiveJudged` collects over one session before it refuses            |
| `maxName`           | 120     | Field name, `by`, keys inside a value                                          |
| `maxId`             | 200     | Collection name and record id                                                  |

Where the two earlier implementations differed, the larger value is the default (fields per change,
text per value). The check value (43) and signature (86) lengths are fixed by the core layer.

### A rejected change ends the session

`receive` (strict reading, then `onSyncMessage`) and `receiveJudged` (strict reading, then
`readChanges` on everything the other sent) turn any problem into a **refusal** of the whole session,
and nothing of the offending piece (in `receiveJudged`: of the whole session) is taken:

- `unreadable`: the message, or one change in it, is not exactly the shape.
- `forged`: `readChanges` judged a change false (signature, check value, a change under the
  receiver's own id, rights).
- `too-large`: more than `maxSessionChanges` changes collected.

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
later change of that device would wait for ever. `receiveJudged` collects the pieces and judges them
together on the last one, because an erased write may arrive in an earlier piece than the final
deletion it needs. Changes whose author cannot be checked yet (`pending`) are neither taken nor
stored; they count as `waiting` and arrive again in a later session.

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
| `private` | boolean | no       | "Private device" flag; written only when true or when it replaces a differing value      |

A device id (default `device-` and 32 lower-case hex digits, `newDeviceId`) is 128 random bits. A
second id, `relayId`, is assigned by a relay; the trust layer only validates it.

### Trust derivation

Trust is derived from the log and the devices met in person, never stored (`computeTrust`):

1. The devices met in person (`direct`) are trusted as given. Their role counts only when the app's
   `roleCounts(role, replica)` says so (default: always); a role that does not count stays as
   `roleVouched`.
2. A device **vouches** when the app's strategy says so (`Voucher.canVouch(device, trusted)`; `vouchAll`,
   `vouchRoles`, `vouchAnyRole` are ready made). The strategy is asked again after every step.
3. For each field of an entry counts **the newest value written by this device itself (unsigned) or by
   a vouching trusted device whose signature checks** (check value, `changeSigningText` with the app
   id and data set, the voucher's signing key). A device's own write into its own entry never counts.
   What any other device wrote counts for nothing.
4. An entry with a vouched name and keys is trusted; this repeats until nothing is added (chains
   A -> B -> C). A met device keeps its keys: an entry with other keys for it is ignored. A role learned
   later from an entry counts from then on (and may make the device a voucher).
5. `removed` = true, so vouched, ends trust, also of a met device, and what the removed device vouched
   for no longer counts through it. The derivation is repeated without the removed ones.
   Hiding ("deleting") an entry ends nothing.
6. `checkable` = the trusted devices and the removed ones whose keys were vouched for: a removal ends
   trust from now on, not what the device wrote before. `deviceKeySource` hands the keys of
   `checkable` to `readChanges`/`judgeChanges`, derived from the replica as it would be with the
   batch taken so far, so changes that enter a device make its own later changes checkable. A
   removed device stays checkable; whether it may still write is the app's `mayWrite` rule.

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
