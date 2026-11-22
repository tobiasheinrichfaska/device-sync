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
${appId}-change:2|${canonical({ v: 2, set: dataSet, device, seq, clock, collection, id, kind, check[, prev] })}
```

- The **marker** `${appId}-change:2` is part of the text, so a signature made for one app never
  verifies in another.
- `set` is the **data set** the change belongs to (a non-empty string; anything else is a `TypeError`,
  so the binding can never be dropped silently); it does not count in another.
- Head fields `device`, `seq`, `clock`, `collection`, `id`, `kind` are bound; `kind` `redacted` counts
  as `set`, so erasing the content keeps the signature valid.
- `check` is the content check value (`changeCheckValue`); it is taken before an erasure and kept, so
  the content (`fields`, `knew`, `time`, `by`) is bound through it.
- `prev` is the **hash chain**: the LINK of the SAME device's previous change (`seq - 1`).
  `changeLink(change)` = base64url(SHA-256(canonical({v, device, seq, clock, collection, id, kind,
  check, prev}))), that is the signed head with its content check value and its own `prev`; only
  the app marker and the data set (the same for every change of a data set, and unknown to a replica)
  are left out. The link therefore covers EVERY signed member: two versions of one number that differ
  in clock, collection, record, kind or content have different links, and so does every later number
  of the chain. `prev` is present on every change with `seq` above 1 and absent on the first; it is
  part of the signed head and it **survives redaction** (an erased change keeps its `prev` and has the
  same link as before, so the text of an erased change stays the one of the original). An honest
  device therefore can never follow two different versions of one number with the same successor:
  signing `m:1` twice makes `m:2` name only one of them.
- Example: `demo-change:2|{"check":"c1","clock":3,"collection":"items","device":"a","id":"x","kind":"set","seq":1,"set":"main","v":2}`.
- Example with prev: `demo-change:2|{"check":"c2","clock":4,"collection":"items","device":"a","id":"x","kind":"delete","prev":"c1","seq":2,"set":"main","v":2}`.

The format changed with the hash chain (round 3, third pass): the text of a change with `seq` above 1
now contains `prev`; the first change's text is unchanged (the committed vectors in `tests/vectors/`
were updated on purpose, `signing-text.json`; `verification.json` gained two refused variants).

**Order of verification** (`judgeChanges`; `judgeChange` is exactly `judgeChanges(context, [change])`
for that change), the first rule that applies decides. Every `false` carries a reason code
(`Rejection.reason`, `Session.refusalReason`):

1. a member other than `device`, `seq`, `clock`, `collection`, `id`, `kind`, `fields`, `knew`, `time`,
   `by`, `check`, `prev`, `sig` (for a `redacted` change: other than `device`, `seq`, `clock`,
   `collection`, `id`, `kind`, `check`, `prev`, `sig`): `false`, `unknown-member` (the signature does
   not cover it, so it would travel unchecked);
2. the app's special-case hook (`checked` / `false` (`not-allowed`) / `pending`; undefined = go on);
3. no `sig` or no `check`: `false`, `unsigned`;
4. `prev` missing after the first change, or present on the first: `false`, `bad-prev` (a signature
   made without the chain must not make a change valid);
5. a `delete` in a collection of `neverErase` (the option, or `KeySource.neverErase`): `false`,
   `never-erase`;
6. a change that is not `redacted` whose content does not match `check`: `false`, `bad-check`;
7. the author's key is not known (`KeySource.keyFor`): `pending`;
8. the signature does not verify: `false`, `bad-signature` (a change this replica already holds with
   the same signed text and the same signature was verified when it was taken: a repeat costs no
   second check);
9. a change under the receiver's own device id that is not already in its log: `false`,
   `own-history`. It is decided **only now**, after the signature verified with this device's own
   key: an unsigned or forged change under the own id is `unsigned` / `bad-signature` and must not
   tell the app to abandon its id;
10. the same `device#seq` is already known (in the log, or earlier in the batch or session) with a
    different signed text (head or check value): `false`, `equivocation` (two changes of one author
    are in hand and both verified under its key: this is a proof); the same when its `prev` is not
    the link of the predecessor (`device#seq-1`) the log or the batch holds, or the batch holds a
    successor whose `prev` names another change;
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
`pending` (not taken, not forwarded), and the same when the deletion itself is `pending`;
without any deletion in sight it is `false`, `redacted-without-deletion` (in a partial session, see
below, it waits instead). Otherwise a forwarder could erase a signed write at a victim while the
deletion is not applied there. In `readChanges` and `receiveJudged` the verdicts do not depend on
the order of the batch, its piece structure, the order in which keys become known, or whether a
verified change that `merge` holds back (a causal hold) is merged yet: the key source is asked
against the replica plus everything verified (also what `merge` holds back) plus the waiting
changes, and a device whose key was once vouched for stays checkable whether or not it has been
removed or has fallen out of trust since (`tests/trust/round4.test.ts`, F1: removal first, after, or
hidden behind a causal hold). A key source whose answer depends on the replica for other reasons
(not the trust layer's) is not covered by this sentence. The set of erased
changes that count is the greatest set consistent with itself; it is found with one linear pass over
the dependencies (an erased change whose record has no deletion that can still apply is dropped, which
opens a gap that kills the later deletions of its author, and so on) and a few merges, so a chain of
erased changes that each need the next one costs linear time (`tests/log/review4.test.ts`, N6).

**Verdicts.** `checked`: taken. `pending`: neither taken nor forwarded, it comes again. `false`:
forgery. `readChanges` judges the batch (`admit`, then `settle`, which repeats while taken changes
make more authors checkable); a single `false` aborts the whole batch and nothing is taken. Each
round of `settle` looks up the key of each waiting author once and judges only the changes of
authors that have become checkable; it merges only what the round before added. A key source that
verifies every signature it reads itself (`KeySource.selfVerifying`, set by the trust layer) is
asked against the replica plus the waiting changes (never one claiming the receiver's own id), so a
chain of devices that each introduce the next is read in one round instead of one per link
(1600 chained entries: about 0.5 s; `tests/trust/chainscale.test.ts`).

**Key source.** `KeySource.keyFor(device, state)` is required. Optional: `neverErase`, a list of
collections that is merged into the judge option of the same name (the device list itself must never
be finally deleted), and `selfVerifying` (see above). A key source says who can be CHECKED, not who
may write: a device that is not trusted (removed, or vouched only through a removed device) stays
checkable when its key was ever vouched for (see "Trust derivation"), and what it may still do is the
app's `mayWrite`.

**What an app does with a reason.**

- `own-history`: this device is told about a change of its OWN id, correctly signed with its key,
  that it does not hold: its state is
  older than the world's (restored backup, cloned profile). It must stop writing and enrol again with
  a NEW device id; writing on would create equivocation.
- `equivocation`: two changes of one device are in hand and both verified under its key: the same
  number signed twice with different content or head, or a change whose `prev` does not name the
  predecessor that is held (that predecessor is signed by the same author, so the author signed two
  incompatible histories). This is a PROOF: the author is faulty or malicious, the app should stop
  trusting that device and tell the people involved. Whoever already took one version keeps it; the
  replicas do not heal by themselves. An erased change (`y:1 redacted`) whose deletion was the other
  version is refused as `redacted-without-deletion` for ever on a device holding the harmless
  version: the signal is the reason code.
- `tip-mismatch` (refusal `diverged`, see "A rejected change ends the session"): a `stand` names
  another link for a number this device holds. The link covers the whole signed head and the chain, so
  ANY difference in the history behind the position, in head or content, shows at the first `stand`
  of the two devices (the one with the lower vector holds the other's tip number); it is detected
  when two devices that hold different versions meet, and not before. A tip is an UNPROVEN claim: the
  sender may have invented it, or a network attacker changed it. The session therefore ends without
  blaming anybody (`Session.subjectDevice` names the device whose HISTORY differs, not a culprit,
  and `refusalDevice` stays unset). What an app does: retry the session (a damaged stand does not
  come twice); to find out whether the author really signed two versions, ask the other device for
  its change at that number (`changeAt(replica, device, seq)` on its side), read it with
  `parseChange`, and call `proveEquivocation(a, b, publicKey, appId, dataSet)`: it is true only for
  two changes with the same device and number, different signed texts, and BOTH signatures
  verifying under the key (and a content that matches its check value). Only that proof may be acted
  on; **never remove or distrust a device because of a `tip-mismatch` alone**, or a member could have
  honest devices removed and an attacker could block all synchronisation with a forged tip.
- `bad-prev`: a change that is not spelled right (no chain link after the first change); a sender that
  follows the format never produces it.
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
only carries the messages; encryption belongs to the session of the `core` layer (built; this package has no test that wires
the two together, the app does).

### Messages

All messages are JSON objects with exactly these members; an unknown member refuses the message.

| `t`       | Members                                                                                               | Meaning                                                                                                                        |
| --------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `stand`   | `vector`, `tips`                                                                                      | The sender's version vector and, per device, the link (`changeLink`) of the change at the vector's position; opens the session |
| `changes` | `changes` (list of changes), `last` (boolean), `more` (only `true`, only with `last: true`, optional) | One piece of the changes the receiver lacks; `last` ends the list; `more` says the answer was cut (see "Partial sessions")     |
| `done`    | `vector`, `fingerprint` (32 lower-case hex)                                                           | Sent once, after the other's last piece was taken                                                                              |

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
  `check`), `prev` (43 base64url characters: required when `seq` is above 1, refused on `seq` 1, kept
  by a `redacted` change). A `redacted` change refuses `knew`, `time` and `by`. `fields` is required, non-empty and at most `maxFields` for `set`, and refused for
  `delete` and `redacted`.
- **Vector:** in a `knew` at most `maxDevices` entries (the concurrent heads of a field); in a
  `stand` or `done` at most `maxStandDevices` (the vector lists every device that ever wrote, so
  it grows over the years). Keys are device ids, values safe integers of 0 or more. A stand or done
  over the limit, or over `maxMessageChars` as JSON, is well-formed but too large: the parser returns
  `{ t: 'overflow', of }` (never sent), without reading the entries, and the session ends gracefully
  (`Session.truncated`, `limit: 'stand-devices'`), it is not a refusal. Arithmetic: one entry costs
  about 50 characters in the vector and 90 in the tips for a 39-character device id, so 10000
  devices are about 1.4 million characters: for such ids `maxMessageChars` (1 million) binds before
  `maxStandDevices` does, at about 7000 devices; raise both together.
- **Tips** (of a `stand`; required, may be empty): at most `maxStandDevices` entries; keys are device
  ids that the vector counts with a number of 1 or more, values are 43 base64url characters. A tip names
  the link (`changeLink`) of the change at the vector's position; a receiver that holds the change at
  that number with another link ends the session (`diverged`, `tip-mismatch`, no culprit), and a
  tip of a number it does not hold proves nothing.
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

| Limit               | Default  | Meaning                                                                                         |
| ------------------- | -------- | ----------------------------------------------------------------------------------------------- |
| `maxFields`         | 40       | Fields in one `set` change                                                                      |
| `maxText`           | 2000     | Characters of one text inside a value                                                           |
| `maxValueChars`     | 16000    | JSON characters of one field value                                                              |
| `maxDepth`          | 6        | Nested lists/objects in one value                                                               |
| `maxEntries`        | 200      | Entries in one list or object of a value                                                        |
| `maxDevices`        | 50       | Devices in one `knew` (concurrent heads of a field)                                             |
| `maxStandDevices`   | 10000    | Devices in the vector of a `stand` or `done` and in its `tips` (over: session ends, no refusal) |
| `maxChanges`        | 500      | Changes in one message                                                                          |
| `pieceBytes`        | 12000    | Size at which a piece is cut (UTF-8 bytes of JSON)                                              |
| `maxMessageChars`   | 1000000  | One `changes` message as JSON text (all its changes together); more is refused                  |
| `maxSessionChanges` | 100000   | Changes one session carries: a sender cuts its answer here, a receiver ends reading here        |
| `maxSessionChars`   | 16000000 | JSON characters of the changes one session carries (same: cut, not refusal)                     |
| `maxGroupChanges`   | 400000   | `maxSessionChanges` while an erased change waits for its deletion (indivisible group)           |
| `maxGroupChars`     | 64000000 | `maxSessionChars` while an erased change waits for its deletion                                 |
| `maxPendingChanges` | 2000     | Changes still unverifiable AFTER the key-learning rounds of a session (cut, not refusal)        |
| `maxName`           | 120      | Field name, `by`, keys inside a value                                                           |
| `maxId`             | 200      | Collection name and record id                                                                   |

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
- `diverged`: a `stand` whose `tips` contradict the receiver's log (another version of a number it
  holds) ends the session at the stand, with the reason `tip-mismatch`, before anything is sent or
  any signature is checked. It blames nobody (a tip is an unproven claim): `Session.subjectDevice`
  names the device whose history differs, `refusalDevice` stays unset; see `proveEquivocation`.
- `unexpected`: a DIFFERENT second `stand` (`repeated-stand`) or a different second `done`
  (`repeated-done`) in one session. Every `stand` costs an answer, so one is enough. An IDENTICAL
  repeat (a transport that delivers a message twice) is ignored: no answer, no refusal.

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
  change and later changes of its author wait for the next session), and a change is never sent
  without what its `knew` names. **Progress:** an answer holds at least one applicable group of
  changes whenever any exists, also when that group alone is larger than the budget: an erased change,
  all earlier numbers of its author and the deletion form ONE group (a deletion is applied only after
  its author's earlier numbers), and a single large change is a group of its own. A budget that cut
  every applicable change away would repeat for ever (the reviewer's proof of concept: 32 big changes
  and then the deletion of an earlier record answered 0 changes with `more: true` in every session).
  The receiver continues in its next session, from the stand it then has.
- **Receiver.** `maxSessionChanges`, `maxSessionChars` and the `quota` hook END THE READING instead
  of refusing: a piece is cut where the limit is hit (before any signature work), later pieces are
  skipped, everything verified so far is taken after the last piece, and the session ends with
  `Session.truncated = true`. Two exceptions keep the sender's guarantee of progress: the first
  change of a session always fits (it is bounded by the message limit), and while an erased change
  waits for its deletion the budgets are `maxGroupChanges` and `maxGroupChars` (if larger), because
  the group cannot be applied in parts. A group larger than those ceilings cannot be taken: the
  session ends `truncated` every time, and the app raises the limits (the log is unbounded, so is
  an indivisible group). What is still unverifiable after the key-learning rounds is cut at
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

| Field     | Type    | Required | Meaning                                                                                                             |
| --------- | ------- | -------- | ------------------------------------------------------------------------------------------------------------------- |
| `name`    | text    | yes      | Display name (app predicate; default 1 to 40 letters, digits, ` ._-`)                                               |
| `sig`     | text    | yes      | Public signing key, a point (87 characters); must differ from `dh`                                                  |
| `dh`      | text    | yes      | Public agreement key, a point (87 characters)                                                                       |
| `role`    | text    | no       | Opaque role (app predicate; default `^[a-z][a-z0-9:_-]{0,79}$`)                                                     |
| `relayId` | text    | no       | The id the relay gave the device (app predicate; default 1 to 80, no control characters)                            |
| `removed` | boolean | no       | `true` ends standing as a voucher and as introduced; entries stay, signatures still verify. Missing counts as false |
| `private` | boolean | no       | "Private device" flag; written only when true or when it replaces a differing value                                 |

A device id (default `device-` and 32 lower-case hex digits, `newDeviceId`) is 128 random bits. A
second id, `relayId`, is assigned by a relay; the trust layer only validates it.

### Trust derivation

Trust is derived from the log and from `direct` (the devices met in person, with the keys learned in
person), never stored (`computeTrust`, `deviceStatus`). The result is a function of the SET of changes
and of `direct`: the order changes arrived in, the order records were created in and the order of the
met list change nothing (property test over 400 random scenarios, `tests/trust/order.test.ts`, and a
differential test of 3200 scenarios against an independent reference written from these rules,
`tests/trust/reference.test.ts`). No rule iterates until it settles on its own result: the only
iteration is the synchronous rounds of rule 1, with a fixed bound.

**What a removal means (read this first).** A removal ends a device's standing as a VOUCHER and as a
device that can be introduced through the chain. The removed device stays **checkable**: its signed
changes, the earlier AND the later ones, still verify, and the signature layer accepts them. So does
every device that fell out of trust without being removed itself (it was vouched for only through a
removed or key-conflicted device): its key was validly vouched for once, so its changes are not held
back for ever (else the honest devices that took one of them could never learn what came after, see
`checkable` in rule 5); `deviceStatus` says `trusted: false, checkable: true` for it. **This
layer does not revoke a removed device's ability to write.** An app that removes a device must itself
(1) stop exchanging with it at the transport, (2) treat data authored by removed devices as
untrusted when it presents it (`deviceStatus(...).removed`), (3) restrict what it may still do with
`mayWrite` / `allowFinalDelete`, knowing that a hook that looks at state can answer differently on two
devices (they may hold different parts of the log), and (4) rotate the group keys on removal (group keys are not part of this package yet). A removed device stays removed: coming back means a NEW device
id (`addDevice` refuses `removed`; `removed: false` is never a way back). An earlier design stopped
the writes of a removed device automatically (`lastSeq`, the verdict `ignored`, `KeySource.standing`);
it was taken out because a device-local decision about someone else's numbers makes honest devices
disagree and block each other.

Terms. A **write** is one value of one field of an entry together with its writer and its change. A
write **counts** when its writer is this device (it holds its own log) or a device that vouches in the
current round and whose signature on the write checks (check value, `changeSigningText` with the app
id and the data set, under one of the **keys** the writer's entry has, see rule 1), and the writer is
not the device the entry belongs to. `canVouch(device, entries)` is the app's strategy (`vouchAll`,
`vouchRoles`, `vouchAnyRole`); it is asked when a device joins and again when its entry changes, and
must answer from the entry (its role); `entries` is a live view of the derivation so far. This device
itself is always a root and its own writes always count.

1. **Potential trust P** (removals and key conflicts ignored: this is "who could be trusted"). The
   fixpoint from the devices met in person, in synchronous rounds: a device joins when its name,
   signing key and agreement key each have a valid counting value (the newest valid one of the writes
   that count), and the keys differ. Role, `relayId` and `private` are taken the same way when
   present. A round looks only at the state at its start, so no order of records matters. Membership
   only grows (a device that joined stays) and the voucher flag follows the newest entry: a voucher
   that is later given another role by a vouching device stops vouching, but whoever it introduced
   while it vouched is not taken out of P again by that (P only grows: a device that joined stays, the
   rounds are bounded, so a derivation always ends; test `N10` in `tests/trust/review5.test.ts`).
   What this means in the demotion cases: whoever the voucher introduced WHILE its newest entry said
   it vouches stays in P; the voucher flag follows the newest entry, so what it introduces after the
   demotion does not join, and a device that was only waiting for a vouch from it when the demotion
   happened (same round) does not join either. Which of these devices are then TRUSTED is rule 5:
   a demoted voucher that nobody removes keeps what it introduced trusted, because T is rule 1 run
   again without the removed devices. A met device keeps the entry learned in person (name,
   keys, role) and may add a role it lacks from the log (when the keys agree). A role that does not
   count (`roleCounts`) stays as `roleVouched`. The **keys** of a device are the one learned in person
   for a met device, else the newest `MAX_CANDIDATE_KEYS` (8) distinct signing keys that counting
   writes gave its entry, newest first: a voucher that writes another key into an entry (up to that
   number) cannot make that device's own writes unverifiable, and one that writes thousands cannot
   make checking cost keys times writes. A signature check is remembered per change and key, and the
   key that verified last for an entry is tried first.
2. **Rank.** Rank is the distance in the vouching graph from the roots, inside P: this device and the
   met devices have rank 0; an edge `u -> w` exists when `u` is this device or vouches and wrote a
   verified identity field (`name`, `sig`, `dh`, `role`, `relayId`, `private`) of the entry of `w`.
3. **Removals**, rank by rank (rank ascending), all devices of one rank acting at the same time.
   A device `r` of P that is reachable acts when it is NOT removed by a device of a STRICTLY lower
   rank (this device itself never loses the right to remove: it holds its own log) and it vouches:
   then for every device `t` into whose entry `r` wrote a **verified** `removed: true` (an
   unverifiable write does not shadow a verified one, whatever the order; a write of the device into
   its own entry and a later `removed: false` count for nothing), the removal is **effective** when
   `r` is reachable from the roots inside P by a chain that does not pass through `t`; `t` is then
   removed. There is **no tie-break by device id** (a joining device chooses its own id): two devices
   of EQUAL rank that remove each other are both removed, whichever id is smaller. What follows,
   stated plainly: (a) a removal made by a device PERSISTS after that device is itself removed by a
   device of the same or a higher rank; only a device of lower rank can undo the damage, by
   removing the remover (then the remover's removals no longer count, as it is removed at a lower
   rank); (b) any voucher can remove the devices it can reach (inherent in the voucher strategy: the
   app chooses `vouchRoles`, and who may hold the role); (c) a removed device cannot be restored:
   it comes back as a NEW device id; (d) a compromised voucher cannot make its own removal void by
   tampering with the remover's entry. The result is a function of the viewer's `direct`: a viewer
   who met B in person gives B rank 0, and a removal by B then acts before a removal by a device
   of rank 1 (so two honest viewers with different met devices can disagree about who is trusted;
   `tests/trust/round4.test.ts`, F6, states the exact outcomes). `direct` is per viewer by design.
4. **Key consistency**, after the removals: for every device `d`, all values ever written for its
   `sig` and `dh` by devices of P that vouch and are NOT removed (the whole history, signatures
   checked, not only the newest) are collected. More than one distinct `sig` or `dh`: `d` is not
   trusted through the chain (reason `key-conflict`); a met device keeps the keys learned in person,
   a conflicting vouch is ignored and reported (`key-mismatch`). More than one distinct `relayId`: the
   relay id is dropped (`relay-conflict`), the device stays trusted. **What a removed device wrote
   carries no authority for key conflicts, and a removed device does not vouch** (what it introduced
   later joins nothing, and what it wrote into other entries is not read as vouching). It does
   have effect on removals made in rank order: a removal it made persists while it is not removed by
   a device of lower rank (rule 3). Keys of an id never
   change: a re-keyed device is a new device id. A voucher can pre-occupy a future device id with its
   own keys: when the real device is entered later, `addDevice` answers `other-keys` (a voucher can
   always write anything; this is the cost of vouching).
5. **Trust T** = what is reachable from the roots through vouchers (rule 1 run again) without the
   effectively removed devices and the key-conflicted devices, so a device that was vouched only
   through a removed device drops out, and a met device that is effectively removed is not trusted
   either. `checkable` = EVERY device in P without a key conflict, trusted or not: the trusted ones, the
   effectively removed ones, and the ones that fell out of T because only a removed (or
   key-conflicted) device vouched for them. A device whose key was ever validly vouched for keeps its
   signed changes verifiable: otherwise honest devices that took one of its changes could never
   take what depends on it, and the verdict would depend on what `merge` currently holds. The entry
   is read from the writes of vouchers that were not removed (keys written by a removed device are
   not used); where only removed devices vouched, the entry as P has it, unless those disagree on the
   signing key, which makes it ambiguous and the device not checkable. A removal ends trust from now
   on, not what the device wrote before or after. Hiding ("deleting") an entry ends nothing.

Reasons (`deviceStatus(replica, id, { ...options, direct })`: `{ trusted, checkable, removed,
reasons }`): `key-conflict`, `key-mismatch`, `relay-conflict`, `removed`, `not-vouched`.
`listDevices` is only a display of the raw entries (what some device wrote last, whoever it was, a
device writing its own role included): never use it for authorization. `addDevice` and `removeDevice`
decide against the derived state, not against the raw entry. `deviceKeySource` gives the key of every
checkable device (rule 5: not only T), derives once per replica state, and lists the device
collection in `neverErase`.

Cost. One pass over the log builds an index of the entries (kept per log array); the rounds then
touch only the entries a newly vouching device wrote, so a chain of 400 devices derives in about 10 ms
once its signatures are checked (checks are remembered per change). `readChanges` of a long chain is
linear in practice because the key source is asked against the replica plus the waiting changes (see
"Verdicts").

What the derivation does not decide (limits an app handles):

- The meeting code carries the role and the name as self-declaration, has no recipient bound and can be
  relayed by a third party within its 120 s window.
- The single use of an invitation is not enforceable offline: two replies to one code can both be
  taken; the damage is one more device of that role. An app keeps a ledger of used invitations.
  A kept `open` invitation lets a removed device answer it again only with a new device id: the old id
  stays removed.
- A voucher can always write anything into an entry; the rules above limit what survives (keys,
  relay ids, removals by unreachable or removed devices), not a trusted administrator's choice of a
  name or a role.
- Removing a device does not stop it from writing (see "What a removal means").
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

# Wire format: end-to-end layer (session and encrypted file)

Two ways to move data between two devices that know each other's agreement key (the trust layer
verified it; this layer never decides whom to trust): a **session** (many messages, both directions,
forward secret) and an **encrypted file** (one message to one named recipient, handed over by any
channel). Implemented in `src/core/session.ts` and `src/core/file.ts`; the vectors in
`tests/vectors/session.json` and `tests/vectors/file.json` are checked by `tests/vectors-session.test.ts`
against the code AND against an independent derivation written from this text with `node:crypto`.

## Common rules

- **Primitives.** ECDH P-256 (the shared secret is the 32-byte big-endian X coordinate, as WebCrypto
  `deriveBits` gives it), HKDF-SHA-256 (RFC 5869: extract with the salt, expand with the info text to 32
  bytes), AES-256-GCM (12-byte nonce, 16-byte tag appended to the ciphertext, additional data as below),
  SHA-256. Nothing else.
- **Markers.** `marker(appId, kind, 2)` with the kinds `hello`, `msg`, `session` and `file` (the app id
  enters every key, salt and additional data, so two apps never share bytes).
- **Length-prefixed fields.** `<n>:<text>` where `<n>` is the decimal UTF-8 byte length of the text.
  Every variable field of a hashed or authenticated text is written this way, so no field can be shifted
  into another.
- **Device ids** (this layer's own rule; the trust layer may be stricter): 1 to 200 UTF-16 units, no
  control character (`\p{Cc}`), no format character (`\p{Cf}`), no lone surrogate, no `|`.
- **Points.** A public key travels as the uncompressed point, 65 bytes, canonical unpadded base64url, 87
  characters (the spare bits of the last character are zero: one point has one text). Every point is
  checked **on the curve** before it is used (WebCrypto `importKey` refuses the point at infinity (it has
  no uncompressed form), a point with a coordinate at or above the field prime and any point off the
  curve); the cofactor of P-256 is 1.
- **One spelling.** Every text is compact JSON with its members in exactly the documented order. A reader
  parses the text, rebuilds the text from the parsed values and accepts only an exact match, so a second
  spelling (spaces, other member order, escapes, a duplicate or unknown member, a `__proto__` member,
  non-canonical base64url, a leading zero in a number, a byte order mark) is refused. Reading is bounded
  before parsing (the cap is a function of the limits) and answers `undefined`, never throws.
- **Refusals are codes** (`reason`), never sentences, and a refusal leaves every state exactly as it was.

## Session

Both sides send a `hello` at the same moment (no initiator, no responder), each with a **fresh ephemeral
ECDH P-256 key**. The session key comes from the ephemeral keys and the two static keys together.

### Hello

```
{"m":"<appId>-hello:2","device":"<device id>","eph":"<ephemeral point>"}
```

It carries no signature: it need not be secret and cannot be forged into a session, because a session
made from a changed hello does not interoperate with the real peer (first message fails). The caller
passes the peer's hello, the peer's expected device id and the peer's static agreement point `dh` (from
the trust layer). The reader checks the text only; the point is checked on the curve when the session is
opened.

### Opening (refusals, in this order)

The caller supplies: `appId`, own `device` and agreement pair, the `peer` (`device`, `dh`), the own
ephemeral pair and both hellos. Refused with a code: `bad-own`, `bad-peer`, `bad-hello` (a hello that is
not exactly device and eph), `own-hello-mismatch` (own hello has another device id or another point than
the ephemeral pair), `wrong-device` (the peer's hello names another device than `peer.device`),
`same-device`, `mirrored` (both hellos carry the same ephemeral point: a message fed back), `bad-peer-key`
(not a point), `same-key` (the peer's static point is this device's own), `bad-point` (the peer's
ephemeral point is not on the curve), `ephemeral-reused`, `crypto-failure`. An invalid app id is a
`TypeError` (programming error). **One ephemeral pair opens one session**: the same pair would derive the
same keys again and a second session would repeat nonces; the library remembers the pair (in memory, per
process) and refuses a second use. A refused opening leaves the pair usable (it is marked only when a
session is made).

### Key derivation

Let `lo` be the device whose id is smaller by **UTF-8 byte order** (not UTF-16 order, not locale order) and
`hi` the other. Write `S` for static, `E` for ephemeral keys. Four 32-byte ECDH secrets, concatenated in this
order, are the input keying material (128 bytes):

```
ee = ECDH(E_lo, E_hi)      ephemeral x ephemeral   (forward secrecy)
t1 = ECDH(E_lo, S_hi)      lo's ephemeral key with hi's static key
t2 = ECDH(S_lo, E_hi)      lo's static key with hi's ephemeral key
ss = ECDH(S_lo, S_hi)      static x static
ikm = ee || t1 || t2 || ss
```

Both sides compute the same four values (each has the secret half of one operand of each).

Transcript text and **HKDF salt** (SHA-256 of the UTF-8 text):

```
<appId>-session:2|<n>:<lo device>|<n>:<lo dh>|<n>:<lo eph>|<n>:<hi device>|<n>:<hi dh>|<n>:<hi eph>
```

It binds the app, both device ids, both static public keys and both ephemeral public keys. **HKDF info**
for the key that protects messages SENT BY device `X`: `<appId>-session:2|key|<n>:<X>`. So there are two
keys, one per direction.

### Messages

```
{"m":"<appId>-msg:2","n":<counter>,"ct":"<base64url of ciphertext || tag>"}
```

- `n` is the sender's counter, 0, 1, 2, ... a canonical decimal safe integer, in clear.
- **Nonce** (12 bytes): four zero bytes, then `n` as an 8-byte big-endian integer. AES-GCM nonces are
  therefore **counter-based**: unique under one key because each direction has its own key and the counter
  only grows. Nothing random is involved in sealing.
- **Additional data** (UTF-8): `<appId>-msg:2|<n>:<sender>|<n>:<receiver>|<counter>`.
- **Plaintext**: opaque bytes (the app decides what they are, e.g. UTF-8 JSON). At most `maxPlaintextBytes`.
  Empty is allowed (the ciphertext is then the 16-byte tag).
- **Receiving**: the next accepted counter is the number of messages accepted so far. A message with a
  smaller counter is `replayed`, with a larger counter `gap` (something was dropped or reordered), at or
  above `maxMessages` `counter-limit`; these are decided from the clear counter before any decryption, and
  again after it (two openings of one message at the same moment: one wins, the other is `replayed`).
  Other refusals: `bad-message` (not exactly the spelling above, too long, ciphertext shorter than a tag
  or longer than `maxPlaintextBytes + 16`), `bad-seal` (the tag does not verify). **Only a message that
  verifies moves the counter**, so refused or forged input never changes the session and the real next
  message is still accepted.
- **Sending**: the counter is taken (before the first `await`, so concurrent seals get different numbers)
  and moves; at `maxMessages` sealing is refused (`counter-limit`) and nothing moves; a plaintext over the
  limit is `too-large`. The counter never wraps.
- `confirmed` becomes true when the first message of the peer has verified: only then is it shown that the
  peer holds the keys.

### Limits

| Limit               | Default                            | Meaning                                                            |
| ------------------- | ---------------------------------- | ------------------------------------------------------------------ |
| `maxPlaintextBytes` | 1 MiB (1 048 576 bytes)            | Largest plaintext per message; the wire text is capped from it     |
| `maxMessages`       | 2^32 (4 294 967 296) per direction | Messages under one key; clamped to 1 to 2^32 whatever is asked for |

A partial override (`resolveSessionLimits`) takes own, safe, non-negative integers only; anything else
keeps the default. The longest wire text is `ceil((maxPlaintextBytes + 16) * 4 / 3) + 256` characters
(`maxSealedChars`); a hello is at most 1024 characters.

### What the session protects, and what it does not

Protected (each point has tests, `tests/core/session.test.ts`):

- **Confidentiality and integrity** of every message against anyone who lacks the static secrets and the
  ephemeral secrets; every message carries a GCM tag over its counter, sender and receiver.
- **Both identities are bound.** The keys depend on the app id, both device ids, both static points and
  both hellos. A third party that knows every public key and both hellos cannot make a message either side
  accepts; a renamed hello, a wrong peer key, a wrong device id or another app id gives a session that
  cannot talk.
- **Implicit mutual authentication**: only the holders of the two static secrets can derive the keys.
  Explicit confirmation is only the first message that verifies (`confirmed`); a `hello` alone proves
  nothing.
- **Key-compromise impersonation resistance** (the crossed terms `t1`, `t2`): someone who stole device A's
  static secret still cannot speak as B to A in a new session, because the term that combines A's
  ephemeral key with B's static key needs A's ephemeral secret or B's static secret.
- **Forward secrecy** against a later leak of BOTH static secrets: the recorded session stays closed
  because `ee` needs an ephemeral secret, which only exists for the length of the session. The test shows
  that the values computable from the static secrets and the public hellos are not enough and that the
  ephemeral term is; it is not a proof of the property. It holds only while the ephemeral pair is
  discarded: the pair is a non-extractable WebCrypto key that lives as long as the caller (or the garbage
  collector) keeps it, and nothing can wipe memory in JavaScript. **There is no forward secrecy within a
  session**: the leak of a session key opens that session, both directions.
- **Replay, duplication, reordering, dropping and reflection** inside a session are refused: counters are
  strictly in order and the two directions use different keys (a message sent by A, fed back to A, never
  verifies; the sender id in the additional data is a second guard).
- Bounded memory and work per message (the wire text is capped before parsing, one AES-GCM operation).

Not protected:

- **Metadata.** The hello carries the device id in clear; messages show their length (plaintext + 16
  bytes), their number and timing; the transport sees who talks to whom. There is no padding.
- **Truncation.** A dropped LAST message cannot be noticed (no closing message); a dropped earlier one shows
  as `gap` when a later one arrives, and then the stream cannot continue: start a new session. Nothing is
  retransmitted here.
- **The hello is not authenticated by itself.** An attacker on the path can replace it; the result is a
  session that fails at its first message (denial of service), never one that accepts forged messages.
- **No post-compromise security and no ratchet**: one pair of keys per session, up to 2^32 messages per
  direction; then open a new session.
- **State is in memory only.** The counters are the nonces: never restore a session from storage with an
  older counter (it would repeat nonces). After a restart make new hellos. The "one pair, one session" guard
  is per process; the caller must never keep an ephemeral pair across a restart.
- **No deniability claim and no signatures**: the peer has the same keys and could have made any message
  itself; nobody else can be convinced who wrote one. A cloned device (the same keys on two devices) is not
  detected here.
- **Whom to trust** is not decided here: `peer.dh` must come from the trust layer. An endpoint compromise,
  a compromised random generator and quantum attacks on P-256 are out of scope.

## Encrypted file

One message for one named recipient, as bytes: it can be mailed, put on a stick or sent in a chat. It is
made for exactly one `to` device by exactly one `from` device and opens only for that device, only from that
sender.

### Layout

UTF-8 bytes of one compact JSON text (members in this order, no byte order mark):

```
{"m":"<appId>-file:2","from":"<device id>","to":"<device id>","eph":"<ephemeral point>","iv":"<12 bytes>","ct":"<base64url of ciphertext || tag>"}
```

`iv` is exactly 12 bytes (16 characters), `ct` at least 16 bytes, at most `maxPlaintextBytes + 16`; `from`
and `to` are valid device ids and differ; the whole file is at most `maxFileBytes` bytes (a function of
`maxPlaintextBytes`; a reader refuses longer input before it parses).

### Key derivation

The sender makes a fresh ephemeral ECDH P-256 key `E` for this file and discards its secret half.
`S_from` and `S_to` are the static keys. Input keying material (64 bytes):

```
ikm = ECDH(E, S_to) || ECDH(S_from, S_to)
```

(the recipient computes `ECDH(S_to, E)` and `ECDH(S_to, S_from)`). **Header text**, used both as the HKDF
salt (SHA-256 of it) and as the AES-GCM additional data (UTF-8):

```
<appId>-file:2|<n>:<from>|<n>:<to>|<n>:<from dh>|<n>:<to dh>|<n>:<eph>
```

HKDF info: `<appId>-file:2|key`. The key is therefore unique per file and bound to app, both ids, both static
points and the ephemeral point; changing any header member (or swapping members of two files) breaks the
tag.

**Nonce.** The `iv` is 12 random bytes the caller supplies (`random`; sealing itself uses no randomness
besides WebCrypto's key generation). Every file has a key of its own, so a repeated nonce would still be
harmless; the caller should nevertheless pass fresh random bytes.

### Opening (refusals)

`bad-own`, `bad-sender` (the sender's id or point is malformed), `not-a-file` (not exactly the spelling above,
another marker or app id, too long, `from` equals `to`), `wrong-recipient` (`to` is not this device),
`wrong-sender` (`from` is not the named sender), `bad-point` (the ephemeral or the sender's point is not on
the curve), `cannot-open` (the tag does not verify: not from this sender, not for this key, or altered).
`readFileHeader` reads `{from, to}` without any key, to find the sender's key before opening.
Making a file is refused with `bad-own`, `bad-recipient`, `same-device`, `same-key`, `bad-random`
(not 12 bytes), `bad-input` (payload is not bytes), `too-large`, `crypto-failure`.

### Limits

| Limit               | Default                   | Meaning                                                       |
| ------------------- | ------------------------- | ------------------------------------------------------------- |
| `maxPlaintextBytes` | 32 MiB (33 554 432 bytes) | Largest payload; a larger file is refused before it is parsed |

### What the file protects, and what it does not

Protected: confidentiality and integrity of the payload for the named recipient; a file only the recipient
opens, only from the named sender (the static-static term authenticates the sender to the recipient); a file
of another app never opens; the sender's later compromise does not open its old files (the ephemeral secret
is gone).

Not protected:

- **No forward secrecy against the recipient's static key**: whoever gets it opens every file ever made for
  it (the test `tests/core/file.test.ts` shows it).
- **Recipient key compromise allows forging**: whoever holds the recipient's static secret can make a file
  that opens as "from A" for any A (the sender is authenticated by a Diffie-Hellman value the recipient can
  compute itself). There is no signature, so a file proves nothing to a third party (deniable).
- **No replay protection and no freshness**: the same file can be fed twice, later or never; the app must
  be idempotent (the change log is). The `iv` and the ephemeral key identify a file but nothing is
  remembered here.
- **Metadata**: sender and recipient ids and the app id are in clear in the header; the size shows
  (payload + 16 bytes, base64url); no padding.
- **Payload meaning**: bytes only. Whether they make sense (and what to do with a stale file) is for the app.
  What was said for the session about endpoint compromise, trust and P-256 holds here too.

# Wire format: envelope and mailbox

An **envelope** is one message for several reader devices that third devices can carry without learning
who wrote it, who may read it or how many readers there are (up to a multiple of 8). The **mailbox** is
what a device keeps of envelopes it carries for others, and the **per-day exchange** is how two devices
that meet bring their mailboxes level. Implemented in `src/core/envelope.ts` and `src/post/`; the
vectors in `tests/vectors/envelope.json` and `tests/vectors/mailbox.json` are checked by
`tests/vectors-envelope.test.ts` against the code AND against an independent derivation written from this
text with `node:crypto` (`tests/core/envelope-reference.ts`). The common rules of the end-to-end layer
(primitives, length-prefixed fields, device ids, points, one spelling, refusals are codes) hold here too.

## Envelope

### Wire text

UTF-8 (in fact ASCII) bytes of one compact JSON text, members in this order:

```
{"m":"<appId>-envelope:2","id":"<id>","day":"<YYYY-MM-DD>","eph":"<ephemeral point>","iv":"<12 bytes>","ct":"<base64url of ciphertext || tag>","k":["<48 bytes>", ...]}
```

- `day` is a real calendar day, `YYYY-MM-DD`, year 1970 to 9999 (`2026-02-30` is not one). A carrier drops
  the envelope after a while (see the mailbox).
- `eph` is a fresh ephemeral ECDH P-256 point per envelope (87 characters, canonical, first byte 4).
- `iv` is the 12-byte nonce of the content (16 characters); `ct` is at least 16 bytes.
- `k` is the **fan**: 8, 16, 24 ... up to `maxFans` slots, each exactly 48 bytes (64 characters, the
  wrapped 32-byte content key plus the 16-byte tag). Some slots are real, the rest are random bytes of the
  same size; their order is shuffled, so no slot can be told from another.
- The whole text is at most `maxEnvelopeBytes` bytes (11 000), checked before parsing.
- A reader parses the text, rebuilds the text from the parsed values and accepts only an exact match
  (a second spelling, an unknown member, a `__proto__` member, a duplicate key, a non-canonical
  base64url text, a fan that is not a multiple of 8, a wrong id: all refused; the answer is `undefined`,
  never an exception).

### Id

`id` = base64url (22 characters) of the first 16 bytes of SHA-256 over this text, every member written as
`<n>:<text>` with `<n>` the UTF-8 byte length (the count of slots is a plain decimal):

```
<appId>-envid:2|<n>:<day>|<n>:<eph>|<n>:<iv>|<n>:<ct>|<number of slots>|<n>:<slot 1>|<n>:<slot 2>|...
```

A changed copy cannot pass under the id of the real envelope, and the id is the same on every device, so a
carrier can compare boxes by ids. The same parts under another app id have another id.

### Making an envelope

The author passes its device id, its signing private key, the readers' agreement points (as the trust
layer verified them), a `channel` (a device-id-like text: 1 to 200 units, no control or format character,
no `|`), the `day`, the content (opaque bytes), a source of randomness and the limits. A reader listed
twice is one reader. Steps:

1. Sign (below), make a fresh ephemeral ECDH key `E` (WebCrypto), draw 32 random bytes as the **content
   key** `CK`, 12 as `iv`, 48 for every padding slot and 4 per slot for the shuffle (all from the
   `random(n)` the caller passes; sealing itself uses no clock and draws nothing else except `E`).
2. Header text: `<appId>-envelope:2|header|<n>:<day>|<n>:<eph>` (the same text for every reader).
3. For every reader with agreement point `dh`: `secret = ECDH(E, dh)` (the 32-byte X coordinate), key
   encryption key `KEK = HKDF-SHA-256(ikm = secret, salt = SHA-256(header text), info =
"<appId>-envelope:2|slot|<n>:<dh>")` (32 bytes), slot = AES-256-GCM(`KEK`, **zero nonce**, no additional
   data, `CK`) = 48 bytes. A zero nonce is safe because `KEK` is unique per envelope and reader (fresh `E`,
   `dh` in the info).
4. Pad with random 48-byte slots to the next multiple of 8, then shuffle the list (Fisher-Yates from the
   last element down, `j = u32(bytes[4i .. 4i+4]) mod (i + 1)`, big endian; the modulo bias is below
   2^-26 per step).
5. `ct` = AES-256-GCM(`CK`, `iv`, additional data = the header text, the inside text below).
6. Compute `id`, write the text, refuse it with `too-large` if it is longer than `maxEnvelopeBytes`.

Making is refused with a code, changing nothing: `bad-author` (device id or signing key unusable),
`bad-channel`, `bad-day`, `bad-input` (the content is not bytes), `bad-random` (the source is not a
function, throws or gives the wrong number of bytes), `no-recipients`, `too-many-recipients` (more than
`maxFans` readers listed), `bad-recipient` (not a point, or not on the curve), `too-large` (the content or
the finished text is over the limit), `crypto-failure`. An invalid app id is an exception (programming error).

### Inside and signature

The inside (the plaintext of `ct`) is one compact JSON text, members in this order:

```
{"from":"<device id>","channel":"<channel>","sig":"<64 bytes>","body":"<base64url of the content>"}
```

The **author's signature** (ECDSA P-256 / SHA-256, low-s, 64 bytes, as the log layer signs) is over the
UTF-8 text

```
<appId>-envsig:2|<n>:<from>|<n>:<channel>|<n>:<day>|<n>:<body as base64url>
```

so it binds the app, the author's device id, the channel, the day and the content. The recipients are not
in it (they must stay hidden): any reader that holds the content can seal it again for others, with the
author's signature still valid; a reader who passes the content on can also show a third party that the
author wrote it (no deniability, see below). The "stand" and "changes" of a log exchange are part of the
content (`body`), so the signature covers them; the package does not look inside the body.

### Opening (refusals, in this order)

The caller passes the app id, its agreement pair, the envelope (text or an envelope read here) and a
function `authorKey(from)` that gives the author's signing public point as the trust layer knows it (or
nothing). Refused with a code: `bad-own` (no usable agreement pair), `not-an-envelope` (not exactly the
spelling above, another marker or app id, too long, wrong id), `bad-point` (the ephemeral point is not on
the curve), `not-for-me` (no slot opens with this device's key: the answer for every stranger, and also for
an envelope whose day or ephemeral key was changed), `damaged` (a slot opened but the content does not
decrypt or its inside is not exactly the spelling above), `unknown-author` (`authorKey` gave nothing, a
point that is not on the curve, or threw), `bad-signature`.

Cost of an envelope that is **not for this device**: one point check, one ECDH, one HKDF derivation and at
most `maxFans` small AES-GCM trials (one per slot); nothing else (the test counts the calls). Cost of one that
is: the same, one decryption of the content, one `authorKey` call (made once, with the author found
**inside**) and one signature check. The first slot that opens decides: a sealer that wraps the key for
one reader in several slots cannot make the reader decrypt more than once.

### Limits

| Limit              | Default      | Meaning                                                                |
| ------------------ | ------------ | ---------------------------------------------------------------------- |
| `maxEnvelopeBytes` | 11 000 bytes | The whole wire text (one message of the exchange: it is cut at 12 000) |
| `maxFans`          | 64 slots     | Readers plus padding; rounded down to a multiple of 8, 8 to 4 096      |

A partial override (`resolveEnvelopeLimits`) takes own, safe, non-negative integers only; anything else keeps
the default. The largest content that can fit is a little under 8 250 bytes (3/4 of the size limit, less
the fixed members and the fan).

### What the envelope hides, and what it does not

Hidden from a carrier (a device that holds the text and no reader key):

- **the sender**: the author's id and the channel are inside the encrypted content;
- **the readers**: a slot is wrapped under a key only the reader and the sealer can compute; a carrier
  that knows every reader's public key still cannot tell which slot is for whom;
- **the number of readers**, up to the padding: 1 to 8 readers all give 8 slots (and the same size for the
  same content), 9 to 16 give 16, and so on; the order of the slots is shuffled, so a reader's place
  carries nothing (a chi-square test over 240 seeded envelopes);
- **the content and its signature**.

Not hidden:

- **Size** (content length plus fixed overhead plus the number of slot groups), **the day**, **the id**,
  **when and from whom a carrier got it**, and which carriers hold it. Two envelopes of the same author
  have unrelated ephemeral keys, nonces and slots, so nothing repeats that links them.
- **A reader's identity to the other readers** is not hidden from them: the author's id is inside the
  content; a reader sees who wrote it, and nothing in the envelope tells it who else reads.
- **The author is not deniable**: the signature over the content verifies with the author's public key, so
  any reader can prove to a third party that the author wrote it. (Within the session and the file layer
  nothing is signed; here something must be, because a carrier is in between.)
- **Replay**: nothing remembers an envelope; a reader that is offered the same envelope twice opens it twice
  (the app must be idempotent: the change log is; the mailbox dedupes by id).
- **No forward secrecy against a reader's static key**: whoever gets it opens every envelope ever made for
  it. The ephemeral secret of the envelope is thrown away right after sealing (it never leaves the
  WebCrypto key, which JavaScript cannot wipe).
- **A reader can re-seal** what it read for others (the signature stays valid) and a hostile reader that
  holds the content key can build envelopes with any inside it likes: the author signature is what stops it
  from putting words in the author's mouth.
- **A carrier can drop, delay or multiply an envelope** (a changed copy has another id and is a different
  envelope for carriers; it never opens). Removing slots or adding random ones costs readers nothing but the
  envelope.
- **Trust** is not decided here: `authorKey` and the readers' points must come from the trust layer. An
  endpoint compromise, a compromised random generator and quantum attacks on P-256 are out of scope.

## Mailbox

### State

```
Mailbox = { items: [ { id, day, text } ], delivered?: { day, per: { <device id>: <count> } },
            acknowledged?: [ { id, day } ] }
```

`items` are the carried envelopes in the order they came (the wire text is kept as it is); `delivered`
counts the new envelopes each other device brought on one day; `acknowledged` remembers ids a receipt
covered. Every operation is a pure function that returns a new value (or the very same object when
nothing changed, so a watcher is not woken for nothing); "today" and the sending device are parameters.
The state is plain JSON: `readMailbox` reads stored state back strictly (every envelope is read again, no
unknown member, nothing over a limit, tables keyed by device ids are rebuilt without a prototype, so a
device called `__proto__` or `toString` is a key like any other).

### Which envelopes are carried

An envelope with day `d` is carried today (`t`) when `-2 <= t - d < postDays` (so with the default 30
days the day 29 days back is carried, 30 days back is not; up to two days ahead is carried, three are
not: clocks differ). `addEnvelopes(mailbox, incoming, today, { from })` works in this order:

1. refuse with a code, changing nothing: `bad-day` (today is not a day), `bad-supplier` (`from` is not a
   device id), `bad-input` (`incoming` is not a list), `too-many` (more than `maxEnvelopes` in one call);
2. drop what is too old or acknowledged from the mailbox (and acknowledgements older than `postDays`);
3. for each incoming envelope: skip it if its id is already there or acknowledged, or its day is not
   carried; count it as `invalid` if it is not an envelope of this app with exactly that id and day (an
   object this package made or read is trusted, but only within the limits of this call: its size and its
   number of fan slots are remembered and checked against the limits of the mailbox, because it may have
   been read under larger ones; any other object is read again strictly);
4. **quota**: with `from` (another device brought them: a session or a file) at most `maxPerSupplier` (400)
   new envelopes per day from that device are taken, the newest days first (within a day in the order
   given), the rest is refused and counted (`rejected`); a further device beyond `maxSuppliers` different
   ones that day delivers nothing; envelopes sealed here have no `from` and no quota;
5. **size**: if the mailbox is over `maxEnvelopes` or `maxChars` the newest days stay, walking from the
   newest and stopping at the first envelope that does not fit; the order of what stays is kept. Every
   step above is linear: the days are bucketed (at most about 32 different days are carried).

`pruneMailbox` does steps 2 and 5. `keepNewest(mailbox, n)` keeps the newest n; `storeMailbox(write,
mailbox)` writes with a callback and, when a write fails, halves the mailbox (newest stay) up to 8 times
and tells how many envelopes did not fit (it never throws; the mailbox is nobody's data, only a carrier).

### Receipts

A receipt is `{ by, ids }`: the device `by` took these envelopes in. The package does not decide who may
acknowledge: `applyReceipts(mailbox, receipts, mayAcknowledge, today)` asks the app's predicate once per
`by` (a predicate that throws, or does not answer `true`, means no) and drops only what an allowed receipt
covers. Receipts that are malformed or not allowed are ignored and counted (`refused`). The covered ids
are remembered in `acknowledged` (with the envelope's day, or today for an id not held) so that a neighbour
that still holds the envelope cannot hand it back; the memory is capped by `maxAcknowledged` (newest days
stay) and forgotten with its day after `postDays`. At most `maxReceipts` receipts of at most
`maxReceiptIds` ids each per call (`too-many` otherwise). A receipt cannot do more than its signer may: the
app checks the signature and the right before it passes the receipt on. A compromised device that is
allowed to acknowledge can make carriers drop envelopes early (a denial of service, nothing more).
`readReceipts` reads receipts from untrusted data strictly (fresh copies).

### Check values

All values are base64url of the first 16 bytes of SHA-256 (22 characters, 128 bits), ids sorted by their
characters and each written `<n>:<id>`:

```
day check:      <appId>-postday:2|<n>:<day>|<number of ids>|<n>:<id>|<n>:<id>|...
mailbox check:  <appId>-postbox:2|<number of ids>|<n>:<id>|<n>:<id>|...
announced stand (not empty mailbox): 32 hex digits of the first 16 bytes of SHA-256 over
                <appId>-poststand:2|<n>:<fingerprint>|<n>:<mailbox check>
```

`announcedStand(fingerprint, mailbox)` is the fingerprint itself when the mailbox is empty. A device that
got an envelope announces another stand, so the devices that met it meet it again.

### Messages of the exchange

Three messages, each one compact JSON text, members in this order, read strictly (one spelling, bounded
before parsing: at most `max(pieceChars, maxEnvelopeBytes) + 512` characters):

```
{"m":"<appId>-post:2","t":"days","days":{"<day>":"<day check>", ...}}                 days in calendar order, at most 64
{"m":"<appId>-post:2","t":"ids","ids":["<id>", ...],"last":<true|false>}              at most 400 ids
{"m":"<appId>-post:2","t":"envelopes","envelopes":[{<envelope>}, ...],"last":<bool>}  each envelope as in "Wire text"
```

A piece is cut at `pieceChars` (12 000) characters and `maxPerMessage` (400) items; one envelope may exceed
the piece alone. There is always at least one `ids` and one `envelopes` message (an empty one carries
`last`). **Only the last message of a kind may be empty**: an `ids` or `envelopes` message with an empty
list and `last: false` is refused by the reader (an honest sender never makes one, and without the rule a
neighbour could keep a session open for ever with empty messages, each one costing a pass over the
mailbox).

### The session

1. Both devices send `days` (a check value per day of what they carry; `postStart` first drops what is too
   old).
2. On the other's `days` a device finds the days whose check values differ and sends the ids it holds of
   those days in `ids` messages (the last one with `last: true`).
3. On the other's last `ids` it sends the envelopes it holds of those days that the other did not list, in
   `envelopes` messages (the last with `last: true`), and on the other's `envelopes` it takes them in
   (`addEnvelopes` with `from` = the other device).
4. Both are done when each sent what the other lacked and got the other's last `envelopes` message.

The state machine is enforced: `days` once, `ids` only after `days` and up to the last, `envelopes` only
after the other's last `ids` and until its last; anything else is the refusal `unexpected`, an unreadable
message `bad-message`, more than `maxTheirIds` (4 000) announced ids `too-many-ids`, more than
`maxEnvelopes` offered envelopes in one session `too-many-envelopes`, and `bad-day` / `bad-supplier` as
above. A refusal changes nothing (the session and the mailbox are values); the caller ends the session. The
ids of the other side are kept in a chain and turned into a set once, so a neighbour that sends thousands of
one-id messages costs a linear amount, and the memory per session is bounded.

### Limits

| Limit             | Default           | Meaning                                                       |
| ----------------- | ----------------- | ------------------------------------------------------------- |
| `postDays`        | 30 days           | An envelope is carried for fewer days than this after its day |
| `maxEnvelopes`    | 2 000 envelopes   | Most in one mailbox, and most in one call or one session      |
| `maxChars`        | 8 000 000 chars   | Most wire characters in one mailbox                           |
| `maxPerSupplier`  | 400 envelopes     | Most new envelopes per day from one other device              |
| `maxSuppliers`    | 256 devices       | Most different other devices counted per day                  |
| `maxAcknowledged` | 4 000 ids         | Most remembered acknowledged ids                              |
| `maxReceipts`     | 256 receipts      | Most receipts one call takes                                  |
| `maxReceiptIds`   | 400 ids           | Most ids in one receipt                                       |
| `maxPerMessage`   | 400 items         | Most ids or envelopes in one message                          |
| `maxDays`         | 64 days           | Most days in a `days` message                                 |
| `pieceChars`      | 12 000 characters | A message is cut at this; one envelope may exceed it alone    |
| `maxTheirIds`     | 4 000 ids         | Most ids the other side may announce in one session           |

plus `maxEnvelopeBytes` and `maxFans` from the envelope. `resolvePostLimits` takes a partial override of
own, safe, non-negative integers only; anything else keeps the default. Where several apps share one
mailbox store, the app id keeps them apart: ids, check values and every message carry it.

### What the mailbox protects, and what it does not

- Memory and work per message, per session and per mailbox are bounded by the limits above; a hostile
  neighbour (a trusted device that misbehaves) cannot fill the mailbox with junk in one session (the quota
  per device and day) and cannot make a device spend more than linear work in the size of what it holds.
- A carrier sees ids, days and sizes, and which neighbour brought what; it learns nothing from the
  contents (see "What the envelope hides").
- Not protected: a neighbour can still use up its own quota with junk (400 a day) and so push older real
  envelopes out when the mailbox is full; a device that is allowed to acknowledge can drop envelopes early;
  a carrier can keep an envelope and hand it on late (the day in it still ends it after `postDays`);
  nothing proves to the sender that an envelope arrived (receipts are the app's).

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
collection, id, kind, check[, prev]}`, a `redacted` change counting as `set`; `prev` (the link of the
  previous change of the same device) is present exactly when `seq` is above 1 (`signing-text.json`).
- Link of a change (what the next change of the device carries as `prev`, and what a `stand` carries
  as a tip): `base64url(SHA-256(UTF-8(canonical({v: 2, device, seq, clock, collection, id, kind, check[, prev]}))))`,
  that is the signed text WITHOUT the marker and `set`; an erased change has the link it had (`chain.json`).
- Signature: ECDSA P-256 / SHA-256, 64 bytes (r, s big-endian, 32 bytes each), unpadded base64url,
  **low-s only** (s at most n/2). A signer must normalise; a verifier must refuse a high s.
- Check code of a device: `check-code.json`.
- `verification.json` holds one public key (a throw-away made for that file) and one signed change
  that every implementation must accept, with the variants it must refuse.
- `chain.json` holds a second throw-away key and the hash chain: three signed changes (the second with `prev`),
  their links, the signed erased version of the second, a `stand` with `tips`, a stand with a changed tip,
  two signed versions of one number (a double signature: what `proveEquivocation` proves) and the
  tampered variants that must be refused or not proven.
- Session and encrypted file (`session.json`, `file.json`): every text is the exact JSON spelling
  documented in "Wire format: end-to-end layer" (a reader accepts only that spelling); fields in hashed and
  authenticated texts are length-prefixed by their UTF-8 byte length; the order of two device ids is the
  byte order of their UTF-8 forms; ECDH secrets are the 32-byte X coordinates; the session nonce is the
  counter (four zero bytes, then 8 bytes big endian). `session.json` holds throw-away private keys (JWK),
  both hellos, the transcript text, the four secrets, the salt, the two keys and four messages; `file.json`
  holds one file with the header text, the salt, the secret input and the key. A port derives the keys
  from the JWKs and must reproduce every hex value and decrypt every message.
- Envelope and mailbox (`envelope.json`, `mailbox.json`): every text is the exact JSON spelling documented
  in "Wire format: envelope and mailbox"; every variable field of a hashed, derived or signed text is
  length-prefixed by its UTF-8 byte length; the fan slots are AES-GCM with a zero nonce under a key from
  HKDF (salt = SHA-256 of the header text, info names the reader's point); the author signature is over
  the `envsig` text. `envelope.json` holds the author's PUBLIC signing point and two readers' throw-away
  private keys (JWK), the id's hashed text, the header text, the salt, each reader's key encryption key,
  slot index and content key, the inside text and the signature, and variants that must be refused with
  the code that is written down; `mailbox.json` holds three envelopes without crypto content, the check
  value texts with their hashes, and one message of each kind. A port derives the keys from the JWKs and
  must reproduce every hex value and open the envelope.
