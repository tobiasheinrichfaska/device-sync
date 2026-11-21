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

- arrays: `[` members joined by `,` `]`, order kept; members that are not JSON values (undefined,
  functions) become `null`;
- objects: members whose value is `undefined` are dropped, the remaining keys are sorted by UTF-16 code
  unit (default JavaScript sort, so `"10"` sorts before `"9"`), each written as
  `JSON.stringify(key):canonical(value)`, joined by `,` inside `{` `}`;
- everything else is `JSON.stringify(value)`, or `null` when that gives nothing (top-level `undefined`).

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
tests in `tests/log/` pin the behaviour. Not yet built: the exchange protocol (chunking, catch-up
messages); signatures are described in the section "Signatures" below.

## Change

One entry of a device's log. Only its author creates it; everybody forwards it.

| Field        | Type                          | Meaning                                                                                               |
| ------------ | ----------------------------- | ----------------------------------------------------------------------------------------------------- |
| `device`     | string                        | Author's device id (random, never derived from a person)                                              |
| `seq`        | integer, 1, 2, 3 ...          | Per-device number, **gapless**                                                                        |
| `clock`      | integer                       | Lamport clock at creation (own clock + 1, raised to the highest clock seen)                           |
| `collection` | string                        | Name of the set of records                                                                            |
| `id`         | string                        | Record id                                                                                             |
| `kind`       | `set` / `delete` / `redacted` | see below                                                                                             |
| `fields`     | object (optional)             | Only for `set`: field name to value. Values are any JSON (lists and objects count as one value)       |
| `knew`       | object (optional)             | Author's version vector, shortened (see below)                                                        |
| `time`, `by` | number, string (optional)     | Author's own time (ms since 1970) and a label; history only, never used to order writes               |
| `check`      | string (optional)             | `changeCheckValue(change)` = `checkValue({fields, knew, time, by})`; set by the signer, kept on erase |
| `sig`        | string (optional)             | Author's signature over the head and `check`; kept on erase                                           |

`kind`: `set` writes the named fields (fields not named keep their value); `delete` is the final
deletion of the record; `redacted` is a former `set` whose content was erased because the record was
deleted. A redacted change keeps `device`, `seq`, `clock`, `collection`, `id`, `check` and `sig`
(`check` is computed at that moment if the author had none) and drops `fields`, `knew`, `time`, `by`,
so numbering stays gapless and the head stays checkable. A `set` that arrives for an already deleted
record is stored redacted from the start.

## Version vector (stand)

`{ [device]: highest seq received without a gap }`. A change is applied only when its `seq` is exactly
the known `seq` + 1 for its device and its `clock` is at most own clock + `MAX_CLOCK_JUMP`
(10 000 000); otherwise it is **held** (returned in `held`, not stored) until it can be applied.
Duplicates and already known changes are ignored; merging is idempotent and independent of order.

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
(`a.knew[b.device] < b.seq` and `b.knew[a.device] < a.seq`); a missing `knew` means no conflict.

## Conflict notice

A pure function of the log, so devices holding the same changes find the same notices. For one field
of a live record: the writes no other write knew (a later write of the same device, or a write with
`knew[device] >= seq`, knows it) are the heads; those that are concurrent with another head clash; a
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
