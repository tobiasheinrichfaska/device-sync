# Read scope: who may read which log (design proposal)

Status: **proposal, nothing built.** This document is the basis for the work; it changes no code.
Every statement about the present state names the file or function it comes from. Statements that
were read from the code but not run are marked _(read, not run)_; guesses are marked _(guess)_.

## 1. Problem

Picture an app where

- **members** write data about themselves,
- a **supervisor role** may read the data of all members,
- other **members must not read each other's data**,
- but all of them use the same devices as _carriers_: a member's data should be able to travel to the
  supervisor over a colleague's device.

The package today has two separate tools and a gap between them:

- the **change log** (`log` layer) replicates a whole collection between trusted devices;
- the **envelope** (`core/envelope.ts`) and the **mailbox** (`post` layer) let third devices carry
  content they cannot read.

What is missing is a basic building block: _per log (or collection), say who may read it, and make
sure a device without that right neither receives the data nor can read it._

## 2. Present state

| #   | Statement                                                                                                                                                                                                                                                  | Evidence                                                                                            |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| P1  | A replica holds one log of the changes of **all** devices and forwards it to every device that lacks something.                                                                                                                                            | `Replica.log` ("Every change known here, from all devices; forwarded ...") in `src/log/types.ts`    |
| P2  | The answer to a `stand` is "everything the other lacks"; the only filters are `signedOnly`, erased changes without their deletion, unmet `knew`, and the size budget. **No filter by reader exists.**                                                      | `answerFor`, `prune` in `src/log/protocol.ts`                                                       |
| P3  | Numbering is per device (not per collection) and **gapless**: a change is applied only when `seq` is the known `seq` + 1, otherwise it is held. A device whose changes are filtered by collection would therefore leave gaps that block all later changes. | `docs/wire-format.md` "Version vector (stand)"; `merge` in `src/log/merge.ts`                       |
| P4  | A signed head binds `device, seq, clock, collection, id, kind, check, prev` and the data set `set`. The head is **in clear**; the content (`fields, knew, time, by`) is bound only through `check`.                                                        | `changeHead` in `src/log/check.ts`; `changeSigningText` in `src/log/signing.ts`                     |
| P5  | `check` is `base64url(SHA-256(canonical({fields, knew, time, by})))`: an **unkeyed** hash of the content.                                                                                                                                                  | `changeCheckValue` in `src/log/check.ts`; `checkValue` in `src/core/canonical.ts`                   |
| P6  | A change can travel **without content**: `redacted` keeps the head, `check`, `prev` and `sig` and drops the content, so numbering and the hash chain stay intact. But it is allowed only beside its record's final deletion.                               | `redacted` in `src/log/merge.ts`; `redacted-without-deletion` in `src/log/signing.ts`; `prune` (P2) |
| P7  | A `stand` carries the vector (per device the highest number held) and `tips` (links). Both are visible to every session partner.                                                                                                                           | `startSession` in `src/log/protocol.ts`; `tipsOf` in `src/log/chain.ts`                             |
| P8  | The signature names a **data set** (`dataSet`); a change signed for one data set does not verify in another.                                                                                                                                               | `JudgeOptions.dataSet`, `changeSigningText`                                                         |
| P9  | A `KeySource` is asked `keyFor(device, acceptedSoFar)` with the replica being judged. The ready-made `deviceKeySource` reads the **device list from that replica** (a reserved collection of the same log).                                                | `KeySource` in `src/log/signing.ts`; `deviceKeySource` in `src/trust/devices.ts` _(read, not run)_  |
| P10 | Devices carry an opaque `role` and two public keys (`sig`, `dh`); the package hard-wires no role. Who may vouch is a strategy (`vouchRoles`, ...); "which person a device belongs to" is left to the app.                                                  | `DeviceEntry`, `Voucher` in `src/trust/types.ts`; `docs/architecture.md`                            |
| P11 | An envelope hides sender, readers, their number (up to padding), content and signature from a carrier; it shows size, day, id and who brought it. Up to 64 reader slots; content at most about 8 250 bytes.                                                | `docs/wire-format.md` "Envelope"; `ENVELOPE_LIMITS` in `src/core/envelope.ts`                       |
| P12 | The envelope carries a `channel` (a device-id-like text the app chooses) inside the encrypted content, signed by the author. The package does not look inside the body: "the app puts its stand and changes in it".                                        | `EnvelopeSealParams.channel`, `isDeviceText` in `src/core/secure.ts`; `docs/architecture.md`        |
| P13 | A mailbox keeps envelopes for `postDays` (30) and trims by count and size; the day exchange between two meeting devices moves what the other lacks.                                                                                                        | `src/post/mailbox.ts`, `src/post/exchange.ts`; `docs/wire-format.md` "Mailbox"                      |
| P14 | **Group keys do not exist**; the architecture notes say removal must rotate them once an encryption layer for groups exists.                                                                                                                               | `docs/architecture.md` ("Trust derivation": "group keys do not"); `CLAUDE.md` Known Limitations     |
| P15 | `fingerprint(replica)` hashes everything a person would see in the replica; a session compares it between both devices.                                                                                                                                    | `fingerprint` in `src/log/protocol.ts`                                                              |
| P16 | There is **no code anywhere** that glues a log exchange into envelopes; the documents describe the intent ("The stand and changes of a log exchange are part of the content (`body`)").                                                                    | `docs/wire-format.md` "Inside and signature"; search of `src/` _(read, not run)_                    |

Consequence: today a member's device that carries data for the supervisor through the normal session
**holds the plaintext of everybody** (P1, P2). The envelope can carry opaque content, but only as one-way
messages: a gap in a gapless log cannot be repaired by a carrier that cannot read it (P3, P16).

## 3. Requirements

- **R1** A device without the right to read a scope never receives its content and cannot read it.
- **R2** A device without the right still may _carry_ it (store and forward) for the readers.
- **R3** The set of readers comes from the trust layer plus an app rule (a strategy like `Voucher`), never
  from a value a device writes about itself. (P10: `listDevices` shows raw entries, "never authorization".)
- **R4** Adding a reader later gives that reader the history.
- **R5** Removing a reader stops future data; what it already holds cannot be recalled. This must be said
  plainly, not hidden.
- **R6** The log stays gapless and the hash chain stays verifiable by every reader.
- **R7** The package stays app-independent (no roles, no names), pure where it is pure, errors as codes.
- **R8** Small steps: each step has its own tests and can be merged alone; format changes are explicit.

## 4. Options

### A. One replica per read scope

Each scope (for example "all data of member M") is its **own replica**: its own log, own numbering, own
vector, own `dataSet`. Devices that may read the scope exchange it; others never see it. The scope id is
used as `dataSet` (P8) and as the envelope `channel` (P12).

- Non-readers never hold content **and no metadata** of the scope (no numbers, clocks, ids, counts).
- Carrying: the author seals its new changes (and its stand) for the readers as an envelope with
  `channel = scope`; third devices carry it (P11, P13).
- The device list stays one trust log known to all trusted devices; scope replicas are judged with a
  `KeySource` that reads the device list from that one trust replica instead of from the scope replica
  (P9). _(guess: a small adapter that ignores `acceptedSoFar` and asks `deviceKeySource` with the trust
  replica; to be shown by a test)_

### B. One shared log, content sealed per scope

Everyone holds and forwards one gapless log. The content of a change (`fields, knew, time, by`) is
encrypted under a **scope key** that is wrapped for each reader's `dh` key (like the envelope's slots).
Heads stay visible, so numbering and chain stay intact for everybody (P3, P6).

Needed (all new): a sealed-content member in the change; `check` over the **ciphertext**, because the
present `check` is an unkeyed hash and would let a non-reader confirm guesses about small values (P5);
parser, validator, merge, judging and redaction changes; format version `:3` with new vectors; key
wrapping, key versions, rotation and key hand-over to new readers (P14); hiding `collection`, `id`,
`kind` is the app's job (pseudonymous ids) and `device, seq, clock, vector, tips` stay visible (P4, P7).

### C. Filter in the exchange only

The sender leaves out changes the peer may not read (hook next to `signedOnly`, P2).

- Breaks gaplessness (P3): later changes of the same device are held for ever. Filling the gaps with
  stand-ins (like `redacted`, P6) is Option B without the encryption, and the stand-ins carry the metadata.
- Cannot satisfy R2: a carrier would have to hold the plaintext to forward it, or hold nothing and forward
  nothing. It only works for "direct sessions between readers".

### Comparison

| Criterion                             | A: replica per scope                                                           | B: sealed content, one log                                                                   | C: filter in the exchange                          |
| ------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| What a non-reader device sees         | Nothing of the scope; an envelope (size, day, id) if it carries                | Heads of every change (device, number, clock, collection, id, kind), all vectors, ciphertext | Plaintext if it carries; else nothing and no carry |
| Non-reader keeps data at rest         | Only envelopes, which expire after `postDays` (P13)                            | All ciphertext for ever, on every device ("store now, decrypt later" if a key ever leaks)    | Plaintext                                          |
| Add a reader                          | Readers hand over the scope log in a session; no key work                      | Wrap every key version for the new reader; the ciphertext is already everywhere              | Plain catch-up                                     |
| Remove a reader                       | Stop exchanging; nothing to rotate                                             | Rotate the scope key for new changes; old content stays readable to the removed reader       | Stop exchanging                                    |
| Gaps repaired by a non-reader carrier | No: gap repair needs a reader or a repeat of the envelope within its lifetime  | Yes: normal forwarding of the gapless log                                                    | No                                                 |
| Trust layer                           | Reader set derived from trust plus an app strategy; shared device list         | Same, plus key wrapping to `dh` keys of the derived readers                                  | Same                                               |
| Envelope and mailbox                  | Used as they are (one-way transport of sealed sync messages)                   | Not needed for carrying; still useful for hand-over                                          | Not usable for carrying                            |
| Size and work                         | N scopes mean N replicas and N sessions per meeting                            | One replica; one decryption per read change                                                  | One replica                                        |
| Tests and vectors                     | New: reader derivation, scope key source, sync over envelopes, three-role case | New: wire format `:3`, key management, rotation, new parser vectors, new fuzzing             | Hook tests only                                    |
| Wire format                           | **Unchanged** (log, session, envelope as they are)                             | New change format, version bump                                                              | Unchanged, but wrong result                        |
| Meets R1 and R2                       | Yes (carrying by envelopes)                                                    | Yes, with the metadata caveat                                                                | No                                                 |

## 5. Recommendation

**Start with A.** Reasons:

1. It needs **no change to the wire format** of the log, the session or the envelope (R8): it uses the data
   set binding (P8) and the envelope channel (P12), which exist.
2. It gives the strongest answer to R1: a non-reader holds neither content nor metadata of the scope, and
   what it carries expires with the mailbox (P13).
3. It has **no key rotation problem** (P14): there is no scope key. Removal means "stop exchanging",
   which is honest about R5.
4. It reuses the envelope and mailbox that were built for exactly this carrier case but have no user yet.

Honest weaknesses of A, to be accepted or solved in the steps below:

- **Gap repair** (P3, P16): an envelope is one-way. If a carrier loses one, a reader repairs the gap in its
  next direct session with another reader; a non-reader cannot help. Envelopes are repeated within their
  lifetime by the mailbox exchange (P13), which helps in practice. _(open question 1)_
- **Many scopes** mean many replicas per supervisor device (one per member). Fine for tens, to be measured
  for thousands. _(open question 3)_
- The **device list** (names, roles, keys of all devices) is visible to every trusted device.
- "Which devices belong to member M" is an app fact (P10); the package takes it as a strategy.

Keep **B** as a later extension if one gapless log with third-party gap repair turns out to matter more than
the metadata and at-rest costs. The two do not exclude each other: a scope could be a replica of its own
whose content is _also_ sealed.

## 6. Threat model (for option A)

| Who                                    | Sees                                                                                                             | Does not see                                                                                    |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Carrier** (a member's device)        | Ids, days, sizes of envelopes it holds; which neighbour brought them; the device list                            | Author, readers, number of readers (up to padding), content, which scope                        |
| **Colleague** (a member, not a reader) | Same as a carrier; the device list including roles; its own scopes                                               | Any other member's scope: no content, no numbers, no clocks                                     |
| **Remote reader** (the supervisor)     | Everything in the scopes it may read, who wrote what (the author is signed inside, not deniable) and when        | Scopes it may not read                                                                          |
| **Removed reader**                     | What it already holds                                                                                            | Anything sent after the removal is derived (it is no longer a recipient)                        |
| **Compromised reader device**          | All scopes that device may read, and, with the envelope's static-key weakness, every envelope ever sealed for it | Other scopes; (the envelope has no forward secrecy against a reader's static key, see P11 docs) |
| **Network or relay**                   | Metadata of transport (as before: sizes, timing, device ids)                                                     | Content                                                                                         |

Not changed by this design: the weaknesses already listed in the Known Limitations of `CLAUDE.md` (the
envelope author is not deniable, no replay protection, no forward secrecy against a static key, a carrier may
drop or delay).

## 7. Open questions

1. **Gap repair for carried scopes.** Is "repeat within the envelope lifetime, plus repair in the next direct
   session between readers" enough, or is a reader-to-reader request/answer over the relay part of the
   building block?
2. **Where the strategy lives.** A `Readers` strategy next to `Voucher` (pure, in `trust` or a new `scope`
   layer)? Inputs: the derived trust and the app's own person-to-device facts.
3. **Scale.** How many replicas can a device hold and exchange per meeting (measure with a seeded test, as in
   `tests/log/performance.test.ts`)?
4. **Scope id format.** It must be accepted both as `dataSet` and as an envelope `channel` (`isDeviceText`:
   non-empty, bounded length, no forbidden characters).
5. **Reader change.** On adding a reader, who hands over the history, and is a full session enough or does it
   need the `sealFile` path for large logs?
6. **Fingerprint** (P15) is per replica, so it stays comparable between readers of the same scope; confirm
   that the session outcome treats a scope replica like any other.
7. **Whether B is ever needed** (one gapless log repaired by non-readers) and what metadata is acceptable then.

## 8. Plan: small pull requests

1. **This PR:** the document. No code.
2. **`scope` readers (pure):** a `ReadScope` descriptor and a `Readers` strategy with a derivation from the
   trust layer (`readersOf`), ready-made strategies analogous to `vouchRoles`; tests with three roles
   (member, colleague, supervisor), removal and re-admission by new device id.
3. **Key source for scope replicas:** an adapter that judges a scope replica with the keys of one trust
   replica; tests: scope changes verify, a change of another scope fails (`set` binding), a removed device
   stays checkable but is no reader.
4. **Sync over envelopes:** pure helpers that seal a stand/changes message for the readers of a scope with
   `channel = scope`, cut it to the envelope size, and on opening check that the channel is the scope the
   receiver expects; tests at the size boundaries and with wrong channels.
5. **Three-device integration test:** member A writes, colleague B only carries (its replicas hold nothing of
   A, checked), supervisor S receives; a gap is repaired by a direct session; a removed reader gets nothing
   new.
6. **Documents:** wire notes (what is sent in the envelope body), `docs/architecture.md`, `FEATURES_REQUIRED.md`,
   and the Known Limitations.
7. **Decision on B** after steps 2 to 5 have shown which of the weaknesses of A hurts.

Each step ships with its own tests. None of them changes an existing wire format.
