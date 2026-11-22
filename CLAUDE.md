# CLAUDE.md — device-sync

> Workspace-wide conventions (language, git, build, architecture, testing, collaboration):
> [`c:\skripte\private\general stuff\CLAUDE.md`](../../private/general%20stuff/CLAUDE.md)

---

## Project overview

Shared, app-independent technology for secure device-to-device data sync in Tobias' offline-first web
apps: a signed gapless change log per device, end-to-end encrypted transfer, device trust and
invitation, a relay client and Web Push helpers. Created 2026-11-21 (decision: extract it from the
apps that carry copies of it). **Status: 0.0.0, core layer partly implemented, log layer incl. signing and exchange protocol (parsers, session, fingerprint), not
published to npm. GitHub repo made public on 2026-11-21 (Tobias' OK); the README carries a "Not reviewed" notice until the security review is done.**

**The inventory of the existing implementations, the measured drift between them and the plan (names
private projects) live in the private companion repo `device-sync-privat`**
(`private/device-sync-privat/docs/`). Never name those projects in this public repo
(`tests/coupling.test.ts` fails if they appear).

**Platform:** browser (and WebView2); no Expo/React Native
**Language:** TypeScript
**Architecture:** layers `core`, `log`, `trust`, `post`, `relay`, `transfer`, `push`, `browser`
(`docs/architecture.md`). Pure layers take clock and randomness as parameters. App things are
parameters, hooks or strategies (`appId`, limits, who may vouch, right to write, hold-back hook).
Errors are codes, not sentences.

## Key rules

- **Public repo in the end (AGPLv3 + commercial):** no app data, no real names, no private project
  names in files or git history. The first commit is neutral.
- **The repo is public (since 2026-11-21, Tobias' OK), the work is in the open.** Nothing is published to
  npm or tagged for use, and the README's "Not reviewed" notice stays, until Tobias says so after a
  security review (threat model, fuzzing of the strict parsers, independent pass). Never commit keys
  other than throw-away test keys; commit messages follow the same no-private-names rule as files.
- Crypto code changes only with the tests that guard it; ported code keeps the tests of both source
  implementations (their union).
- The other apps are not converted from here; they get a note to check the package.

---

## Project Directory

| File/Folder                                                      | Purpose                                                       |
| ---------------------------------------------------------------- | ------------------------------------------------------------- |
| `CLAUDE.md`                                                      | Project documentation and conventions                         |
| `README.md`                                                      | Short description, install, license section                   |
| `FEATURES_REQUIRED.md`                                           | Critical paths (target)                                       |
| `docs/architecture.md`                                           | Layers and parameters (plan)                                  |
| `manual_tests/`                                                  | Human-tester instructions (README only, no UI)                |
| `src/index.ts`                                                   | Public entry: status and re-export of the finished layers     |
| `src/core/` (`encoding`, `canonical`, `json`, `markers`, `keys`, `signature`, `index`) | Core layer, first part: base64url, canonical JSON (refuses lone surrogates), duplicate-key scan, markers, device keys, length-prefixed check code, low-s `signText`/`verifyText` |
| `tests/core/`                                                    | Unit tests of the core layer (`review2`: low-s signatures, check code) |
| `src/log/` (`types`, `vector`, `check`, `chain`, `validate`, `logCache`, `recordIndex`, `merge`, `replica`, `signing`, `limits`, `parse`, `protocol`, `index`) | Log layer (pure): change, version vector, merge (causal hold, repeated passes), `validate` (shared strict checks of names, values, limits for the parser and for local writing; prototype-less dictionaries), `recordIndex` (per-record index of the log: last write per device and field, log positions), redaction, conflict notices, history, undo; signing and judging of changes (`signing`: signed text with `prev`, `signChange`, `judgeChange(s)`, `readChanges` (incremental rounds, `KeySource.selfVerifying`), erased-change fixpoint in linear time, hooks); hash chain (`chain`: `heldIn`, `tipsOf`, `tipConflict`; every change after the first carries `prev`, a `stand` carries `tips`); exchange protocol: `limits` (`LIMITS`, one object), `parse` (strict `parseChange`/`parseVector`/`parseSyncMessage`), `protocol` (`pieces`, `fingerprint`, session `startSession`/`onSyncMessage`/`receive`/`receiveJudged`/`outcome`) |
| `src/trust/` (`types`, `ids`, `voucher`, `wire`, `known`, `derive`, `devices`, `meeting`, `invitation`, `index`) | Trust layer (pure): device list as records of one reserved log collection (`addDevice`, `renameDevice`, `setDevicePrivate`, `removeDevice`, `listDevices`), trust derived not stored (`derive`: one order-independent engine with entry index, potential trust, rank, removals in rank-then-id order, key consistency among the vouchers that were not removed; `computeTrust`, `deviceStatus`, `deviceKeySource` as a `selfVerifying` `KeySource` for `readChanges`; no write cut-off: a removed device stays checkable), voucher strategies (`vouchAll`, `vouchRoles`, `vouchAnyRole`), meeting code (signed, 120 s), invitation + reply + HMAC proof, list of devices met in person, `newDeviceId` |
| `tests/trust/`                                                   | Trust tests: `devices` (cases of both earlier implementations), `meeting`, `invitation` (tamper sweeps, boundaries, two apps), `fullstack` (invitation to judged changes), `fuzz` (seeded, 3500 inputs per parser), `ids-known`, `docs`, `helpers`, `order` (400 random scenarios, identical trust for every delivery and creation order), `review4` (round 3 part B: T1 removal, T2 keys, T3 local decisions, T4 linear, `checkCode` groups), `review5` (round 3 third pass: N3 compromised voucher with three proofs of concept, N9, N10, removed device stays checkable and the N2 scenario converges, N4 with trust, `selfVerifying` safety), `reference` (3200 scenarios of the derivation against an independent reference written from the rules), `chainscale` (N5: 1600-device chain) |
| `tests/vectors/`, `tests/vectors.test.ts`                        | Committed JSON test vectors for other implementations (canonical form, signing text, check code, one verification vector with a throw-away key) and the test that runs them |
| `tests/log/`                                                     | Log tests: `basis` and `typed` (cases of both earlier implementations), `properties` (seeded random schedules), `protocol` (session, pieces, fingerprint, refusals), `parse` (strict reading, limits, seeded fuzzing, depth bombs), `hardening` (review findings: unsafe names, unchecked local writes, clock-jump passes, invented `knew`), `review2` (second half of the security review: batch judging, equivocation, memory before the signature check, `signedOnly`, reasons, `allowFinalDelete`, one stand/done, `knew` heads), `review3` (third review, part A: partial sessions and limits that cut instead of refusing, erased change only with an applied deletion, `own-history` after the signature, `signedOnly` and erased changes, linear piece processing, `Map` counts, erased members, index cache, `neverErase`), `review4` (round 3 third pass: N4 hash chain and `tips`, 3000-run honest simulation, N6 erasure chain in linear time), `performance` (no quadratic merge), `exchange` (full stack with real signatures, 120 seeded schedules, forgeries), `fuzz` and `helpers` (generators) |
| `docs/wire-format.md`                                            | What the core and log layers put on the wire, incl. the exchange: messages, limits table, strictness rules |
| `tests/coupling.test.ts`                                         | Guard: no private project names, only own imports             |
| `scripts/fix-declarations.mjs`                                   | Rewrites `.ts` imports in the emitted declarations            |
| `package.json`, `tsconfig.json`, `tsconfig.build.json`, `vitest.config.ts`, `.prettierrc.json`, `.prettierignore` | Toolchain (`"private": true` against an accidental npm publish) |
| `.github/workflows/tests.yml`                                    | Check "Tests": typecheck, format, tests, build                |
| `.gitattributes`, `.gitignore`                                   | LF line endings; ignore rules                                 |
| `LICENSE`, `LICENSE_COMMERCIAL.md`, `CONTRIBUTING.md`            | AGPLv3 + commercial                                           |

---

## Data Model

No persisted data of its own. The wire formats (change, envelope, file, session) will be documented
next to their code with test vectors; no factory defaults.

## Tests

```bash
npm install
npm run typecheck
npm test
npm run format:check
```

## Known Limitations

- Only the first part of the core layer (encoding, canonical JSON, markers, device keys, check code) and the log layer (change model, merge, redaction, notices, history, undo, signing, exchange protocol with strict parsers) exist; the trust layer (device list, derivation, meeting code, invitation) exists; the end-to-end encrypted session, post, relay, transfer, push and browser are not implemented.
- Exchange: pieces are meant to arrive in order. A reordered session may not take everything but never corrupts a replica, and the next session fills the gap (`tests/log/order.test.ts`); in `receiveJudged` the pieces before the last may come in any order. `receiveJudged` judges each piece as it arrives and holds verified changes and changes whose author cannot be checked yet, bounded by `maxSessionChanges` and `maxSessionChars` in all; what is still unverifiable after the key-learning rounds is cut at `maxPendingChanges` and must come again. Limits never refuse: a sender cuts its answer to a prefix of its own log (`more: true`), a receiver ends the reading (`Session.truncated`) and takes what it verified, the next session continues (partial sessions; `outcome().complete` is false meanwhile; the judging state of a session is extended in place, so a `Session` value is never fed twice). Only hostile input is a refusal. The log itself is unbounded: an app bounds a flooding member with `mayWrite` and the `quota` hook (default unlimited). A stand is answered only with signed changes (`signedOnly`); a second `stand` or `done` ends the session. The fingerprint (128 bits) is a consistency check, not a proof against a peer that lies. Apps pass their own device id pattern (`deviceId` option); the default is permissive. A transport should cap message size before the parser; `parseSyncMessageText` refuses text over twice `maxMessageChars` itself.
- Performance: a batch merge is linear (6000 changes to 6000 records in about 15 ms; `tests/log/batch.test.ts`); notices and final deletions use a per-record index of the log (`recordIndex`), so 8000 writes of one device to a 40-field record merge in well under a second and 20000 deletions likewise (`tests/log/performance.test.ts`). Every merge still copies the log and the collection of the touched records (O(records) per local write: about 11 ms at 20000 records in one collection); the index is kept per log array (a log rebuilt by hand is indexed again on first use). Pairs of heads of one field are compared pairwise, so a field written by thousands of different devices is quadratic in the devices. Replicas are immutable values: the per-log caches are checked against array length and last element, a middle entry changed in place is not noticed. Verifying 12000 new signatures costs about 2 s of crypto in any case (`tests/log/review3.test.ts`); a repeat of a change the replica already holds is not verified again.
- Conflict notices are derived from the log (a change against the earlier implementations, which built them incrementally and could differ between devices); a notice lists the concurrent heads, not every superseded write.
- The "hold back until approved" hook exists only as a type (`ApprovalHook`) and a marked spot in `merge`.
- The soft-delete field name `deleted` is reserved. Local writing refuses what the parser refuses (names, values, limits); `knew` names only the unresolved concurrent heads of the fields, so a field written by many devices one after another stays writable; more than `maxDevices` unresolved concurrent heads give `too-many-devices` until someone resolves them.
- A change that names a `knew` the receiver never reaches (a liar, or a change whose dependencies were lost) is held for good, with everything later from its author; only its own author is blocked. Held changes are not stored: the sender must send them again. `merge` takes `set`/`delete` changes without `knew` as held; the parser refuses them. Canonical JSON throws `TypeError` for anything that is not plain JSON (a top-level `undefined` is still `null`).
- Trust: the invitation text carries no signature; the inviter's keys in it are only as trustworthy as the channel (compare check codes; use `checkCode(..., groups)` with 8 or more groups where the code is the only protection against a modified link). **Removal ends a device's standing as a voucher and as a device that can be introduced through the chain; the device stays `checkable`, so its signed changes (earlier AND later) still verify and are accepted by the signature layer. This layer does NOT revoke a removed device's ability to write** (the automatic write cut-off, `lastSeq`, the verdict `ignored` and `KeySource.standing` were taken out: a device-local cut-off made honest devices disagree and block each other). An app stops exchanging with a removed device at the transport, treats data authored by removed devices as untrusted at presentation (`deviceStatus`), restricts writes with `mayWrite` / `allowFinalDelete` (hooks that look at state can answer differently on two devices) and, once the encryption layer exists, rotates the group keys on removal. A removed id stays removed: re-admission is a new device id (`addDevice` refuses `removed`; `removed: false` is never a way back). Removals are processed in a fixed order, rank (distance from the met devices) then device id; a removed device removes nobody; two devices of equal rank that remove each other are decided by the smaller id (deliberate, deterministic). Any voucher can remove the devices it can reach (inherent in the voucher strategy: choose `vouchRoles`). A removed device's writes carry no authority for key conflicts, vouching or removals, so a compromised voucher cannot neutralise its own removal or poison other entries once it is removed; while it is NOT removed, a voucher that writes other keys into another entry still makes that entry untrusted through the chain (`key-conflict`) and conflicting relay ids are dropped. A voucher can pre-occupy a future device id with its own keys (`addDevice` of the real device then answers `other-keys`), and `listDevices` shows raw entries (self-written roles included): never authorization. Potential trust only grows: a voucher that is later given another role stops vouching, but what it introduced earlier stays. `canVouch` is asked when a device joins and when its entry changes (answer from the entry), the number of rounds is bounded. The derivation is linear (400-device chain: 7 ms warm), every new replica state is derived again (index per log array); `readChanges` of a 1599-change chain takes about 0.6 s because `deviceKeySource` is `selfVerifying` (the key source is asked against the replica plus the waiting changes, never one claiming the receiver's own id). `addDevice`/`removeDevice` decide on this device's own log as judged (no signature is checked again). Not ported: the 'confirmed role' flag of one earlier implementation, the device lock after days without contact, relay/session wiring. Parsers are stricter than the earlier ones (one spelling only, unknown members refused).
- Trust, accepted: the meeting code carries role and name as self-declaration, has no recipient bound and can be relayed by a third party within its 120 s window. The single use of an invitation is not enforceable offline (two replies to one code can both be taken; the damage is one more device of that role): an app keeps a ledger of used invitations; a removed device re-enters only through a fresh invitation with a new device id. A vouching device (an administrator) can still choose any name or role for an entry. A removal can only be undone by a new device id, never by writing `removed: false`.
- Equivocation (one device number signed twice with different content) is seen with a hash chain: every change after the first carries `prev` (the check value of the same device's previous change, in the signed head, kept by an erased change) and a `stand` carries `tips` (per device the link of the change at its vector position). Two devices holding different versions of one number refuse each other at the first stand (`forged`, `equivocation`, `refusalDevice`), also after the author was removed; a successor whose `prev` names another version is `equivocation` too. A version that differs only in the head (clock, collection, id) and not in the content has the same link: only the signed-text comparison (both versions in one replica) sees it. A device that took the harmless version keeps refusing the erased write of the other (`redacted-without-deletion`); the app reacts to the reason code (stop trusting the author). A device restored from an old backup gets `own-history` (only for a change that really carries its own signature) and must re-enrol with a new device id. Format change: the signed text of a change with `seq` above 1 contains `prev`; `tests/vectors/` were updated on purpose.
- A partial session cut (`more`) can delay an erased change until the next session; an erased change without any deletion in sight in a partial session waits instead of being refused. The fixpoint that decides which erased changes count is found with one linear pass over the dependencies plus a few merges.
- A final deletion is judged false unless the app passes `allowFinalDelete`. Signatures are low-s only (a high-s twin is refused); the check code carries about 66 bits. JSON texts with duplicate keys and strings with lone surrogates are refused (cross-language rules in `docs/wire-format.md`, vectors in `tests/vectors/`).
- Public but unreviewed: the README says so; no npm release and no tag for use before the security review.

_Last updated: 2026-11-22 (security findings H1, H2, H6, H4b, M3-M5, N1-N4, N6, N7, X1, L1-L4, L6, L7, L9, IDX fixed; round 3 part A and part B: T1-T4, checkCode groups; third review: N3-N6, N9, N10 fixed, the write cut-off (L5, N1, N2, N7, N8) taken out, N11/N12 documented)_
