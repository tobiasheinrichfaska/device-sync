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
| `src/core/` (`encoding`, `canonical`, `markers`, `keys`, `signature`, `index`) | Core layer, first part: base64url, canonical JSON, markers, device keys, check code, `signText`/`verifyText` |
| `tests/core/`                                                    | Unit tests of the core layer                                  |
| `src/log/` (`types`, `vector`, `check`, `validate`, `recordIndex`, `merge`, `replica`, `signing`, `limits`, `parse`, `protocol`, `index`) | Log layer (pure): change, version vector, merge (causal hold, repeated passes), `validate` (shared strict checks of names, values, limits for the parser and for local writing; prototype-less dictionaries), `recordIndex` (per-record index of the log: last write per device and field, log positions), redaction, conflict notices, history, undo; signing and judging of changes (`signing`: signed text, `signChange`, `judgeChange(s)`, `readChanges`, hooks); exchange protocol: `limits` (`LIMITS`, one object), `parse` (strict `parseChange`/`parseVector`/`parseSyncMessage`), `protocol` (`pieces`, `fingerprint`, session `startSession`/`onSyncMessage`/`receive`/`receiveJudged`/`outcome`) |
| `src/trust/` (`types`, `ids`, `voucher`, `wire`, `known`, `devices`, `meeting`, `invitation`, `index`) | Trust layer (pure): device list as records of one reserved log collection (`addDevice`, `renameDevice`, `setDevicePrivate`, `removeDevice`, `listDevices`), trust derived not stored (`computeTrust`, `deviceKeySource` as `KeySource` for `readChanges`), voucher strategies (`vouchAll`, `vouchRoles`, `vouchAnyRole`), meeting code (signed, 120 s), invitation + reply + HMAC proof, list of devices met in person, `newDeviceId` |
| `tests/trust/`                                                   | Trust tests: `devices` (cases of both earlier implementations), `meeting`, `invitation` (tamper sweeps, boundaries, two apps), `fullstack` (invitation to judged changes), `fuzz` (seeded, 3500 inputs per parser), `ids-known`, `docs`, `helpers` |
| `tests/log/`                                                     | Log tests: `basis` and `typed` (cases of both earlier implementations), `properties` (seeded random schedules), `protocol` (session, pieces, fingerprint, refusals), `parse` (strict reading, limits, seeded fuzzing, depth bombs), `hardening` (review findings: unsafe names, unchecked local writes, clock-jump passes, invented `knew`), `performance` (no quadratic merge), `exchange` (full stack with real signatures, 120 seeded schedules, forgeries), `fuzz` and `helpers` (generators) |
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
- Exchange: pieces are meant to arrive in order. A reordered session may not take everything but never corrupts a replica, and the next session fills the gap (`tests/log/order.test.ts`); in `receiveJudged` the pieces before the last may come in any order. `receiveJudged` keeps up to `maxSessionChanges` changes in memory until the last piece; changes of authors that cannot be checked yet are dropped and must come again. The fingerprint (128 bits) is a consistency check, not a proof against a peer that lies. Apps pass their own device id pattern (`deviceId` option); the default is permissive. A transport should cap message size before the parser; `parseSyncMessageText` refuses text over twice `maxMessageChars` itself.
- Performance: a batch merge is linear (6000 changes to 6000 records in about 15 ms; `tests/log/batch.test.ts`); notices and final deletions use a per-record index of the log (`recordIndex`), so 8000 writes of one device to a 40-field record merge in well under a second and 20000 deletions likewise (`tests/log/performance.test.ts`). Every merge still copies the log and the collection of the touched records (O(records) per local write: about 11 ms at 20000 records in one collection); the index is kept per log array (a log rebuilt by hand is indexed again on first use). Pairs of heads of one field are compared pairwise, so a field written by thousands of different devices is quadratic in the devices.
- Conflict notices are derived from the log (a change against the earlier implementations, which built them incrementally and could differ between devices); a notice lists the concurrent heads, not every superseded write.
- The "hold back until approved" hook exists only as a type (`ApprovalHook`) and a marked spot in `merge`.
- The soft-delete field name `deleted` is reserved. Local writing refuses what the parser refuses (names, values, limits); a record written by more than `maxDevices` devices cannot be written to any more (`too-many-devices`: one `knew` could not name them all).
- A change that names a `knew` the receiver never reaches (a liar, or a change whose dependencies were lost) is held for good, with everything later from its author; only its own author is blocked. Held changes are not stored: the sender must send them again. `merge` takes `set`/`delete` changes without `knew` as held; the parser refuses them. Canonical JSON throws `TypeError` for anything that is not plain JSON (a top-level `undefined` is still `null`).
- Trust: the invitation text carries no signature; the inviter's keys in it are only as trustworthy as the channel (compare check codes). A removed device stays checkable, so whether it may still write is the app's `mayWrite` rule. `canVouch` is asked per pass of the derivation with the devices trusted so far. The derivation re-reads the whole device list on every new replica state (cached per state). Not ported: the 'confirmed role' flag of one earlier implementation, the device lock after days without contact, relay/session wiring. Parsers are stricter than the earlier ones (one spelling only, unknown members refused).
- Public but unreviewed: the README says so; no npm release and no tag for use before the security review.

_Last updated: 2026-11-21 (security findings H3-H5, M1, M2 fixed)_
