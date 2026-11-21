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
| `src/log/` (`types`, `vector`, `check`, `merge`, `replica`, `signing`, `limits`, `parse`, `protocol`, `index`) | Log layer (pure): change, version vector, merge, redaction, conflict notices, history, undo; signing and judging of changes (`signing`: signed text, `signChange`, `judgeChange(s)`, `readChanges`, hooks); exchange protocol: `limits` (`LIMITS`, one object), `parse` (strict `parseChange`/`parseVector`/`parseSyncMessage`), `protocol` (`pieces`, `fingerprint`, session `startSession`/`onSyncMessage`/`receive`/`receiveJudged`/`outcome`) |
| `tests/log/`                                                     | Log tests: `basis` and `typed` (cases of both earlier implementations), `properties` (seeded random schedules), `protocol` (session, pieces, fingerprint, refusals), `parse` (strict reading, limits, seeded fuzzing, depth bombs), `exchange` (full stack with real signatures, 120 seeded schedules, forgeries), `fuzz` and `helpers` (generators) |
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

- Only the first part of the core layer (encoding, canonical JSON, markers, device keys, check code) and the log layer (change model, merge, redaction, notices, history, undo, signing, exchange protocol with strict parsers) exist; the end-to-end encrypted session, trust, post, relay, transfer, push and browser are not implemented.
- Exchange: pieces are meant to arrive in order. A reordered session may not take everything but never corrupts a replica, and the next session fills the gap (`tests/log/order.test.ts`); in `receiveJudged` the pieces before the last may come in any order. `receiveJudged` keeps up to `maxSessionChanges` changes in memory until the last piece; changes of authors that cannot be checked yet are dropped and must come again. The fingerprint (128 bits) is a consistency check, not a proof against a peer that lies. Apps pass their own device id pattern (`deviceId` option); the default is permissive. A transport should cap message size before the parser; `parseSyncMessageText` refuses text over twice `maxMessageChars` itself.
- Performance: a batch merge is linear (6000 changes to 6000 records in about 15 ms; `tests/log/batch.test.ts`). Writing one change at a time scans the log (`knownFor`), about 1 ms at 3000 changes, so importing thousands of records one write at a time takes seconds; a final deletion walks the log once. Not optimised further.
- Conflict notices are derived from the log (a change against the earlier implementations, which built them incrementally and could differ between devices); a notice lists the concurrent heads, not every superseded write.
- The "hold back until approved" hook exists only as a type (`ApprovalHook`) and a marked spot in `merge`.
- The soft-delete field name `deleted` is reserved; field count and value size are limited only on the wire (`LIMITS`), not when writing locally.
- Public but unreviewed: the README says so; no npm release and no tag for use before the security review.

_Last updated: 2026-11-21 (tests: 313 in 18 files)_
