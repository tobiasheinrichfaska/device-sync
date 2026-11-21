# CLAUDE.md — device-sync

> Workspace-wide conventions (language, git, build, architecture, testing, collaboration):
> [`c:\skripte\private\general stuff\CLAUDE.md`](../../private/general%20stuff/CLAUDE.md)

---

## Project overview

Shared, app-independent technology for secure device-to-device data sync in Tobias' offline-first web
apps: a signed gapless change log per device, end-to-end encrypted transfer, device trust and
invitation, a relay client and Web Push helpers. Created 2026-11-21 (decision: extract it from the
apps that carry copies of it). **Status: scaffold (0.0.0): nothing implemented or exported yet, not
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
| `src/index.ts`                                                   | Public entry (only the status so far)                         |
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

- Scaffold only: no layer is implemented yet.
- Public but unreviewed: the README says so; no npm release and no tag for use before the security review.

_Last updated: 2026-11-21_
