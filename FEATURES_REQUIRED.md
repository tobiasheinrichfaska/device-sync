# Critical User Paths — device-sync

**Purpose:** Core workflows that must not break. Audit validates these end-to-end.
Status: core (partly) and log (model, signing, exchange protocol) implemented; the rest is the target.

## Library behaviour (target)

- [x] **Two devices converge** (`tests/log/exchange.test.ts`: 120 seeded schedules of three devices, each exchange signed, cut into pieces, JSON, strictly read, judged and merged, also with duplicated pieces; `tests/log/properties.test.ts` for the pure model. Pieces out of order within one session are not supported: that session ends with different fingerprints and the next one catches up) — after exchanging their changes, both hold the same data and the same fingerprint
- [x] **A forged or altered change is refused** (log layer: `tests/log/signing.test.ts`; exchange: `tests/log/exchange.test.ts`, the session ends with `forged` and the receiver's replica is unchanged) — a bad signature, a change under a foreign device id or a change outside its data set is judged false and nothing of that exchange is taken
- [ ] **An envelope opens only for its readers** — a carrier sees neither sender, readers nor their number
- [x] **A new device joins by invitation** and is trusted only through the vouching strategy of the app (`tests/trust/fullstack.test.ts`: invitation text exchange, entry in the log, signed changes of the new device judged by a third replica with `readChanges` + `deviceKeySource`; a device nobody vouches for stays pending; chains, removal, forged entries; tamper sweeps and fuzzing of the three parsers in `tests/trust/meeting|invitation|fuzz.test.ts`)
- [~] **Two apps never share bytes** (covered: markers, check code and change signatures per appId; key derivation pending) — different `appId`s give different signatures and keys
- [ ] **A relay client survives errors** — it acts on the error code, never on its text

| Path                          | Impact                              | Audit Check                                    |
| ----------------------------- | ----------------------------------- | ---------------------------------------------- |
| No app names in the package   | public repo must stay app-neutral   | `tests/coupling.test.ts` green                 |
| Local writing is as strict as the parser | a change a receiver refuses blocks everything later from its device | `tests/log/hardening.test.ts` (H3/H4: names, values, limits, origin) |
| A `knew` cannot be invented   | a lying `knew` could hide a conflict | `tests/log/hardening.test.ts` (M2: required, causal hold, convergence) |
| No quadratic work from well-formed input | one device or many deletions could stall a replica | `tests/log/performance.test.ts` (8000 writes to one record, 20000 deletions) |
| An honest batch is never refused for its round structure | a new device could never get in | `tests/log/review2.test.ts` (H1: every order, piece size, key-learning order) |
| One device number has one content | equivocation splits replicas silently | `tests/log/review2.test.ts` (H2: both proofs, every meeting order; reason `equivocation`) |
| Nothing unverified fills memory | a flood of large pieces could exhaust a device | `tests/log/review2.test.ts` (H6: `maxSessionChars`, `maxPendingChanges`, `quota` now end the reading; unsigned floods still refused at the first piece) |
| A large honest history can always be joined | a new device could be locked out for good | `tests/log/review3.test.ts` (L1: partial sessions, newcomer batch not capped, quota/limits truncate) |
| An erased change is taken only with its applied deletion | a forwarder could erase a signed write at one device | `tests/log/review3.test.ts` (L2: gap, `knew`, clock jump) |
| Forgeries under the own id are not `own-history` | an app would abandon its id for a forgery | `tests/log/review3.test.ts` (L3) |
| An unsigned deletion is not announced by its victims | an honest session was refused, an innocent author blamed | `tests/log/review3.test.ts` (L4) |
| Piece processing is linear | known valid changes in many pieces could stall a device | `tests/log/review3.test.ts` (L6) |
| An erased change carries only signed members | unchecked members were stored and forwarded | `tests/log/review3.test.ts` (L9) |
| Changes after a removal are ignored, not refused | the session must go on | `tests/log/review3.test.ts` (`KeySource.standing`, `neverErase`) |
| A device does not send what it has not signed | an honest device would block itself | `tests/log/review2.test.ts` (H4b: `signedOnly`, `withheld`) |
| Every refusal has a reason | an app must tell "stop writing, re-enrol" from "stop trusting that device" | `tests/log/review2.test.ts` (M4: `own-history`, `equivocation`, ...) |
| Final deletion is opt-in | one member's signature could erase any record for good | `tests/log/review2.test.ts` (M5: `allowFinalDelete`) |
| A field written by many devices stays writable | `too-many-devices` after 51 phones over the years | `tests/log/review2.test.ts` (X1: 80 devices in a row; 60 concurrent heads still trigger) |
| One signature, one spelling; check code unambiguous | malleable signatures, colliding codes | `tests/core/review2.test.ts` (N1 low-s, N2 length-prefixed text) |
| Other implementations get the same bytes | cross-language ambiguity | `tests/vectors.test.ts` + `tests/vectors/*.json` |
| Parsers are strict            | a lenient parser opens a hole       | `tests/log/parse.test.ts`: seeded fuzzing (6000 inputs per parser), limit boundaries, depth bombs |
