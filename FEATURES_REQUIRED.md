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
| Parsers are strict            | a lenient parser opens a hole       | `tests/log/parse.test.ts`: seeded fuzzing (6000 inputs per parser), limit boundaries, depth bombs |
