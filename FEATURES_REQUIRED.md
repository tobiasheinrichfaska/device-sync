# Critical User Paths — device-sync

**Purpose:** Core workflows that must not break. Audit validates these end-to-end.
Status: scaffold, nothing implemented yet. The paths below are the target.

## Library behaviour (target)

- [~] **Two devices converge** (pure log model covered: seeded random schedules converge in any order, with duplicates; exchange protocol and fingerprint not built yet) — after exchanging their changes, both hold the same data and the same fingerprint, in any order and with duplicates
- [x] **A forged or altered change is refused** (log layer: `tests/log/signing.test.ts`; the exchange protocol that carries batches is not built yet) — a bad signature, a change under a foreign device id or a change outside its data set is judged false and nothing of that exchange is taken
- [ ] **An envelope opens only for its readers** — a carrier sees neither sender, readers nor their number
- [ ] **A new device joins by invitation** and is trusted only through the vouching strategy of the app
- [~] **Two apps never share bytes** (covered: markers, check code and change signatures per appId; key derivation pending) — different `appId`s give different signatures and keys
- [ ] **A relay client survives errors** — it acts on the error code, never on its text

| Path                          | Impact                              | Audit Check                                    |
| ----------------------------- | ----------------------------------- | ---------------------------------------------- |
| No app names in the package   | public repo must stay app-neutral   | `tests/coupling.test.ts` green                 |
| Parsers are strict            | a lenient parser opens a hole       | fuzz tests of every parser (to be written)     |
