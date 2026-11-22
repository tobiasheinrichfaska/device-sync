# Device lock: days without contact, operator orders, wipe instruction

**New, not yet reviewed.** `src/lock/` is a pure state machine over a plain storable value. It has no clock,
no storage and no deletion: times come in as parameters, the state goes out as a text the app stores, and
what a locked device must erase is the answer of an app hook that the app carries out itself. This document
is held to the code by `tests/lock/docs.test.ts`.

## What it does

A device works for `maxDays` days after its last counted contact. From `warnDays` elapsed days the status is
`warn`, after `maxDays` it is `locked`. Exactly `maxDays` still works; one millisecond more locks (as in the
earlier implementation). Two variants are two configurations of the same machine:

| Variant         | `source` / `kind`   | What counts as contact                              | Typical settings                                 |
| --------------- | ------------------- | --------------------------------------------------- | ------------------------------------------------ |
| Peer deadline   | `peer` / `device`   | a file of a trusted other device (the device clock) | 10 days, `revive`, `distinct`, `skewMs` one day  |
| Server deadline | `server` / `remote` | an answer of the server (the server's time)         | 10 days, warning from day 7, `wipeOn: 'contact'` |

Functions: `lockStart`, `recordLockContact`, `lockStatus`, `lockObserve`, `lockCheck`, `lockMarkWiped`,
`lockRemoved`, `lockRemovedBy`, `lockSetDays`, `storeLockState`, `readLockState`, `signLockOrder`, `readLockOrder`,
`applyLockOrder`.

## Sources of time

The state names the one `source` whose contacts move the deadline. A contact from another source is only
noted (`others`, at most 7 names, information only), so a server lock is never advanced by a time a peer
claims. For kind `remote` the state keeps the server's time `at` next to the device clock reading `local` of
that contact; elapsed time is always measured on the device clock from `local` (offline there is nothing
else), and a server time lower than the last one is refused (`time-went-back`: an old answer replayed). For
kind `device` the contact time is the device clock (`at` equals `local`).

## Clock guard

`high` is the highest device clock ever seen. Elapsed time is measured to `max(now, high)`, so a clock set
back never lowers it. A clock that stands before `high` by more than `slackMs` (default 10 minutes) gives the
reason `clock` (stored by `lockObserve`; shown by `lockStatus` at once). Expiry is kept once seen (`expired`),
also when the clock is turned back later. **Limits:** the guard only knows what the app showed it. The app
must call `lockObserve` (or `lockCheck`) at every start and whenever it comes to the front and store the
result. A device whose owner sets the clock back offline BEFORE the app ever looks again, or who restores an
old stored state, cannot be stopped by any pure code; a server lock catches it at the next contact. A clock
jumping forward locks early (the safe direction); a counted contact restores it.

## Contacts that do not count

`recordLockContact(state, source, at, local, info)` answers `counted: false` with a reason `why`:
`other-source`, `removed`, `locked` (expired or clock lock and no `revive`), `same-peer` (state `distinct`:
the peer of the last counted contact again; two stolen devices cannot keep each other alive), `old` (`info.created`, the
peer's clock when it made its file, is not newer than the last one), `clock-differs` (that clock differs from
the device's by more than `skewMs`). Whether the peer is trusted and whether the data show this device removed
is the caller's check (trust layer: `deviceStatus`); it only passes a contact it accepts and calls
`lockRemoved` otherwise. With `revive` a counted contact lifts an expiry or clock lock; without it
only a new `lockStart` does (the server variant: a locked device is wiped at its next contact).

## Removal

`lockRemoved(state)` locks the device for good with the reason `removed`: only a new `lockStart` helps. The
caller decides what shows this device removed. The sync driver's removal notice is the proof for a device
that was removed while it did not know: `lockRemovedBy(state, verdict)` takes the verdict of
`judgeRemovalNotice` (or `SyncReport.notice`, `docs/sync.md`, "Removal notice") by its shape,
`{ selfRemoved: true }`, and calls `lockRemoved` for a proven removal only; any other verdict, a refused or
partial notice, a notice about another device, or no verdict leaves the state as it is. The lock layer
knows nothing of the trust layer; it never sees the notice itself. Store the returned state at once: the
driver keeps the proof in RAM only, so after a restart the stored lock state is what keeps the device shut.

## Operator orders

One signed text per order, for one target device. Compact JSON, members in this order, one spelling:
`{"k":"<app>-lockorder:1","to":"<device>","from":"<device>","op":"lock"|"unlock","n":<counter>,"sig":"<base64url>"}`.
The signature (ECDSA P-256, low-s, `signText`) is over `<marker>|<len>:<to><len>:<from><op>|<n>` with byte
lengths, so no field can shift into another. `applyLockOrder` checks, cheap first: text, target equals `self`,
`from` is not `self` and `mayOperate(from)` (required, no default; use the trust layer's status and your
roles), counter above `opN` (replay and reorder protection), the key from `keys(from)` (for example
`deviceKeySource`), the signature. `n` must grow per target: use the operator's clock in ms. A lock sets the
operator lock (`held`, `by`), an unlock clears only that; it does not lift expiry (a contact does) and never
`removed`. **Not protected:** a carrier can drop or delay an order (the device then locks only by time); two
operators whose counters collide see the second refused as `replayed`; the order does not hide who it is for.

## Wipe hook

`lockCheck(state, now, { onLocked }, atContact)` returns `{ status, state, wipe }`. `wipe` is whatever
`onLocked({ reason, by })` returned, while the device is locked and the app has not called `lockMarkWiped`
(so a crash before erasing repeats the instruction). With `wipeOn: 'contact'` it is given only when
`atContact` is true. The package never deletes.

## State text

`storeLockState` writes compact JSON with a fixed member order; `readLockState` accepts nothing else (one
spelling, consistent values, bounded) and answers undefined otherwise, never throws. A caller that cannot
read the stored state must treat the device as locked, never as open.

## Limits

| Limit                   | Value                               |
| ----------------------- | ----------------------------------- |
| `maxDays` ceiling       | 3650                                |
| Other sources per state | 7 (`maxSources` 8 counts the main)  |
| Source name             | `[a-z][a-z0-9:_-]{0,39}`            |
| State text              | at most 2 000 characters            |
| Order text              | at most 1 200 characters            |
| `slackMs`               | 0 to 86 400 000 (default 600 000)   |
| `skewMs`                | 0 to 2 592 000 000 (default 0: off) |

## Codes

| Code               | Meaning                                                               |
| ------------------ | --------------------------------------------------------------------- |
| `bad-input`        | a value is not a time, a name or an id of the allowed shape           |
| `bad-config`       | days out of range, `warnDays` above `maxDays`, unknown kind or option |
| `time-went-back`   | a `remote` time lower than the last one                               |
| `too-many-sources` | an eighth source name                                                 |
| `not-an-order`     | text is not exactly an order of this app                              |
| `wrong-device`     | the order is for another device                                       |
| `not-allowed`      | `from` is this device or `mayOperate` said no                         |
| `unknown-key`      | `keys(from)` gave nothing or threw                                    |
| `bad-signature`    | the signature does not check                                          |
| `replayed`         | counter not above the highest applied                                 |

Status reasons: `removed`, `operator`, `clock`, `expired`. Not-counted reasons: `other-source`, `removed`,
`locked`, `same-peer`, `old`, `clock-differs`.
