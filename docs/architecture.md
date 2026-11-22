# Architecture (plan, not yet built)

The package is app-independent. Everything an app decides (record shapes, who may write what,
approval, texts, storage names) is passed in as a parameter, a hook or a strategy.

## Layers

| Layer        | Content                                                                                                  |
| ------------ | -------------------------------------------------------------------------------------------------------- |
| **core**     | Canonical JSON and check values, device keys, signatures, session, encrypted file, envelope with fan-out |
| **log**      | Change log, version vector, merge, conflict notices, erasure with redaction, catch-up, chunked exchange  |
| **trust**    | Device list, invitation, acquaintance, removal; a strategy decides who may vouch                         |
| **post**     | Mailbox for sealed envelopes carried by third devices                                                    |
| **relay**    | Client of a simple store-and-forward relay: enrol, renew, invite, drop, collect loop, ring               |
| **transfer** | Fountain QR, tone acknowledgement, direct connection (optional entry points)                             |
| **push**     | Web Push encryption and VAPID, ring request, service worker template                                     |
| **browser**  | Key storage in IndexedDB, one listener per tab, camera and audio behind narrow interfaces                |

`core`, `log`, `trust`, `post` and `push` are pure: no clock, no randomness, no I/O (both are passed
in) and testable without a UI. Only `browser` and `relay` touch `fetch`, IndexedDB or WebRTC.

## Parameters instead of constants

- **`appId`**: every marker, hash prefix, key-derivation salt and storage name is built from it, so two
  apps never sign or derive the same bytes. The wire format is versioned (`:2`).
- **Limits** (text length per value, fields per change, envelope fan-out) are configuration.
- **Hooks**: a special case in signature checking, records that are never erased, the right to write
  (the receiver decides, `mayWrite`), whether a final deletion is allowed at all (`allowFinalDelete`, off
  by default), a per-author quota against a flooding member (`quota`; it ends the reading of a
  session, it does not refuse it), holding a change back until someone approves it. The key source
  (`KeySource`) gives the key of a device who can be CHECKED (not who may write), optionally the
  collections that are never finally deleted (`neverErase`) and whether it verifies what it reads
  itself (`selfVerifying`).
- **Partial sessions**: size limits never make a large honest history impossible. A sender cuts its
  answer to a prefix of its own log (`more: true`), a receiver whose limit is hit ends the reading and
  takes what it verified (`Session.truncated`); the next session continues (`docs/wire-format.md`).
- **Strategies**: who may vouch for a device, how a device lock is computed (peer contact or server
  time).
- **Errors** are codes (`art`), not sentences; the app translates.

## Trust derivation (trust layer)

Trust is never stored; it is derived from the log and the devices met in person, and the result is a
function of the set of changes (not of any order): potential trust by vouching from the met devices,
a rank per device (distance from the met devices), removals processed in the order rank then device
id (a removed device removes nobody; equal-rank mutual removals go to the smaller id), a key
consistency rule among the vouchers that were not removed (a voucher cannot replace another device's
keys; what a removed device wrote carries no authority), and reachability from the met devices. The
exact rules are in `docs/wire-format.md`, "Trust derivation".

**What a removal means.** It ends a device's standing as a voucher and as introduced through the
chain. The device stays checkable: its signed changes, earlier and later, still verify and the
signature layer accepts them. The package does not revoke a removed device's ability to write; the
app stops exchanging with it at the transport, treats data authored by removed devices as untrusted
at presentation (`deviceStatus`), restricts writes with `mayWrite` / `allowFinalDelete` (hooks that
look at state can differ between devices), and the encryption layer (not built yet) must rotate the
group keys on removal. A removed device stays removed: coming back means a new device id.

`derive.ts` holds one engine (a generator that asks for signature checks): `computeTrust` and
`deviceKeySource` run it with real checks, `addDevice` and `removeDevice` run it on this device's own
log to decide against the derived state. The derivation indexes the log once per state;
`deviceKeySource` answers `keyFor` by lookup and is `selfVerifying`, so `readChanges` can read a long
chain of introductions in one round.

## Hash chain (log layer)

Every change after a device's first carries `prev`, the check value of the same device's previous
change, inside the signed head; an erased change keeps it. A `stand` carries `tips` (per device the
link of the change at its vector position), so two devices holding different versions of one number
refuse each other at the first session (`equivocation`, naming the author) instead of staying
different for ever without a signal.

## Who may vouch (trust layer)

The package hard-wires no role. An app passes a `Voucher` (`canVouch`, optional `mayInvite`) and
predicates for roles, names, ids and relay ids. The two earlier implementations map onto the ready-made
strategies like this:

- "Only devices with an administrative role vouch and invite" = `vouchRoles([thatRole])`.
- "Every device of a trusted person vouches" = `vouchAnyRole()` plus the `roleCounts` hook (a role counts
  only while the person it names still exists in the data).
- "Every trusted device vouches" = `vouchAll()`.
- "A private device never holds the highest role" (a rule of one earlier implementation) = the
  `privateRoles` predicate (the roles a private device may hold); the package knows no highest role.

Left to the app: everything a removed device may still do (it stays checkable, so its signed changes,
earlier and later, verify; the app restricts it with `mayWrite`, stops exchanging with it, and rotates
the group keys once the encryption layer exists), the device lock after days without contact, and
which person a device belongs to.

## Wire protocol of the relay

Described next to the client with machine-readable test cases, so a server and any port of it can be
tested against the same cases. Not yet written.
