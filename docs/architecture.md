# Architecture (built layer by layer; core, log, trust and post exist)

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

## Session and encrypted file (core layer)

`core/session.ts` and `core/file.ts` move bytes between two devices that know each other's agreement key
(the trust layer verified it; the caller passes it in). The **session** is symmetric (both sides send a
`hello` with a fresh ephemeral key; keys from ephemeral x ephemeral, the two crossed terms and static x
static; one key per direction; the counter in clear is the nonce; strictly in order; forward secret against
a later leak of the static keys). The **file** is one message for one named recipient (fresh ephemeral key,
recipient's static key, sender's static key). Both bind the app id and both identities into the key and
the authenticated data, read every text strictly (one spelling) and answer refusals as codes. The payload is
opaque bytes; the app decides what is in it. What they do NOT protect (metadata, truncation, replay of a
file, forging by the holder of the recipient's key, no ratchet) is listed in `docs/wire-format.md`.

## Envelope and mailbox (core and post layers)

`core/envelope.ts` seals one message for SEVERAL reader devices so that third devices can carry it:
the content is encrypted once, its key is wrapped per reader with a fresh ephemeral key and the reader's
agreement key (ECDH, HKDF, AES-GCM, zero nonce), the fan of slots is padded with random slots to a multiple
of 8 (at most `maxFans`) and shuffled, and inside the AUTHOR signs app, sender, channel, day and content.
A carrier sees an id, a day and a size; not the sender, the readers or their number (up to the padding).
Opening needs the device's agreement key and a lookup of the author's signing key (`authorKey`, the trust
layer's job); a device that is not a reader pays one ECDH, one derivation and at most one trial per slot.
The content is opaque bytes: the app puts its stand and changes in it.

`post/` is what a device does with envelopes it carries: a mailbox value (add, quota per delivering device
and day, expiry after `postDays`, trimming to `maxEnvelopes` / `maxChars`, receipts), and the per-day
exchange of two meeting devices (a check value per day, the ids of the days that differ, then what the
other lacks) as strict message texts and an immutable, bounded session. All pure: "today", the delivering
device and the decision who may acknowledge (`mayAcknowledge`) are parameters. The earlier implementations'
receipt idea is kept generic: the mailbox drops only what a receipt of an allowed device covers. What the
envelope and the mailbox protect and do not: `docs/wire-format.md`, "Wire format: envelope and mailbox".

## Trust derivation (trust layer)

Trust is never stored; it is derived from the log and the devices met in person, and the result is a
function of the set of changes (not of any order): potential trust by vouching from the met devices,
a rank per device (distance from the met devices), removals processed rank by rank (all devices of a
rank act at once; no tie-break by device id: equal-rank mutual removals remove both; a removal
persists after its maker is removed by an equal or higher rank), a key consistency rule among the
vouchers that were not removed (a voucher cannot replace another device's keys; what a removed device
wrote carries no authority for conflicts), and reachability from the met devices. The exact rules
are in `docs/wire-format.md`, "Trust derivation".

**What a removal means.** It ends a device's standing as a voucher and as introduced through the
chain. The device stays checkable: its signed changes, earlier and later, still verify and the
signature layer accepts them. So does every device whose key was ever validly vouched for and that
fell out of trust without being removed itself (vouched only through a removed device): checkable
is every device of the potential trust without a key conflict, trusted or not, so no honest device
is held back for ever by changes it cannot check. The package does not revoke a removed device's ability to write; the
app stops exchanging with it at the transport, treats data authored by removed devices as untrusted
at presentation (`deviceStatus`), restricts writes with `mayWrite` / `allowFinalDelete` (hooks that
look at state can differ between devices), and the encryption layer (session, file and envelope exist; group keys
do not) must rotate the group keys on removal. A removed device stays removed: coming back means a new device id.

`derive.ts` holds one engine (a generator that asks for signature checks): `computeTrust` and
`deviceKeySource` run it with real checks, `addDevice` and `removeDevice` run it on this device's own
log to decide against the derived state. The derivation indexes the log once per state;
`deviceKeySource` answers `keyFor` by lookup and is `selfVerifying`, so `readChanges` can read a long
chain of introductions in one round.

## Hash chain (log layer)

Every change after a device's first carries `prev`, the LINK of the same device's previous change
(a hash of its whole signed head, so a version that differs in any signed member has another link),
inside the signed head; an erased change keeps it. A `stand` carries `tips` (per device the link of
the change at its vector position), so two devices holding different versions of one number end the
first session (`diverged`, `tip-mismatch`) instead of staying different for ever without a signal.
A tip is an unproven claim, so that reason names no culprit; the one proof an app may act on is two
signed changes of one device and number (`proveEquivocation`, with `changeAt` as the evidence
accessor). Two limits keep a long history joinable: a vector has its own, larger limit
(`maxStandDevices`), and an answer to a stand always holds at least one applicable group of
changes, even if that group is larger than the session budget.

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

Left to the app: everything a removed or untrusted device may still do (it stays checkable, so its
signed changes, earlier and later, verify; the app restricts it with `mayWrite`, stops exchanging with it, and rotates
the group keys once the encryption layer exists), the device lock after days without contact, and
which person a device belongs to.

## Wire protocol of the relay

Described next to the client with machine-readable test cases, so a server and any port of it can be
tested against the same cases. Not yet written.
