# Sync driver (`src/sync/`)

Wires the log, trust, core and relay layers into an exchange over the relay: devices that are online at
the same time hand each other what the other lacks, sealed for that one device, without any direct
contact. A pure-ish layer: it takes the clock, randomness, the relay client and the app's hooks as
parameters, keeps no timer and never loops. The app calls `syncOnce` when it likes and waits
`report.nextMs` (the cadence of the relay layer) before the next call.

**Not security-reviewed by a human.** New; never run against a real relay (tests use the repository's
reference server with real keys, real signatures and the real trust derivation).

## What the relay is, and what that decides

The relay (`docs/relay-protocol.md`) keeps a message at most 30 seconds, in RAM, and hands it to the
named device once. It is a rendezvous, not a mailbox: two devices must be online within 30 s of each
other. The data sets therefore travel as short pull rounds (below). What a rendezvous cannot do, the
post layer's store-and-forward does: **envelopes** (content sealed for named readers, carried by any trusted
device, see "Envelopes and the mailbox") travel with the sync, so a third device can carry content for
an offline one. An envelope hides sender and readers from a carrier, but not from the relay (it is both
carrier and delivery party), and one envelope holds under 8.3 kB, so the log's own exchange does not use
envelopes: it uses what fits a rendezvous.

- **Content**: the log's own exchange messages (`docs/wire-format.md`, "Exchange"): a `stand` asks, `changes`
  pieces answer. The changes carry the authors' signatures, which the log layer judges (`receiveJudged`).
- **Packet**: one message in a small frame of JSON, two shapes (one spelling each, other members refused):
  `{"m":"<app>-sync:2","r":"<16 hex>","s":"<set>","msg":{...}}` for the log's exchange of the data set `<set>`
  and `{"m":"<app>-sync:2","r":"<16 hex>","post":"<message text>"}` for the mailbox exchange.
  `r` names the round. The version of the packet marker is 2 since the set name (`s`) and the mailbox shape.
- **Seal**: the packet is an encrypted file for ONE device (`sealFile`: the static keys of both devices go
  into the key, so only those two can make or open it).
- **Frames**: the sealed file is cut by `splitPayload` (40 000 bytes per part, so a frame stays under the
  relay's 65 536) and put together by the `FrameAssembler`.

**Pull rounds, not sessions.** A session of the log expects both sides to stay in step, which a 30-second
rendezvous with lost messages cannot promise. Here the asker sends a `stand`; the answerer holds no state
and answers it from its current log (`changes` pieces, cut at the answer budget, `more` when cut); the
asker feeds the pieces into one log session and merges when the last arrives. Two devices pull from each
other: an ask whose vector is ahead of the receiver makes the receiver pull back, and a device that merged
something asks its peers again (so data goes A to B to C when A and C never meet). A lost message costs
one round timeout, never a corrupt replica; the next ask starts from the log's vector. Nothing is
resumed and nothing is stored: `SyncState` lives in RAM.

Peers are asked only when the relay says they are **present** (collected within 30 s); answers go back
without that check. A peer that is in sync is asked again every `idleRoundMs`.

## Who gets content, who is heard (what the package enforces)

| Rule                                                                                                                                                                                                                                                                                                                             | Where                                           |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| Recipients are derived from the trust layer (`Trust.trusted` of the replica as it stands), never given by the caller. Removed, merely known and unknown devices are not peers.                                                                                                                                                   | `buildRoster`                                   |
| A trusted device is reachable only with a relay id in its (vouched) entry that no other trusted device names.                                                                                                                                                                                                                    | `buildRoster` (`no-relay-id`, `relay-id-clash`) |
| A removal counts at once for outbound: the next step derives the roster again, drops every queued message for the device (`recipient-not-trusted`) and forgets its rounds. A grant or file queued with `queueFile` is checked at drop time, not at queueing.                                                                     | `syncOnce`, `queueFile`                         |
| Inbound is filtered at the transport, before assembling and before any merge: the relay id must be a peer's (else `unknown-sender` / `removed-sender`); the assembled file must be addressed to this device, name the same device as the relay id (`sender-mismatch`) and open with that device's agreement key (`cannot-open`). | `takeIn`                                        |
| **The sender is the device whose key opens the file, never the relay's `from`.** `from` only bounds what is assembled and is checked against the file. A relay that forges it makes messages drop, nothing more. The data inside is judged by its authors' signatures.                                                           | `takeFile`                                      |
| A device that finds itself removed does nothing: no collect, no sending (`self-removed`).                                                                                                                                                                                                                                        | `syncOnce`                                      |
| After a removal the report says so (`newlyRemoved`, `trust`); the group key is checked through the adapter: `rotationStatus` (`needsRotation` and the lead hint), `rotateAfterRemoval` (a new epoch for the trusted devices only), `grantToMissing`. The grants go out through `queueFile`.                                      | `groupAdapter.ts`                               |

**Stays the app's job** (hooks and decisions the package does not take):

- _Who may write._ `judge: { mayWrite, allowFinalDelete, quota, special }` are passed to the log layer
  unchanged. A removed device stays _checkable_: its signed changes, earlier and later, verify, and a
  trusted device that holds them can pass them on. The package cuts a removed device off at the transport,
  not in the log (a device-local write cut-off made honest devices disagree, see `CLAUDE.md`, Trust).
- _Who may vouch_: the `Voucher` strategy of the trust options. _Hold back until approved_: `approval`.
- _Retention_ of old group keys (`pruneGroup`), of the log, of what a removed device may still read.
- _Telling a removed device_ that it was removed: nothing is sent to it, not even a notice. (An app that
  wants the notice sends it itself; the removal is a signed entry in the log.)
- _Presentation_: data authored by removed devices is shown as untrusted (`deviceStatus`).
- _Re-admission_: a removed id stays removed; a returning device enrols with a new id.
- The relay id of a device must be written into its entry (`addDevice(..., { relayId })`) by a vouching
  device; the package never learns a relay id from the relay.

## Data sets

The driver carries SEVERAL data sets. The **main set** (`trust.dataSet`) is the one the device list lives
in; every other set is registered in `SyncConfig.sets` by name, with the app's rules for it:

```ts
sets: { 'times:p1': { mayExchange: (peer, trust) => ..., judge: { mayWrite, allowFinalDelete, fieldRules }, approval } }
syncOnce(config, state, mainReplica, nowMs, { sets: { 'times:p1': replica }, mailbox })
// -> { replica, sets: { 'times:p1': replica' }, mailbox, report }
```

The caller holds the replicas (it stores them with `storeReplica`, `docs/channel.md`) and gets them back
changed; a registered set that is not in `held.sets` starts empty under this device's id. A set name is
1 to 80 of letters, digits and `:._-`, not the main set's name (`bad-input`), at most `maxSets` of them.

- Every exchange message names its set (`s`). A set that is not registered here is dropped (`unknown-set`).
- One round per peer and set; asks, answers, rates and pieces are counted per set, so a quiet set costs no
  asks and a busy one cannot starve the others.
- Signatures name the set (`docs/wire-format.md`): a change signed for one set never verifies in another.
  The keys of every set come from the same trust, derived from the main set's device list
  (`channelKeys(trust)`): a removed device stays checkable, who may write is the set's `judge.mayWrite`.
- **Who may read a set** is `mayExchange(peer, trust)`: asked for every ask this device makes, every ask it
  answers and every answer it takes. A set that only some roles may read is never sent to, asked of or taken
  from the others (`set-not-allowed`). A throwing hook counts as "no". Default: every trusted peer.

## Envelopes and the mailbox

With `SyncConfig.post` the mailbox (`docs/wire-format.md`, "Mailbox") travels with the sync:

- The mailbox comes in `held.mailbox` and goes out in `SyncResult.mailbox` (pruned: too old, too far ahead,
  acknowledged; at most 2000 envelopes). The app puts its own envelopes in with `addEnvelopes` (no `from`) and
  opens the ones addressed to it with `openChannel` (`docs/channel.md`); `report.received` lists what came in at
  this step.
- Per peer and step one mailbox exchange (`postStart` / `postStep`: a check value per day, the ids of the days
  that differ, the envelopes the other lacks), carried as `post` packets of one round. The exchange is
  symmetric: both sides send what the other lacks in the same round. Two exchanges opened at once: the smaller
  round id wins. A message out of order or over a limit ends the exchange (`post-refused`, nothing changes in
  the mailbox) and the next step starts a new one. A peer is asked again when the mailbox changed since the last
  ask, or after `idleRoundMs`; a settled mailbox costs nothing.
- **Bounded**: an exchange offers and announces only the newest `maxExchangeEnvelopes` envelopes of the mailbox
  (frames of one answer are bounded, the relay takes 65 536 bytes a frame). A larger difference moves over
  several exchanges, newest first.
- The quota of the mailbox applies to whoever brings an envelope (400 a day from one device, 256 devices a
  day): a flooding peer fills its own quota only.
- `PostConfig.mayCarry(peer, trust)` limits who this device carries for (default every peer). Without
  `cfg.post` a mailbox packet is dropped (`post-disabled`) and the mailbox is untouched.
- **Receipts clear envelopes.** `PostConfig.receipts(sets)` returns the receipts the app's data holds
  (`receiptsOf(replica)`; written with `writeReceiptRecord`), read strictly each step, and
  `PostConfig.mayAcknowledge(by, trust)` says who may acknowledge (default nobody). An envelope covered by an
  allowed receipt is dropped and its id is remembered, so a neighbour that still holds it cannot hand it back
  (`report.acknowledged`). The receipt record is ordinary data of a set the carriers hold: it travels like any
  other change, and every carrier that has it drops the envelope.
- What an envelope protects and what not: unchanged (`docs/wire-format.md`). The relay sees that a mailbox
  exchange happens and its sizes; a carrier sees size, day, id and the carrier path of an envelope.

Over a relay that keeps a message 30 s, two devices that are never online together converge through a
third: A seals an envelope for C, A and B meet and B stores it, B and C meet and C opens it, C writes a
receipt into a shared set, B and then A learn it and drop their copies
(`tests/sync/sets-post.test.ts`, with the repository's reference relay and the clock moved past 30 s
between the meetings).

## Exchange by file

`makeExchangeFile(cfg, { to, replica, held, memory, notice, nowMs })` and `takeExchangeFile(cfg, { file,
replica, held, memory, nowMs })` (`src/sync/file.ts`) hand data over WITHOUT a relay and without the other
being online: any carrier (a QR run, a mail, a memory stick, a direct connection, or the relay as an
ordinary file that `report.passed` hands to the app).

**Decision: built, because it adds something over the pull rounds.** A pull round needs a round trip and both
devices online within 30 s; a file is one way, asynchronous and carrier-free, and a device that remembers
the other's last stand sends only what is missing. Everything else the file does, the pull rounds and the
mailbox exchange also do (the same log protocol, the same strict readers, the same judging), so the file is
a transport of the same content, not a second protocol.

The file is sealed for ONE device (`sealFile`) and its payload is one compact JSON text, members in this order:
`{"m":"<app>-xfile:1","sets":{"<set>":{"stand":<stand>,"pieces":[<changes>,...]},...},"post":[<envelope>,...],"notice":<text or null>}`.

- `stand` is this device's own stand of the set (the other answers with a file of its own); `pieces` are the
  changes the other lacks according to `memory` (the answer of the log protocol to a stand, cut at the answer
  budget, `more` when cut), signed, gapless per device, an erased change with its deletion.
- `post` is the newest `maxExchangeEnvelopes` envelopes of the mailbox; `notice` is an opaque text of at most
  `maxNoticeChars` that the package never reads (a slot for an app message, for example about a removal).
- **Stand memory** (`StandMemory`, `rememberStand`, `readStandMemory`): per peer and set the last stand heard.
  Only stands received are remembered, never "what I sent" (a file may be lost). It only grows, holds at most
  `maxRememberedPeers` peers (the one touched earliest goes), and costs a wrong memory one gap that the next
  file fills. A device that forgot sends everything again.
- **Taking** is exactly as strict as the relay path: the sender is the trusted device whose key opens the file,
  the payload is read by `readExchangePayload` (one spelling, duplicate keys refused, bounded), every change is
  judged by its signature and the app's rights, a set that fails (the log's refusal, by code in `refused`) is
  left out whole and the others still count, a set that is not registered or that `mayExchange` refuses is
  dropped (`dropped`), envelopes pass the mailbox's quota. A file has no replay protection: taking one twice is
  harmless (idempotent).
- A set the recipient may not read (`mayExchange`) is not put into the file at all.

## What a step sends

A step queues, per peer, the asks and answers of every set and the mailbox exchange, seals each for the peer
(`sealFile`) and cuts it into frames of at most 40 000 bytes (`splitPayload`). `drain` then drops at most
`maxDropsPerStep` times; each call carries **one frame per recipient, at most 50 recipients** (the relay's
limit), a device is a recipient once per call, the own relay id is never one (a roster never contains it), and
a message larger than a megabyte (`queueFile`) simply takes more calls (`tests/sync/drop-split.test.ts`).

## Cutting and limits

An answer is cut by the log layer at `answerChanges` changes or `answerChars` characters, always keeping a
gapless prefix and at least one applicable group (progress guarantee). If its frames would exceed
`maxFramesPerAnswer` the budget is halved until it fits; a group that does not fit even then is not sent
(`answer-too-large`; raise the limits). A cut answer says `more` and the asker pulls again at once. At
most `maxDropsPerStep` relay calls are made per step, one frame per recipient per call; the rest of the
queue waits for the next step. Every message dropped is at most the relay's `maxContentBytes` (a test
watches every drop).

| Limit                  | Default   | Meaning                                                                                        |
| ---------------------- | --------- | ---------------------------------------------------------------------------------------------- |
| `roundMs`              | 30_000    | a pull round waits this long for its answer, then it is dropped and asked again                |
| `idleRoundMs`          | 30_000    | a peer that is in sync is asked again after this long (finds what a lost message left behind)  |
| `outboxMs`             | 25_000    | a queued message the relay did not take within this time is dropped (the relay keeps one 30 s) |
| `maxQueuedFrames`      | 200       | frames waiting for one peer; a message that does not fit is dropped (`outbox-full`)            |
| `maxDropsPerStep`      | 12        | `drop` calls of one step (each carries one frame per recipient, at most 50 recipients)         |
| `maxCollectCalls`      | 5         | `collect` calls of one step                                                                    |
| `maxMessagesPerStep`   | 500       | messages one step takes in                                                                     |
| `maxCollectBytes`      | 8_388_608 | content bytes one step takes in                                                                |
| `maxPiecesPerRound`    | 200       | pieces one round takes before it is ended as hostile (`round-overflow`)                        |
| `maxAsksPerWindow`     | 8         | asks of one peer answered per window; more are dropped (`ask-rate-limited`)                    |
| `askWindowMs`          | 10_000    | the window of the line above                                                                   |
| `rememberedAsks`       | 16        | round ids of answered asks remembered per peer (`duplicate-ask`)                               |
| `answerChanges`        | 400       | budget of one answer, in changes (a cut answer says `more`; the next round continues)          |
| `answerChars`          | 240_000   | budget of one answer, in JSON characters                                                       |
| `maxFramesPerAnswer`   | 60        | frames of one answer; the budget is halved until it fits, else `answer-too-large`              |
| `maxSets`              | 16        | data sets a registry may hold besides the main one                                             |
| `maxExchangeEnvelopes` | 100       | newest envelopes one mailbox exchange (or file) offers and announces                           |
| `maxExchangeFileBytes` | 8_000_000 | payload bytes of an exchange file; the answer budget is halved until it fits                   |
| `maxNoticeChars`       | 8000      | characters of the notice slot of an exchange file                                              |
| `maxRememberedPeers`   | 256       | peers the stand memory of an exchange file remembers                                           |
| `maxPassedPerStep`     | 16        | files of trusted devices that are not sync packets (key grants) handed to the app per step     |
| `maxEvents`            | 50        | events listed in one report                                                                    |
| `busyHoldMs`           | 30_000    | after a frame came or went the step stays "busy" (fast cadence) this long                      |
| `failureBaseMs`        | 2_000     | pause after a failed collect, doubled for every failure in a row                               |
| `failureCapMs`         | 60_000    | longest such pause                                                                             |

(The `## Limits` table is read by `tests/sync/docs.test.ts`: it lists exactly `SYNC_LIMITS`.)

## Idempotence and misbehaving relays

A replayed ask is answered once (`duplicate-ask`) and at most `maxAsksPerWindow` times per window; a
replayed piece is ignored (`duplicate-piece`, by the transfer id of its frames); an answer for no open
round is dropped (`stale-round`); duplicates of a frame are ignored (`duplicate-frame`); reordered
non-last pieces are fine and an early last piece takes what it can (what stays missing is asked again by
the vector); a collect answer that is lost has already deleted its messages at the relay, so the round
times out and is asked again. A dropped or lost message never leaves a gap in a replica: merging holds
changes behind a gap and the next round fills it. `tests/sync/fullstack.test.ts` runs 120 seeded schedules
with losses, duplicates, reordering, lost collect answers, forged `from` and clock jumps past 30 s, and
asserts that the three devices converge, with no refusals.

## Report and codes

`syncOnce(config, state, replica, nowMs)` returns `{ ok: true, replica, report }` or `{ ok: false, reason }`
(`busy`, `not-enrolled`, `bad-input`). The report holds the derived `trust`, `newlyRemoved`, `peers`,
`present`, `collected`, `applied`, `framesSent`, `messagesSent`, `dropped` (by code, this step), `passed`
(files of trusted devices that are not sync packets, for example key grants: hand them to `acceptGrant`),
`events`, `busy` and `nextMs`. Totals since the state was made: `totals(state)`. The cadence: fast
(`RECOMMENDED_POLL.busyMs`) while a round or queued frames exist or for `busyHoldMs` after a frame came or
went, slow (`idleMs`) otherwise, and after a failed collect 2, 4, 8 ... seconds up to a minute.

## Codes

| Code                    | Kind     | Meaning                                                                                             |
| ----------------------- | -------- | --------------------------------------------------------------------------------------------------- |
| `unknown-sender`        | inbound  | the relay id is no trusted peer's (not on the list, or no relay id in the entry)                    |
| `removed-sender`        | inbound  | the relay id belongs to a device whose removal counts                                               |
| `frame-refused`         | inbound  | the frame is malformed or over the framing limits                                                   |
| `duplicate-frame`       | inbound  | a frame that was already taken (counted, not an error)                                              |
| `not-a-file`            | inbound  | the assembled bytes are not exactly a file of this app                                              |
| `wrong-recipient`       | inbound  | the file is addressed to another device                                                             |
| `sender-mismatch`       | inbound  | the file names another sender than the relay id says (a forged or misrouted `from`)                 |
| `sender-not-trusted`    | inbound  | the sender named in the file is no peer now                                                         |
| `cannot-open`           | inbound  | the file does not open with the sender's agreement key (damaged, forged, wrong key)                 |
| `bad-packet`            | inbound  | the file opened but its payload is not exactly a sync packet                                        |
| `ignored-message`       | inbound  | a `done` message (never sent by this layer)                                                         |
| `ask-rate-limited`      | inbound  | more asks from one peer than the window allows                                                      |
| `duplicate-ask`         | inbound  | a repeat of an ask that was answered                                                                |
| `stale-round`           | inbound  | an answer for no round of ours (late, repeated, or another peer's)                                  |
| `duplicate-piece`       | inbound  | a piece of the round that was already taken                                                         |
| `unknown-set`           | inbound  | the packet names a data set that is not registered here                                             |
| `set-not-allowed`       | inbound  | the set (or the mailbox) may not be exchanged with this peer (the app's `mayExchange` / `mayCarry`) |
| `post-disabled`         | inbound  | a mailbox packet while no envelope traffic is configured                                            |
| `post-refused`          | round    | a mailbox exchange ended: a message out of order, unreadable or over a limit (detail: the reason)   |
| `round-timeout`         | round    | a round got no complete answer in time; it is asked again                                           |
| `round-overflow`        | round    | too many pieces in one round                                                                        |
| `round-refused`         | round    | the log layer refused the round (detail: refusal and reason); nothing of it was taken               |
| `diverged`              | round    | an ask's tips contradict our log (no culprit named, `detail` is the device whose history differs)   |
| `stand-too-large`       | round    | an ask whose vector is over the log's limit                                                         |
| `answer-too-large`      | round    | an answer does not fit `maxFramesPerAnswer` even at the smallest budget                             |
| `seal-failed`           | outbound | sealing or framing a message failed (detail: the reason code)                                       |
| `outbox-full`           | outbound | the peer's queue is full                                                                            |
| `outbox-expired`        | outbound | a queued message waited longer than `outboxMs`                                                      |
| `drop-failed`           | outbound | the relay call failed (detail: kind); the message is gone, the round repeats                        |
| `drop-refused`          | outbound | the relay refused this recipient (detail: kind, e.g. `recipient-full`)                              |
| `recipient-not-trusted` | outbound | queued for a device that is no peer any more: dropped, never sent                                   |
| `no-relay-id`           | roster   | a trusted device whose entry has no usable relay id: it cannot be reached                           |
| `relay-id-clash`        | roster   | two trusted devices name one relay id: both are left out                                            |
| `self-removed`          | step     | this device's own removal counts: the step does nothing else                                        |
| `collect-failed`        | step     | the collect failed (detail: kind)                                                                   |
| `collect-interrupted`   | step     | a later collect call failed; what was collected is used                                             |

## What is NOT protected

- The relay sees app, device ids, sizes, timing and who talks to whom. Frames and sealed files hide content,
  not that an exchange happens.
- A removed device keeps what it already has (data and keys); the package stops sending to it and
  hearing it, and offers the rotation of the group key, which protects only what is written afterwards.
- Until a device has learnt of a removal (through a trusted peer) it still answers the removed device.
  The window is the time for the removal to travel; no clock decides it.
- A compromised trusted device can pass on a removed device's signed changes; the log accepts them
  (the signature is valid). Restrict with `mayWrite`.
- A file is authenticated by the static agreement keys of both devices (no signature, no replay protection,
  no forward secrecy against those keys; see `docs/wire-format.md`, "Encrypted file"). The sync is
  idempotent by design.
- A relay can drop, delay, duplicate and reorder; a device that is offline for more than 30 s misses what was
  dropped meanwhile and catches up by the vector at the next meeting. There is no store-and-forward at the
  relay; the mailbox exchange between devices is the store-and-forward (an envelope sits in a mailbox for 30 days).
- A mailbox exchange moves at most the newest `maxExchangeEnvelopes` envelopes a round; a message lost or
  reordered by the relay ends the exchange and costs one new one. An envelope is delivered at least once to
  a reader whose carriers meet it, never exactly once: apps must be idempotent.
- Nothing is persisted by the driver: after a restart every peer is asked again. The replicas and the mailbox
  are the caller's (`storeReplica`, `storeMailbox`); the stand memory of the file flow is too.
- A trusted peer can make this device pull rounds (an ask that claims to be ahead) and spend answers; both
  are bounded per window and per round.
- Not run against a real relay; the reference server was written from the protocol document.
