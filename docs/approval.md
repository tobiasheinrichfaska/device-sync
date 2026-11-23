# Hold back until approved (log layer)

A different model, where everything is applied and the approved view is derived from the log, is in
`docs/review.md`; it explains which of the two to use.

An app can ask, for every change that arrives, whether it is applied now, held back until a person
or a rule approves it, or rejected. The package supplies the mechanism (`src/log/approval.ts`); the
app supplies the decision (a hook) and the user interface. Without a hook nothing changes: `merge`,
`write` and the sessions behave exactly as before, and `merge` never reads the approval state.

## What the app writes

```ts
const hook = (change: Change, replica: Replica): ApprovalDecision => 'apply' | 'hold' | 'reject';

// receiving (a session, or a plain batch)
step = receiveJudged(session, replica, raw, judge, { approval: { hook } });
result = mergeApproved(replica, changes, { hook });

// later, from a screen or a rule
pendingApproval(replica); // what waits, by device and number
result = approve(replica, [{ device, seq }]);
result = reject(replica, [{ device, seq }]);
result = decide(replica, (change) => 'approve' | 'reject' | undefined);

// storing: replica.approval is plain JSON; read it back strictly
const read = readApprovalState(JSON.parse(text));
```

`true` from the hook means `apply`, `false` means `hold`; a hook that throws or answers anything else
holds (nothing is applied by accident). The hook is asked once per change that is new to the replica
(not applied, not already held), and only for `set` and `delete`. It gets the replica as it was when
the call began, never the half merged one, so the answer cannot depend on the order inside one batch.
**For replicas to converge, answer from the change alone** (device, author label, collection, record,
field names, values); a hook that reads state (`deviceStatus`, the time) answers differently on two
devices and they hold different sets, which is the app's choice and not a fault. A change that is
sent again while it is held is not asked again.

## What each answer does

**apply**: merge takes the change as it always did (gapless number, `knew`, clock).

**hold**: the change goes to `Replica.approval`, outside `log`, `vector` and `collections`:

- no stand and no `done` claims it, so the peer sends it again, and the held copy is the one that
  counts; the replica does not look different from one that never received it;
- the author's later numbers and changes that name it in `knew` wait exactly as they wait for any gap
  or causal hold: merge leaves them in `held` and does not store them (they come again in a later
  session, as before);
- the hash chain and the equivocation check see only the log: a held change is judged (signature, key,
  rights) when it arrives, but is not compared with another version of the same number until it has
  been applied. Rights can change before the approval: the app decides again at approval time;
- bounded: at most `maxPending` changes and `maxChars` characters; what does not fit is not kept
  (`ApprovalReport.dropped`) and comes again;
- while any change is held the fingerprints of two devices differ although nothing was cut:
  `outcome().equal` is false, `complete` stays true (it only says nothing was cut) and
  `outcome().held` counts the changes this replica holds back (waiting for a decision, or decided and
  waiting to be applicable). An app that sees `complete && !equal && held > 0` decides and compares
  again after the decisions; it does not repeat sessions on `!equal` alone (a second session brings
  the same held changes again and changes nothing). `held` is 0 without a hook. It counts only this
  side: the wire carries no hold of the peer, so `complete && !equal && held === 0` can still mean
  that the PEER holds changes of ours (look at its `held`, on its side).

**approve**: marks the held change decided and runs merge over everything decided. Merge applies it in
a correct order (the number before it, the changes it names in `knew`, the clock); one that cannot
be applied yet (a number before it is still held) stays decided and applies as soon as that arrives.
Decisions are final: an approved or rejected entry is never asked again.

**reject**: drops the content for good and keeps the number. The change is applied as an erased change
(`kind: 'redacted'`): head, hash-chain link, check value and signature stay, the content is gone. The
author's later changes are not blocked, and changes that name it in `knew` find it satisfied. Rejection
only exists for a write (`set`). What follows from this:

- the replica does not forward it, nor anything that follows it from its author: peers refuse an erased
  change of a record that is not deleted, so the sender leaves it out (`Session.withheld` counts) and
  everything later of that device with it. A device that never saw the change gets it from a device
  that applied it, not from the rejecter. Another device's changes that name it in `knew` are cut as
  well, since the receiver could not apply them;
- the rejecter's stand still claims the number (it holds it as an erased change), so peers do not
  send it again;
- a rejecting device and an approving device end with different data. They are not refused or forced to
  agree: the exchange takes no notice, apart from the differing fingerprint.

**A final deletion cannot be rejected, only held or approved.** The erased changes that other devices
made because of it reach us only together with it; rejecting it would make later honest peers send
erased changes of a live record, and the session judge would refuse them. A hook that answers `reject`
for a deletion holds it; `reject` and `decide` leave a held deletion held. A deletion held for ever
blocks its author's later numbers, which is what "never approved" means; an app that does not want
that device any more removes it in the trust layer.

## Final deletions and their erased changes

An erased change of a record is applied only together with the record's deletion. So:

- a held deletion holds the erased changes that come with it (in the same call or later, while it is
  held); they cannot be decided alone and follow the decision on the deletion;
- an erased change that merge would apply while its deletion cannot be applied in the same call (it
  waits behind a held change of its author, say) waits too. The merge is tried and, if it applied one
  wrongly, tried again without it; after 16 rounds every erased change of a live record is left for the
  next call. Normally this costs one merge;
- a write that is held for a record which then gets deleted loses its content on the spot: the entry
  becomes an erased change and is applied, nobody is asked, no content is kept in the state. A write
  to an already deleted record is not asked either;
- if a deletion does not fit into the bounds, its erased changes do not pass without it.

## What is deliberately not covered

- **The judging layer assumes everything is applied.** `readChanges` / `receiveJudged` verify
  signatures, check codes, rights and erased changes against a replica as it would be with everything
  merged; they do not know about holds. That is right for what they decide (a change is genuinely its
  author's) but not for derived state: a held `addDevice` still lets that device's own changes be
  verified in the same batch. The hook sees those changes too and should hold them as well.
- **Equivocation** between a held change and a second version of the same number is not seen until
  one of them is applied.
- **Order across calls.** The result is the same for any order of arrival, any cutting into sessions
  and any moment of decision (`tests/log/approval-property.test.ts`) only for a hook that answers from
  the change alone.
- **Cost.** A call costs the batch plus the held entries (at most `maxPending`); a session that repeats
  changes the replica holds does not call the hook for them. Signatures of held changes are verified
  again when they are sent again, as for any change the replica does not hold.

## Stored state

`replica.approval` is `{ entries: [{ change, decision }] }`, sorted by device and number, plain JSON.
`decision` is `hold` (waits for the app), `approved` or `rejected` (decided, waits until it can be
applied). `readApprovalState(raw, options)` reads it strictly and never throws: exactly those members,
each change as the parser reads it, no number twice, only a write can be `rejected`, within the bounds.
It is local state: signatures are not checked again (they were judged when the change arrived).
Restore it with `{ ...replica, approval: read.state }`. Entries whose number the replica has since
passed are dropped at the next approval-aware call.

## Limits

| Name         | Value     | Meaning                                                   |
| ------------ | --------- | --------------------------------------------------------- |
| `maxPending` | 2000      | Entries the state holds (override with `ApprovalOptions`) |
| `maxChars`   | 8_000_000 | Characters of the JSON of all held changes together       |

## Codes

| Code             | Meaning                                                                             |
| ---------------- | ----------------------------------------------------------------------------------- |
| `not-object`     | `readApprovalState`: not a plain object                                             |
| `unknown-member` | the state has a member other than `entries`                                         |
| `bad-entries`    | `entries` is not a list                                                             |
| `too-many`       | more than `maxPending` entries                                                      |
| `too-large`      | more than `maxChars` characters of changes                                          |
| `bad-entry`      | an entry is not exactly `{ change, decision }`                                      |
| `bad-decision`   | a decision that is not `hold`, `approved`, `rejected`, or `rejected` on a non-write |
| `bad-change`     | a change the strict parser refuses                                                  |
| `duplicate`      | one device and number twice                                                         |
