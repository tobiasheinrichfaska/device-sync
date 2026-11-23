# Review by approvers (log layer)

A second way to let some devices check what other devices write, next to hold-back (`docs/approval.md`).
Here **everything is merged as usual** and the review state is **derived from the log**: what an approver
wrote is approved, what anybody else wrote is a request until an approver write that knew it settles it.
Nothing is stored and nothing is held outside the replica; `src/log/review.ts` is pure (no clock, no
randomness) and only a function of the replica and of the app's `isApprover`.

## Which model to use

|                                    | hold-back (`approval.ts`)                                       | review (`review.ts`)                                                                                     |
| ---------------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| what an unapproved change does     | not applied: it waits outside `log`, `vector` and `collections` | applied like any change; the data is in the replica                                                      |
| who sees an unapproved value       | nobody until approved (stronger privacy)                        | every device that holds the change; the approved view hides it                                           |
| the approved state                 | the replica itself                                              | `reviewView(replica, config)`, derived                                                                   |
| requests, conflicts                | the app builds them from `pendingApproval` and the replica      | `reviewRequests`, `reviewConflicts`, derived                                                             |
| a decision                         | local state (`approve`, `reject`), per device                   | a write to the log (`approveChange`, `keepValue`, ...); it travels and settles the field on every device |
| the requester sees its own request | no (the change is not in its view of the approved data)         | yes, as a request against the approved view                                                              |
| two approvers disagree             | each decides for itself                                         | a conflict (`approver-clash`), ended by one more decision                                                |

Use hold-back when unapproved data must not enter the data set at all. Use review when everybody should
see what is asked for, when the approvers want both views (approved and with all changes), and when a
decision must reach every device. **Do not put one collection under both models**: a change that the
hook applied after approval would show up here as a request again. They do not interfere otherwise: the
review never reads or writes `Replica.approval`, `mergeApproved` never reads review state, a decision is an
ordinary `write` (it keeps `approval` as it was), and the derived conflict notices of `merge` stay as they
are (a decision that knew the heads settles the notice too). Scope the review to its collections with
`reviewed`.

## What the app passes

```ts
const config: ReviewConfig = {
  isApprover: (device) => roleOf(device) === 'office', // the only app-specific question
  reviewed: (collection) => collection !== 'times', // default: every collection
  hiddenField: 'deleted', // the soft-delete field, default DELETED_FIELD
};

reviewView(replica, config); // the approved view, a Replica (read it with visibleRecords, valuesOf)
reviewRequests(replica, config); // pending requests, conflicts first
reviewConflicts(replica, config); // the three kinds of conflict
reviewSettlements(replica, config); // approver conflicts that an approver already settled
review(replica, config); // all three in one pass

approveChange(replica, request, config, { origin }); // "take over"
keepValue(replica, request, config, { origin }); // "keep"
correctValue(replica, request, value, config, { origin }); // "correct"
approveAll(replica, requests, config, { select, origin }); // "take all"
takeApproverValue(replica, conflict, value, config, { origin }); // pick one of several approved values
```

`isApprover` must be a pure function of the device and of state that every device derives alike from the
log (for example a role from the trust layer); a throwing answer counts as `false`. Two devices that hold
the same changes but answer differently derive different views, which is the app's fault, not a divergence of
the log. There are no marks to store: a decision is the approver's ordinary write of the field, and the fact
that its `knew` covers a request is what settles that request.

## Rules

1. **Approved value of a field**: the newest write (the order that decides values) of any approver.
   A field no approver wrote is not in the approved view; a record no approver wrote is not there.
   Finally deleted records stay deleted. Collections that are not reviewed pass unchanged.
2. **Request**: the newest write of every non-approver device to a field, unless an approved write knew it,
   it asks for the approved value already, or a newer write that asks for the approved value answered it.
   An earlier write of a device counts no more. A record an approver hid (`hiddenField` true) has only
   the request to bring it back open.
3. **Knowing is transitive.** A `knew` names the heads only, so what a head knew counts too; two
   writes are concurrent when neither knew the other. This is computed from the log, not read from one
   `knew`.
4. **Conflicts** (all derived, none stored):
   - `concurrent-requests`: two requests to one field that did not know each other and ask for different
     values;
   - `approval-not-known`: a request that did not know the field's last approved write;
   - `approver-clash`: approved writes of several approvers that did not know each other and carry
     different values (only the newest applies, as the usual rule says).
5. **Decisions** are writes of an approver device (`replica.device`), so they carry the heads they saw in
   `knew`. `approveChange` writes the request's value, `keepValue` the approved value again (a field no
   approver wrote gets `null`; a record no approver wrote at all is hidden through `hiddenField`),
   `correctValue` another value, `takeApproverValue` one of the values of an `approver-clash`.
   `approveAll` writes one change per record and takes only requests without a conflict (a field
   with any conflict is left for one-by-one decisions, also its requests without one).
6. **Two approvers deciding the same conflict** converge by the log's own rules: the same value leaves nothing
   open, different values make a new `approver-clash` of the two decisions, ended by one more decision
   (the later decision wins; the other device takes note, without an error). `reviewSettlements` lists the
   approver conflicts that an approver write has settled, so another approver can be told "someone decided
   this"; it is derived and stays, so the app keeps its own list of the ones it showed (key `device#seq`).
7. **Removal of an approver**: when the app's `isApprover` stops answering `true` for a device, what that
   device wrote is a request again (against the approved value of the remaining approvers), its decisions no
   longer settle anything, and it cannot decide (`not-approver`). A conflict on a record an approver hid is
   still reported, but its requests are not open (rule 2).

## Codes

A refusal is `{ ok: false, reason }`; the reasons of `write` (`record-deleted`, `invalid-name`,
`too-large`, `field-rules`, ...) pass through. The ones the review adds, and the kinds of conflict:

| Code                    | Meaning                                                |
| ----------------------- | ------------------------------------------------------ |
| `not-approver`          | this replica's device is not an approver               |
| `not-reviewed`          | the collection is not reviewed                         |
| `no-record`             | the record does not exist here                         |
| `not-an-approver-clash` | `takeApproverValue` was given another kind of conflict |
| `unknown-value`         | the value is not one of the conflict's values          |
| `concurrent-requests`   | conflict kind                                          |
| `approval-not-known`    | conflict kind                                          |
| `approver-clash`        | conflict kind                                          |

## Cost and limits

Linear in the writes of the reviewed records: a record's writes are read once through the record index and
sorted, and every field is analysed with the writes it has. A field written by many different devices costs
the product of its writes and its writers (the same bound as the notices of `merge`); a field that only
approvers wrote, and only one of them, is not analysed at all. The tests run 24 000 writes in a fraction
of a second and check the doubling ratio (`tests/log/review.test.ts`).

## What it does not do

- It does not authorize anything: `mayWrite` and `allowFinalDelete` decide who may write; the review only
  decides what counts as approved. A device that is not an approver can still write; it makes requests.
- It hides nothing: every device holds the unapproved data (use hold-back for that).
- It does not store which hints a person has read; settlements are derived and the app marks them.
- The approved view is a `Replica` value with `notices` empty; `historyOf` on it still reads the full log.
