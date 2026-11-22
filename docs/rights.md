# Rights at the receiver that look at the batch (`JudgeOptions.rights`)

**New, not yet reviewed.** The plain hooks `mayWrite`, `allowFinalDelete` and `fieldRules` see the replica
as it was before the batch and, for `mayWrite`, only the author's id. A rule such as "a helper device
may change a row a coordinator device made for it" needs two things more: the author's **role**, and the **earlier
changes of the same batch** (the coordinator made the row in the very file that carries the edit). The `rights`
option gives both. Nothing changes for an app that does not pass it. This document is held to the code by
`tests/trust/rights.test.ts`.

```ts
const rights: RightsOptions<TrustView> = {
  view: rightsView(direct, trustOptions), // built once per batch (trust layer)
  rank: (author, view) => (view.roleOf(author) === 'coordinator' ? 0 : 1),
  mayWrite: (author, change, state, view) => /* true | false | 'a-code' */,
  allowFinalDelete: (author, change, state, view) => view.trusted(author) && view.roleOf(author) === 'coordinator',
  fieldRules: (change, state, view) => /* undefined | 'a-code' */,
};
// readChanges(replica, changes, { ...judgeOptions, rights })   or   syncOnce({ ..., judge: { rights } })
```

## Batch semantics

1. **Once per judged batch, never per piece.** The stage runs where a batch is closed: `settle` (the end of a
   session, `readChanges`), `judgeChanges` / `judgeDetailed` (one call) and `judgeRetained` (a snapshot).
   It looks at the changes whose signatures verified and that are about to be taken. So the verdict does not
   depend on how a session was cut into pieces or in what order the changes arrived.
2. **The view** is built once, from the replica as it would be with EVERY verified change of the batch
   merged: a device the batch introduces has its role. The trust layer's `rightsView(direct, options)` is the
   usual one: `TrustView` with `roleOf(device)` (the role as vouched, also for a device that fell out of trust:
   it keeps the role it had for what it wrote before), `trusted(device)`, `fallenOut(device)` and the whole
   `trust`. The derivation is synchronous (`computeTrustSync`) and counts the log as judged: the stage runs
   after the signatures verified, nothing is checked twice.
3. **Order.** The changes are asked in ascending `(rank(author, view), device, number)`. The default rank is 0
   for everybody, so the order is by device and then number, and one author's changes are asked in the order it
   wrote them. An app that lets authors act on what other authors made puts those first (the coordinators before the
   helpers). A device id decides nothing when the app gives a rank.
4. **State.** Each hook gets the state as it stands with the changes asked EARLIER and allowed: its
   `collections` hold them (the same last-write rule as `merge`); `log`, `vector` and `notices` are those before
   the batch. The object is one working copy changed in place between calls: read it, never keep it.
5. **Refusal.** One refused change refuses the batch (one false change and nothing is taken, as always): the
   session ends `forged`, the reason is `not-allowed` (from `mayWrite`), `delete-not-allowed` (from
   `allowFinalDelete`) or `field-rules`, and `detail` carries the app's code. A hook answers `true` (allow),
   `false` (refuse), or a text of 1 to 120 characters (refuse with that code). A throw, or any other answer,
   refuses with the code `invalid-rule-answer`; a `view` or `rank` that throws, or a rank that is not a whole
   number, refuses every change of the batch with the same code.
6. **Together with the plain hooks.** The plain hooks still run first, per change, against the state before
   the batch; both must allow. Giving `rights.allowFinalDelete` lifts the default refusal of every final
   deletion (it is the app's rule then); without it a final deletion is refused as before.
7. **Cost.** One merge of the batch, one `view`, one sort, one fold per allowed change (a collection is copied
   once, when first touched): linear in the batch (8000 changes in a few milliseconds, `tests/trust/rights.test.ts`).
   The hooks' own cost is the app's.

## What it does not do

- A partial session (`more`, `Session.truncated`) holds only a prefix of the sender's log: a rule that needs
  a change of another author that was cut off refuses the batch until the next session brings it. Where that
  matters, decide ownership from the record id or the change itself, or raise the session limits.
- The stage does not run for a piece on its own, so a hostile piece is refused at the end of the session, not
  at its piece, when the refusal is the stage's.
- The removal of a device is the trust layer's: `view.fallenOut(device)` tells a device that is removed (or
  vouched only through a removed device) from a trusted one. A removed device stays checkable; whether it may
  still write is this hook's answer.
