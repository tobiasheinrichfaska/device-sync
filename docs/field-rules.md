# Field rules (log layer)

An app has rules the package cannot know: which collections have which fields, what a value must look
like, who may touch an existing record. `fieldRules` is the hook for them. It is not part of the wire
format and changes no bytes; it only refuses.

```ts
type FieldRules = (change: Change, state: Replica) => string | undefined;
```

It returns `undefined` when the change is fine, else a short code (1 to 120 characters; the package
never shows or translates it). It must be a pure function of its two arguments and fast: it runs once
per change. `change.fields` is absent for a final deletion.

## Where it runs

| Where                                                              | How to pass it                                                            | What a refusal is                                                                                                                                       |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| local writing (`write`, `remove`, `softDelete`, `restore`, `undo`) | `ParseOptions.fieldRules` (the options object the writing functions take) | `{ ok: false, reason: 'field-rules', detail: code }`; nothing is created, so a device never makes a change its peers would refuse and block itself with |
| a session (`receiveJudged`)                                        | `JudgeOptions.fieldRules`, or `SessionOptions.fieldRules` as the default  | the whole session is refused: `Session.refusal` `forged`, `refusalReason` `field-rules`, `refusalDetail` the code, `refusalDevice` the author           |
| a batch (`readChanges`, `judgeChanges`)                            | `JudgeOptions.fieldRules`                                                 | verdict false, `Rejection.reason` `field-rules`, `Rejection.detail` the code                                                                            |
| the retained changes of a snapshot (`catchUp`)                     | `JudgeOptions.fieldRules`, or `CatchUpOptions.fieldRules`                 | the snapshot is refused: `forged`, `rejection.detail`                                                                                                   |

The strict parsers (`parseChange`, `parseSyncMessage`) check structure only and do not call it: they
have no replica.

On the receiving side it is asked last, after the structural checks, the signature, the hash chain,
`allowFinalDelete` and `mayWrite`, and never for an erased change (it has no content). A rule that
throws, or answers anything but `undefined` or a text of 1 to 120 characters, refuses with the code
`invalid-rule-answer` (fail closed). The cost is one call per change a session reads; the rule's own
cost is the app's.

`state` is the replica as it was before the batch or piece the change arrives in, never the half
merged one: all devices decide alike whatever the order inside one session. So a rule must not rely on
an earlier change of the same session being visible (one that creates a record and one that changes it
arrive together; decide ownership from the record id or the author, as `mayWrite` does).

## Rights and whole-file rejection

`mayWrite` and `fieldRules` have the same consequence for a session: one refused change refuses
everything the session carries, so the numbering of every device stays gapless and the replica stays
exactly the value it was (nothing of earlier pieces is taken). The same session is refused again next
time, so a sender that holds a change the receiver refuses is blocked until the receiver's rule or the
sender's log changes. An app avoids this by letting its devices run the receivers' rules on their own
log before sending (`judgeChanges` on the changes of other authors, `fieldRules` through local
writing), and by dropping a device's changes it will never accept through the approval layer's
`reject` (`docs/approval.md`), which keeps the number and refuses the content without ending the
session.
