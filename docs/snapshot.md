# Snapshot and catch-up (log layer)

A device that joins late would have to fetch the whole change log of every device. A snapshot is a
condensed state a device that holds a lot can hand over, so the late device starts from it and
only fetches what came after. The mechanism is `snapshot` (make one), `catchUp` (start from one) and
the strict readers `parseSnapshot` / `parseSnapshotText`, in `src/log/snapshot.ts`. Which device
makes snapshots, and which producer a receiver believes, are the app's decisions.

## What a snapshot holds

```ts
interface Snapshot {
  v: 1; // SNAPSHOT_VERSION
  set: string; // data set, as in a change signature
  producer: DeviceId; // the device that made it and signed it
  clock: number; // the producer's Lamport clock
  vector: VersionVector; // what the snapshot stands for: per device the highest number
  fingerprint: string; // the producer's fingerprint of its data
  changes: Change[]; // the retained changes, real and signed, ordered by device and number
  sig: string; // the producer's signature
}
```

The **retained changes** are real changes with their own signatures, not summaries. Per record that
is not deleted, and per field: the last write of every device, and for each of those the write with
the highest `knew` of that device when it covers the last write (what settles a conflict). Of a
deleted record: the first final deletion. Of every device: the change at its number in the vector
(the tail). Everything a replica derives from its log is the same from the retained changes as from
the whole log: the values, the winner of each field, the conflict notices, and what a later change's
shortened `knew` names (tests: `tests/log/snapshot.test.ts`, seeded schedules against full-log
devices). What is lost is the history: `historyOf`, `fieldHistory` and `undo` see only retained writes.

The tail is what lets later changes chain and verify: the next change of a device carries `prev` =
the link of the tail, and a `stand` names the link of the tail as its tip.

The **signed text** is the marker (`<app>-snapshot:1`) and the canonical form of version, data set,
producer, clock, vector, fingerprint and a digest of the links of the retained changes (a link is a
hash of a change's whole signed head). A forwarder can therefore neither add nor leave out a change
nor change the vector.

## Wire form and limits

A snapshot is one JSON text (`JSON.stringify(snapshot)`), possibly many megabytes. A transport cuts
it into frames itself (the relay layer's `splitPayload` serves); this layer does not frame.

| Limit                | Default   | Meaning                                                              |
| -------------------- | --------- | -------------------------------------------------------------------- |
| `maxSnapshotChanges` | 400000    | retained changes; more is refused (`unreadable`), never cut          |
| `maxSnapshotChars`   | 128000000 | the snapshot as JSON (UTF-16 units); a text over twice it is refused |

The reader (`parseSnapshot`, `parseSnapshotText`, never throws) is strict: exactly the members above,
every change read by `parseChange` and carrying `sig` and `check`, strictly increasing by (device,
number), no number above the vector, no clock above the snapshot's, no `knew` beyond the vector, the
tail of every device present, consecutive retained numbers of one device chained (`prev` = link of the
earlier), an erased change only beside the deletion of its record, no key twice in the text.

## Making one

`snapshot(replica, { appId, dataSet, signingKey })` is async. Every change of the log must be signed
already (`signOwnChanges`, `insertSignatures`). Any device can make one, also one that itself started
from a snapshot. It returns `{ ok: false, reason }` with the codes below.

| Code                      | Meaning                                                     |
| ------------------------- | ----------------------------------------------------------- |
| `unsigned`                | a change of the log has no signature yet                    |
| `missing-history`         | the log lacks the change at a device's number in the vector |
| `erased-without-deletion` | an erased change whose record's deletion is not in the log  |
| `too-large`               | over `maxSnapshotChanges` or `maxSnapshotChars`             |

## Starting from one

```ts
const result = await catchUp(replica, snapshotTextOrObject, {
  judge, // appId, dataSet, keys, ownDevice, mayWrite, allowFinalDelete, fieldRules ...
  trustProducer: (producer, info, replica) => boolean, // REQUIRED, no default
});
// { ok: true, replica, added, fingerprintChecked } | { ok: false, reason, rejection? }
```

`catchUp` takes nothing unless the whole snapshot passes; the caller keeps the old replica on a
failure. Order of the checks: strict reading; the app's trust hook (sees only the head: data set,
clock, vector, fingerprint, number of changes); the producer's key and signature; every retained
change judged like a received one (signature, check value, hash chain against what is held,
`own-history`, `mayWrite`, `allowFinalDelete`, `fieldRules`); at last, for a replica that held
nothing, the result against the signed fingerprint. The replica may be empty or already hold changes:
the snapshot adds the retained changes above what it holds, raises the vector and keeps the rest.
With a key source that is `selfVerifying` (the trust layer's), the device list inside the snapshot may
make the authors and the producer known.

| Code                     | Meaning                                                                           |
| ------------------------ | --------------------------------------------------------------------------------- |
| `unreadable`             | not a snapshot (shape, limits, order, tails, links)                               |
| `untrusted-producer`     | the hook said no (or threw)                                                       |
| `unknown-producer`       | no key for the producer                                                           |
| `bad-producer-signature` | the signature, data set or app does not match                                     |
| `forged`                 | a retained change is false; `rejection` names it and the reason (as in a session) |
| `unknown-author`         | no key for the author of a retained change                                        |
| `inconsistent`           | an empty replica does not end with the data the producer signed                   |

`Replica.base` (new, optional, plain JSON) remembers per device the number up to which the log is
condensed. It is why a caught-up replica behaves a little differently as a sender: it can hand out
only what lies above its base. A peer whose stand is below it for some device gets nothing of that
device (`Session.withheld` counts it, `needsSnapshot(replica, stand)` names the devices): that peer
must start from a snapshot too, or exchange with a device that holds the whole log. `missingFor`
leaves such changes out the same way.

## What a snapshot cannot prove

**The condensed part is believed on its producer's word.** The retained changes are each true (signed
by their authors, judged by the receiver's rules). What no receiver can check is that the set is
complete and the stand honest:

- a producer can leave out a write, a deletion or a whole record (the receiver then lacks it, and
  because the vector says the number is covered, no later session brings it back);
- a producer can claim a vector that is higher than what it holds (a gap that is never filled), or
  lower (harmless: the receiver fetches more);
- it cannot invent a write, change one, move one to another author, or make a change chain to a
  history other than the signed one: those fail the signatures.

The fingerprint catches a producer that was careless or buggy (a receiver that starts empty ends with
other data than the one the producer signed: `inconsistent`). It does not catch a producer that
leaves something out and signs a fingerprint of what it shows; tests pin both.

What an app does:

1. Accept snapshots only from producers it trusts for the data (`trustProducer`): a device a person
   met, an office device, never "whoever answers". A removed or untrusted device is refused here.
2. After catching up, exchange with a device that holds the whole log (or another producer). A
   session that is `complete` with equal vectors but unequal fingerprints (`Outcome.equal` false)
   means the condensed part differs: drop the replica and start again from another producer. A
   snapshot of a snapshot passes the same doubt on; an app that wants certainty keeps one full-log
   device.
3. Keep a device that makes snapshots full-log or itself checked; the producer is the one place where
   an honest majority does not protect.
4. A device that restores an old backup of ITS OWN id is refused (`own-history`): it enrols with a
   new device id (as everywhere in this package).

Also not covered: two versions of one number below the base are never seen (the changes are not
held), the history of old writes (see above), and a snapshot is a point in time: it is neither
revoked nor refreshed, a receiver that takes an old one only fetches more afterwards.

## Cost

Producing is linear in the log (one pass; memory per record, field and writing device). Starting from
one costs one signature check per retained change (about 2 s per 12000 on a laptop; most of it) and a
linear merge. The retained changes are the current state plus the last write per device and field:
for 3000 records written four times each the 12000 changes become about 3000 (`tests/log/snapshot.test.ts`).

## Format

Version 1. The format of a change is unchanged; `Replica.base` is optional, so stored replicas stay
readable. The limits table in `docs/wire-format.md` lists the two new limits.
