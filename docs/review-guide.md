# Review guide for a human security reviewer

**Status of this package: not security-reviewed by a human.** Four adversarial review rounds were run by
AI; they found real problems (section 5), which is a reason to expect more, not a sign of safety. Nothing
here is an approval. This guide is written for a cryptographer or application-security engineer who has
never seen the code. It says where to look first, what the code claims, which tests guard each claim, and
what is known to be missing. Every path in backticks was checked to exist (`tests/review-guide.test.ts`
fails if one does not); the claims were checked against the source and the documents named next to them.

Reading order if you have little time: section 2 (what is defended), the first four rows of section 3
(session, file, envelope, signatures), then section 6 (accepted limits) and section 7 (questions).

## 1. What the package is

A TypeScript package (ES modules, Node 24 and browsers, WebCrypto only, one runtime dependency:
`@noble/hashes`, used for SHA-256 in `src/core/encoding.ts`) for offline-first web apps whose users each
hold the data on their own devices and synchronise device to device.

Intended deployment, as the documents describe it:

- Every device has an ECDSA P-256 signing key and an ECDH P-256 agreement key, generated non-extractable
  in the browser (`src/core/keys.ts`, `src/browser/keystore.ts`).
- Data is a **signed, gapless change log per device** (`src/log/`): every change is signed, carries the
  link of the same device's previous change (hash chain), and replicas converge by merging. The merge rules
  are generic; record shapes, rights and texts are the app's, passed in as parameters and hooks.
- **Trust is derived**, never stored (`src/trust/derive.ts`): devices met in person are roots, devices
  introduce ("vouch for") other devices through entries in the log, and removals are processed by rank.
- Bytes move between devices through **end-to-end encryption** in three shapes: an interactive **session**
  (`src/core/session.ts`), a one-recipient **encrypted file** (`src/core/file.ts`), and a **sealed
  envelope** for several readers that third devices can carry (`src/core/envelope.ts`, with the mailbox in
  `src/post/`). The payload is opaque bytes; the app puts its stand and changes in it.
- A **relay client** (`src/relay/`) talks to a simple store-and-forward message relay (protocol in
  `docs/relay-protocol.md`). The relay is untrusted; it only carries ciphertext.
- **Web Push** helpers (`src/push/`) build a content-free "ring" so a sleeping device looks at the relay.
- A **browser layer** (`src/browser/`) stores keys as non-extractable `CryptoKey` objects in IndexedDB and
  elects one listener per tab.
- A **transfer** layer (QR, audio, direct connection) is being added concurrently and is not part of what
  this guide covers; treat it as unreviewed and unfinished.

Layers and the parameters-instead-of-constants design: `docs/architecture.md`. Wire formats:
`docs/wire-format.md` (core, log, trust, session, file, envelope, mailbox, cross-language notes),
`docs/relay-protocol.md`, `docs/push.md`, `docs/browser.md`.

How the layers fit together is the app's job today: there is no integration layer yet that runs a log
exchange inside a session over a relay. `tests/trust/fullstack.test.ts` composes log, signing and trust;
no test composes session or envelope with the log exchange.

## 2. Threat model

### Assets

1. Confidentiality and integrity of the synchronised data (the opaque payloads and the change log).
2. The device private keys (signing and agreement).
3. The correctness of the trust decision: which devices may be believed as authors.
4. Availability of synchronisation for honest devices (a hostile member or relay must not be able to
   block everybody for ever, or exhaust memory or CPU).
5. Metadata: who talks to whom, when, how much (partly protected; see the "not protected" lists).

### Attackers

| Attacker                                  | Can do                                                                                                                                    | Defended by                                                                                                                                                                      |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Malicious relay or carrier device         | Drop, delay, duplicate, reorder, replace; see ids, sizes, timing; for a relay holder of its signing secret, enrol or impersonate a device | End-to-end encryption and signatures; counters and strict ordering in the session; idempotence required of apps; envelope hides sender and readers from carriers                 |
| Network attacker                          | The same on the path, replace a hello                                                                                                     | Keys bound to both identities and both hellos; a replaced hello gives a session that fails, never one that accepts forged messages                                               |
| Compromised member device (still trusted) | Sign any change as itself, vouch for others, remove devices it can reach, flood                                                           | Derivation rules limit what survives (key conflicts, removal by rank); hooks `mayWrite`, `quota`, `allowFinalDelete`; **not** prevented: a trusted voucher's choices (section 6) |
| Removed device                            | Keep signing; keep any keys it ever held                                                                                                  | Standing as voucher ends; its changes stay checkable on purpose. **The package does not revoke its ability to write, and group keys do not exist yet** (section 6)               |
| XSS or hostile script in an app's origin  | Use (not export) the non-extractable keys while the page runs; read the stored relay credential                                           | Non-extractable keys, credential kept short-lived. Not defended beyond that (`docs/browser.md`, "What IndexedDB protects and what it does not")                                  |
| Hostile input at every parser             | Malformed, oversized, ambiguous, deeply nested, duplicate-key, prototype-polluting, non-canonical text                                    | One spelling per text, rebuilt-and-compared; size checks before parsing; null-prototype containers; never throw on foreign input; limits as data                                 |
| Hostile member with valid keys (resource) | Many valid small changes, huge stands, many keys per entry, signature-check amplification                                                 | Limits and partial sessions (`src/log/limits.ts`), per-author `quota` hook, candidate-key cap in the derivation; the log itself stays unbounded unless the app bounds it         |

### Explicit non-goals

- Endpoint compromise, malware with access to the browser profile or session, a compromised random
  generator, quantum attacks on P-256.
- Hiding traffic metadata (sizes, timing, device ids in hellos and file headers, the relay's view).
- Forward secrecy against a later leak of a recipient's static key for files and envelopes; a ratchet or
  post-compromise security anywhere.
- Deniability (envelope authors are provably the author; session and file are deniable by construction).
- Replay protection for files, envelopes and push messages (apps must be idempotent).
- Key backup or recovery (a lost key store is a lost device; re-enrol with a new device id).
- Preventing a trusted administrator from choosing any name or role.

## 3. Security claims, the code behind them and the tests that guard them

Ordered by "look at this first". "Docs" names the section that states the claim; the tests tie the text
to the code (`tests/docs.test.ts`, `tests/core/docs-session.test.ts`, `tests/post/docs.test.ts`,
`tests/push/docs.test.ts`, `tests/relay/docs.test.ts`, `tests/trust/docs.test.ts`,
`tests/browser/docs.test.ts` check numbers, codes and examples in the documents against the code).

### 3.1 Session handshake and messages (look at this first)

- **Claim.** Two devices that know each other's static agreement key derive two directional AES-256-GCM
  keys from four ECDH terms (ephemeral x ephemeral, the two crossed terms, static x static) through
  HKDF-SHA-256, salted with a hash of a transcript that binds app id, both device ids, both static keys and
  both ephemeral keys. Counters in clear are the nonces and must arrive strictly in order. Mutual
  authentication is implicit (only the holders of both static secrets derive the keys); forward secrecy
  against a later leak of both static keys; key-compromise-impersonation resistance through the crossed
  terms; reflection impossible (different keys per direction); one ephemeral pair opens one session.
- **Code.** `src/core/session.ts` (`openSession`, `createHello`, `nonceFor`, `usedEphemerals`), shared
  primitives and strict readers in `src/core/secure.ts`, keys and point checks in `src/core/keys.ts`.
- **Docs.** `docs/wire-format.md`, "Wire format: end-to-end layer", sections "Key derivation" and
  "What the session protects, and what it does not".
- **Tests.** `tests/core/session.test.ts` (replay, reorder, reflection, mirrored hello, man in the middle,
  stolen static key, forward secrecy argument, nonce uniqueness, counter limit, strict readers, curve
  checks), `tests/core/secure.test.ts` (UTF-8 byte order of device ids, one spelling per point),
  `tests/vectors/session.json` run by `tests/vectors-session.test.ts` against the code and against an
  independent derivation in `tests/core/reference.ts`.
- **Look hardest at.** The key schedule (is the transcript complete; is the salt/info split sound; the
  `lo`/`hi` ordering by UTF-8 byte order of device ids); the nonce construction; the fact that the hello is
  unauthenticated and a message only confirms the peer after the first verified message (`confirmed`);
  the in-process-only guard against reusing an ephemeral pair; counter handling under concurrent opens.

### 3.2 Encrypted file

- **Claim.** One message for one named recipient from one named sender: key from ECDH(ephemeral, recipient
  static) and ECDH(sender static, recipient static), HKDF with the whole header as salt and as additional
  data; opens only for that recipient, only from that sender, only in that app.
- **Code.** `src/core/file.ts` (`sealFile`, `openFile`, `readFileHeader`), `src/core/secure.ts`.
- **Docs.** `docs/wire-format.md`, "Encrypted file" (layout, derivation, refusals, what is not protected).
- **Tests.** `tests/core/file.test.ts` (tamper sweeps over every character and bit, swapped members, another
  app, round trips, seeded fuzzing of the reader, the documented non-protections shown as passing tests),
  `tests/vectors/file.json` with `tests/vectors-session.test.ts`, reference in `tests/core/reference.ts`.
- **Look hardest at.** The sender authentication by a DH value the recipient can compute itself (so the
  recipient's key can forge "from A"; documented); the nonce being 12 caller-supplied random bytes under a
  per-file key; absence of replay protection.

### 3.3 Sealed envelope for several readers, and the mailbox

- **Claim.** Content is encrypted once under a random content key; the key is wrapped per reader with a
  fresh ephemeral key (ECDH, HKDF, AES-GCM with a zero nonce); the fan is padded with random slots to a
  multiple of 8 and shuffled; inside, the author signs app, sender, channel, day and content. A carrier
  sees an id, a day and a size, not sender, readers or their exact number. A non-reader pays one ECDH,
  one derivation and at most one trial per slot.
- **Code.** `src/core/envelope.ts` (`sealEnvelope`, `openEnvelope`, `readEnvelope`, `envelopeId`,
  `shuffled`), mailbox and per-day exchange in `src/post/mailbox.ts`, `src/post/exchange.ts`.
- **Docs.** `docs/wire-format.md`, "Wire format: envelope and mailbox".
- **Tests.** `tests/core/envelope.test.ts` (hiding of the reader count, slot indistinguishability,
  shuffle uniformity, cost counting, relabelling by a carrier, tamper sweeps, fuzzing),
  `tests/vectors/envelope.json` and `tests/vectors/mailbox.json` with `tests/vectors-envelope.test.ts`,
  independent reference in `tests/core/envelope-reference.ts`, `tests/post/mailbox.test.ts`,
  `tests/post/exchange.test.ts`.
- **Look hardest at.** The zero-nonce wrapping argument; AES-GCM is not key-committing and several slots
  can hold different keys (question 2 in section 7); the author-only signature leaving recipients
  unsigned (a reader can re-seal); the mailbox quota logic as a denial-of-service surface.

### 3.4 Signatures and canonical JSON

- **Claim.** ECDSA P-256 / SHA-256 over the UTF-8 bytes of a text, low-s only, one spelling per signature
  (canonical unpadded base64url, 64 bytes); verification never throws. The signed text of a change carries
  the app marker, the data set, head, content check value and the chain link, so a signature never
  verifies in another app or data set; unknown members that the signature does not cover are refused.
  Canonical JSON sorts keys by UTF-16 code unit and refuses everything that is not plain JSON.
- **Code.** `src/core/signature.ts`, `src/core/canonical.ts`, `src/core/json.ts`, `src/core/encoding.ts`,
  `src/core/markers.ts`, `src/log/signing.ts` (`changeSigningText`, `judgeChanges`, `readChanges`),
  `src/log/check.ts` (check value and `changeLink`).
- **Docs.** `docs/wire-format.md`: "Canonical form", "Signatures" (including the numbered order of
  verification) and "Cross-language notes" (numbers, key order, strings, duplicate keys).
- **Tests.** `tests/core/signature.test.ts`, `tests/core/review2.test.ts` (low-s, check code input
  checks), `tests/core/canonical.test.ts`, `tests/core/markers.test.ts`, `tests/log/signing.test.ts`,
  vectors `tests/vectors/canonical.json`, `tests/vectors/signing-text.json`,
  `tests/vectors/verification.json` (a signed change every port must accept, and variants it must refuse),
  `tests/vectors/check-code.json` run by `tests/vectors.test.ts`.
- **Look hardest at.** Whether every field that influences meaning is covered by a signature or by a hash
  that a signature covers; the number formatting of canonical JSON for other languages; the order of
  verification and which verdict each rule yields.

### 3.5 Trust derivation

- **Claim.** Trust is a function of the set of changes and of the devices met in person, independent of
  arrival order. Potential trust grows by vouching from met devices; removals are evaluated rank by rank
  (all devices of a rank at once, no tie-break by device id); a voucher cannot replace another device's
  keys; what a removed device wrote carries no authority for conflicts; a device whose key was ever
  validly vouched for stays _checkable_ (its signed changes verify) even when no longer trusted.
- **Code.** `src/trust/derive.ts` (one engine, a generator that asks for signature checks),
  `src/trust/devices.ts` (`computeTrust`, `deviceKeySource`, `addDevice`, `removeDevice`),
  `src/trust/voucher.ts`, `src/trust/invitation.ts`, `src/trust/meeting.ts`, `src/trust/known.ts`.
- **Docs.** `docs/wire-format.md`, "Trust (device list, meeting code, invitation)", "Trust derivation"
  (read "What a removal means" first).
- **Tests.** `tests/trust/order.test.ts` (400 random scenarios in every order),
  `tests/trust/reference.test.ts` (differential test against an independent naive reference, 3000+
  scenarios), `tests/trust/review4.test.ts`, `tests/trust/review5.test.ts`, `tests/trust/round4.test.ts`
  (every labelled finding), `tests/trust/chainscale.test.ts`, `tests/trust/fuzz.test.ts`,
  `tests/trust/fullstack.test.ts`, `tests/trust/invitation.test.ts`, `tests/trust/meeting.test.ts`.
- **Look hardest at.** The rules themselves as a design (not only the code): that a removal does not stop a
  device from writing; the per-viewer dependence on devices met in person; the "any voucher can remove
  what it can reach" consequence; the invitation proof (HMAC keyed by a one-time code, verified with
  WebCrypto `verify`) and the 120 second meeting code; the cap of 8 candidate keys per entry.

### 3.6 Equivocation and the hash chain

- **Claim.** Every change after a device's first carries `prev`, the hash of the same device's previous
  whole signed head; a `stand` carries `tips`. Two devices holding different versions of one number end the
  first session (`diverged`, `tip-mismatch`) without blaming anyone, because a tip is an unproven claim.
  The only proof an app may act on is two verifying signed changes of one device and number with
  different signed texts (`proveEquivocation`).
- **Code.** `src/log/chain.ts` (`tipsOf`, `changeAt`), `src/log/check.ts` (`changeLink`),
  `src/log/signing.ts` (`proveEquivocation`, the `equivocation` and `own-history` verdicts),
  `src/log/protocol.ts` (session handling, `receiveJudged`).
- **Docs.** `docs/wire-format.md` ("Signatures", "What an app does with a reason"), `CLAUDE.md`
  ("Known Limitations", equivocation entry).
- **Tests.** `tests/log/review4.test.ts` (N4, N6), `tests/log/round4.test.ts` (F4, F5),
  `tests/log/review2.test.ts` (H2), `tests/vectors/chain.json` (double signature, tampered tips).
- **Look hardest at.** Cases where a forwarder or a partial session could make one device take a
  version the others never see; the erasure ("redaction") interplay with the chain, since an erased
  change keeps its `prev` and signature; what is **not** detected (replicas that never meet).

### 3.7 Parsers and resource limits

- **Claim.** Every parser reads exactly one spelling, refuses unknown members, duplicate keys, lone
  surrogates, `__proto__`-like names, non-canonical base64url, oversized or over-deep input before doing
  work, never throws on foreign input, and returns fresh copies. Work and memory are bounded by limits
  that are data. An honest history larger than a limit never becomes impossible to sync (partial sessions).
- **Code.** `src/log/parse.ts`, `src/log/validate.ts`, `src/log/limits.ts`, `src/log/protocol.ts`,
  `src/relay/readers.ts`, `src/relay/framing.ts`, `src/post/limits.ts`, `src/core/secure.ts`,
  `src/core/envelope.ts` (`readEnvelope`), `src/core/session.ts` (`parseHello`, `parseSealedMessage`).
- **Docs.** `docs/wire-format.md` ("Exchange": strict reading, limits, partial sessions),
  `docs/relay-protocol.md` ("Limits").
- **Tests.** `tests/log/parse.test.ts`, `tests/log/hardening.test.ts`, `tests/log/fuzz.ts` (seeded
  generator), `tests/log/scale.test.ts`, `tests/log/performance.test.ts`, `tests/log/review3.test.ts`
  (L6 linear piece processing), `tests/relay/readers.test.ts`, `tests/relay/framing.test.ts`; fuzzing
  blocks in `tests/core/file.test.ts`, `tests/core/envelope.test.ts`, `tests/post/exchange.test.ts`.
- **Look hardest at.** Any path where work depends on attacker-chosen sizes before a signature has been
  checked; time bounds in the tests are loose ("separates linear from quadratic"), so read the algorithms
  rather than trust the clock; the interplay of per-message, per-session and per-author limits.

### 3.8 Push encryption (RFC 8291 / RFC 8188, VAPID RFC 8292)

- **Claim.** The ring request is exactly what the relay accepts; the message is `aes128gcm`, one record;
  VAPID tokens verify; every input is checked before any cryptography runs; the service worker template
  never reads push data and uses no network.
- **Code.** `src/push/message.ts` (`encryptPushMessage`, `decryptPushMessage`), `src/push/vapid.ts`,
  `src/push/ring.ts`, `src/push/endpoint.ts`, `src/push/worker.ts`.
- **Docs.** `docs/push.md`.
- **Tests.** `tests/push/message.test.ts` (the RFC 8291 appendix A vector with every intermediate value;
  agreement with an independent `node:crypto` implementation on 300 seeded messages in both directions),
  `tests/push/vapid.test.ts` (the RFC 8292 token), `tests/push/ring.test.ts`, `tests/push/worker.test.ts`
  (runs the generated worker in a `node:vm` sandbox), vectors `tests/vectors/push.json`, reference
  `tests/push/reference.ts`.
- **Look hardest at.** Salt freshness (a parameter, not checked), the endpoint allow-list, and whether the
  worker's escaping of texts is complete. Nothing was run against a real push service or a real browser.

### 3.9 Key storage and the relay client

- **Claim.** Private keys are stored as non-extractable `CryptoKey` objects (no JWK, no export); an
  extractable private key is refused; a corrupt or foreign record is a code, never an exception; a vanished
  store means "device lost" (a new device id, never new keys under the old id). The relay client never lets
  the access token appear in a result, uses `credentials: 'omit'`, retries only for kinds that are safe to
  repeat, and treats every relay answer as untrusted input.
- **Code.** `src/browser/keystore.ts`, `src/browser/credential.ts`, `src/browser/idb.ts`,
  `src/browser/leader.ts`, `src/browser/listener.ts`; `src/relay/client.ts`, `src/relay/kinds.ts`.
- **Docs.** `docs/browser.md` ("Key storage"), `docs/relay-protocol.md`.
- **Tests.** `tests/browser/keystore.test.ts`, `tests/browser/fake-idb.test.ts`, `tests/browser/leader.test.ts`
  (with seeded simulations in `tests/browser/leader-sim.ts`), `tests/relay/client.test.ts`,
  `tests/relay/conformance.test.ts` with `tests/relay/conformance/cases.json` and the in-memory
  `tests/relay/reference-server.ts`.
- **Look hardest at.** The browser tests use an in-memory IndexedDB written for this repository; none of
  this ran in a real browser. The relay's own token formats (`z1`, `e1`, `n1`) are server concerns,
  specified for implementers in `docs/relay-protocol.md`, not verified against the real servers.

## 4. Build, run the tests, other implementations

Requirements: Node 24 (the CI uses 24; WebCrypto and `node:crypto` are used by tests), npm.

```bash
npm ci
npm run typecheck        # tsc --noEmit
npm run format:check     # prettier --check .
npm test                 # vitest run (forks pool, 30 s per-test timeout)
npm run build            # tsc build to dist/, then a declaration fix-up
```

One area at a time: `npx vitest run tests/core`, `tests/log`, `tests/trust`, `tests/post`, `tests/relay`,
`tests/push`, `tests/browser`. The CI workflow is `.github/workflows/tests.yml` (typecheck, format check,
tests, build, a check that declarations do not point at `.ts` files). The seeded property and fuzz tests
take a few seconds each; the seeds are fixed, so a failure reproduces.

**Independent reference implementations.** These are written from the documents with `node:crypto` only
and share no code with `src/`; the tests run the code against them, in both directions, and let them play
the attacker:

- `tests/core/reference.ts`: session and file key derivation.
- `tests/core/envelope-reference.ts`: envelope making and opening, forged insides.
- `tests/push/reference.ts`: RFC 8291 / 8188 encryption and VAPID checking.
- `tests/trust/reference.test.ts`: a naive re-implementation of the trust rules (differential test).
- `tests/relay/reference-server.ts`: an in-memory relay server written from the protocol document, with
  deliberate defect switches so the conformance runner can be shown to notice faults.

Caveat on independence: they were written in the same project, by the same author, from the same texts.
They show that the documents are sufficient to reproduce the bytes and that the code matches the
documents; they cannot show that the documents are the right design.

**Committed vectors for other implementations** (all keys in them are throw-away keys): in
`tests/vectors/`: `canonical.json`, `check-code.json`, `signing-text.json`, `verification.json`,
`chain.json`, `session.json`, `file.json`, `envelope.json`, `mailbox.json`, `push.json`. They are run by
`tests/vectors.test.ts`, `tests/vectors-session.test.ts` and `tests/vectors-envelope.test.ts`. The
relay's language-neutral conformance cases are `tests/relay/conformance/cases.json`
(`docs/relay-protocol.md`, "Conformance case format"). Notes for porters:
`docs/wire-format.md`, "Cross-language notes".

## 5. What the earlier AI review rounds found

Four adversarial AI review rounds covered the **core primitives (encoding, canonical JSON, signatures,
check code), the log layer and the trust layer**. The fix commits are in the git log (titles name "review
findings", "round 3 part A/B", "round 4", "round 5"; the numbers in titles and the count of four rounds in
the README do not line up one to one, so read the log rather than rely on numbering). Finding labels in
the test files: `H*`, `M*`, early `N*`; `L*`, `T*`, `IDX`, later `N*`; `F1` to `F7` in the latest round
(`tests/log/round4.test.ts`, `tests/trust/round4.test.ts`). Each such test was written from the reviewer's
proof of concept first. The classes, so you can hunt for the same classes elsewhere:

| Class                                | Examples found (see the commit messages and the tests named above)                                                                                                                                                                                                                                                                                                |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Quadratic or worse algorithms        | Batch merge of 6000 changes took about 12 s (copying a collection per change), now about 15 ms; a chain of 400 devices took minutes to read; settle of a 1600-device chain 27 s to 0.6 s; the erasure fixpoint of 4000 chained changes 8.7 s to 15 ms; signature-check amplification (keys times writes, 200 x 200: 12.8 s to 0.6 s)                              |
| Non-strict parsers, second spellings | A change with a member the signature did not cover was accepted (a sweep of 67 variants found it); high-s signature twin; a second text for one point; duplicate JSON keys and lone surrogates meaning two things; names reaching the prototype; a check code hashing ambiguous text (no length prefixes); an 8 MB message built from parts each within its limit |
| Order dependence                     | Conflict notices built incrementally differed between devices (1204 spurious and 324 missed in 12000 random states); trust verdicts depended on arrival order, on an id tie-break the joiner chooses, and on what `merge` currently held                                                                                                                          |
| Liveness and availability            | An honest batch refused because of round structure; a new device unable to join a large history; a stand with more than 50 devices ending all synchronisation; a partial session that could repeat for ever; honest devices blocking each other after a device-local write cut-off (that mechanism was removed)                                                   |
| Authority and blame confusion        | `own-history` decided before the signature verified; a forged tip that could make an app blame an innocent device (now neutral, with a separate proof function); a compromised voucher neutralising its own removal or poisoning other entries; an unverifiable removal shadowing a verified one                                                                  |
| Redaction and equivocation           | A forwarder erasing a signed write at one victim only; the same number signed twice with different content or only a different head; versions invisible after the author was removed                                                                                                                                                                              |
| Memory before verification           | Large unsigned pieces buffered before any signature check; a stand costing work proportional to a hostile device count                                                                                                                                                                                                                                            |

Fixed items are listed so you can check they stay fixed: the tests named above run in the normal suite.

## 6. Known and accepted limitations

These are taken from `CLAUDE.md`, section "Known Limitations", and from the "not protected" lists of the
wire-format and layer documents. They are accepted for now; a reviewer may of course disagree.

- **No human review yet; public but unreviewed**; no npm release and no tag for use before the review.
- **Group keys and transfer are not implemented.** Removal does not rotate any key; the package never
  revokes a removed device's ability to write; an app must stop exchanging with it, treat its data as
  untrusted at presentation, restrict it with `mayWrite` / `allowFinalDelete` (hooks that look at state
  can answer differently on two devices) and a removed id stays removed (re-admission is a new id).
- **Trust.** Any trusted voucher can remove devices it can reach and can write any name or role; two
  equal-rank devices that remove each other are both removed; the result depends on the viewer's devices
  met in person; a voucher can pre-occupy a future device id with its own keys; a voucher that writes
  more than 8 keys into an entry can make that entry's own writes unverifiable until it is removed;
  the meeting code carries role and name as self-declaration, has no recipient bound and can be relayed
  within its 120 s window; the invitation carries no signature and its single use is not enforceable
  offline (an app keeps a ledger); the check code carries about 66 bits by default (use 8 or more groups
  where it alone protects an invitation link).
- **Log.** The log is unbounded unless the app bounds a flooding member (`mayWrite`, `quota`, default
  unlimited); the fingerprint (128 bits) is a consistency check, not proof against a lying peer; a final
  deletion is judged false unless the app passes `allowFinalDelete`; a change that names a `knew` the
  receiver never reaches is held for good with everything later from its author; an indivisible group of
  erased changes larger than `maxGroupChanges` / `maxGroupChars` cannot be taken until the limits are
  raised; every merge still copies the log and the touched collection (O(records) per local write); pairs
  of heads of one field are compared pairwise (quadratic in the number of devices that wrote that field);
  replicas are immutable values and a middle entry changed in place is not noticed by the caches;
  equivocation is only detected when two replicas that hold the versions meet; the "hold until approved"
  hook exists only as a type.
- **Session.** Not resumable (counters live in memory); one ephemeral pair opens one session, remembered
  per process only; a dropped last message is not noticed and a gap ends the stream; no ratchet and no
  padding; the hello is unauthenticated (a replaced hello makes the session fail); forward secrecy needs
  the ephemeral pair to be discarded and JavaScript cannot wipe memory.
- **File.** No forward secrecy against the recipient's static key; the holder of that key can forge a
  file "from" anybody to it; no replay protection or freshness; sender, recipient and app id are in clear.
- **Envelope and mailbox.** Size, day, id and carrier path are visible; the author is not deniable; a
  reader can re-seal; no replay protection; no forward secrecy against a reader's static key; a carrier
  can drop, delay or multiply an envelope; a neighbour can use up its own quota with junk and push older
  real envelopes out of a full mailbox; a compromised allowed device can make carriers drop early through
  receipts; the exchange does not resume.
- **Relay.** The relay sees app, device ids, sizes, timing and the push endpoint of a ring and can drop,
  delay, duplicate or reorder; whoever holds its signing secret can enrol or impersonate a device; a
  collect whose answer is lost has already deleted its messages; a drop is never repeated after an
  unclear outcome; version 1 only (the later admission revision is not implemented); open points of
  version 1 are listed in `docs/relay-protocol.md`; the reference server and the conformance cases were
  written from the document and the server source, **not run against the real servers**; 9 of 70
  conformance cases need the optional test interface.
- **Push.** The push service sees timing, endpoint and body size; anyone holding a subscription can send a
  push to it; no replay protection; the salt is a caller parameter; one record only; **nothing was run
  against a real push service**; the service worker was tested only in a `node:vm` sandbox.
- **Browser.** **Never run in a real browser.** No key backup or export; a cleared store means a lost
  device; any script of the origin can use (not export) the keys while the page runs; nothing is encrypted
  at rest; no persistent-storage request; a database written by a newer schema is refused; the channel
  election fallback is a sketch tested by simulation, prefer Web Locks.
- **Randomness** for salts, nonces of files, invitation codes, device ids and the fan padding is passed in
  by the caller (`random(n)`); the package cannot check its quality. Ephemeral keys come from WebCrypto.
  The relay client's retry jitter uses `Math.random` (not security relevant).

## 7. Questions to the reviewer

1. **Session key schedule.** Is the construction (four DH terms concatenated as input keying material,
   HKDF salt = SHA-256 of a length-prefixed transcript, info per direction, unauthenticated hellos, implicit
   authentication with confirmation by the first verified message) sound? Is there an unknown-key-share
   or identity-misbinding angle given that device ids are in the transcript but only the app's trust layer
   ties an id to a static key? Would you rather see a standard pattern (for example Noise XX/IK) instead?
2. **Envelope and AES-GCM key commitment.** The content is one AES-GCM ciphertext; each slot wraps the
   content key for one reader. A malicious author can place different keys in different slots. Does the lack of
   key commitment allow one ciphertext that opens to different valid, author-signed plaintexts for
   different readers? Is the zero-nonce slot wrapping acceptable given a unique KEK per envelope and
   reader? Does "the first slot that opens decides" leave a gap?
3. **File sender authentication.** Is authenticating the sender only by a static-static DH value (so the
   recipient's key can forge) an acceptable choice for the intended use, or should files be signed?
4. **Canonical JSON and signed texts.** Are all signed and hashed texts unambiguous (length prefixes,
   markers, order of members)? Does the cross-language description of number and string handling in
   `docs/wire-format.md` suffice for a second implementation to agree on every input?
5. **Low-s and strictness.** Is refusing high-s and non-canonical encodings everywhere consistent, and is
   there any place where a second spelling of a key, signature, id or point still reaches a hash?
6. **Trust derivation as a design.** Is "removal ends standing but does not stop writing, and the removed
   device stays checkable" a defensible trade-off against liveness? Is the rank-by-rank rule with no
   tie-break, which removes both of two mutually removing equal-rank devices, acceptable? What is the
   worst a single compromised voucher can do under the documented rules?
7. **Missing group keys.** Given pairwise session, file and envelope only, what must an app do on removal
   to meet a reasonable confidentiality goal, and should the package refuse to be used for real data until
   group keys exist?
8. **Equivocation and tips.** Is the neutral handling of `tip-mismatch`, with proof only by
   `proveEquivocation`, enough to avoid both false blame and silent forks? Are there partial-session
   interleavings that let a version be hidden from a victim?
9. **Resource exhaustion.** Which input can you make expensive before a signature is checked? Which limit
   in `src/log/limits.ts`, `src/post/limits.ts` or `src/relay/limits.ts` is too generous or can be
   combined with another to multiply cost?
10. **Randomness and time as parameters.** Is passing `random` and the clock in from the caller a
    reasonable boundary, or should the package draw randomness itself for the safety-critical values
    (nonces, codes, ids)?
11. **Key storage in the browser.** Is storing non-extractable keys in IndexedDB, with the relay credential
    next to them in clear, acceptable for the stated threat of XSS, and what would you add?
12. **Push and relay client.** Anything in the VAPID/ring construction, the endpoint allow-list or the
    relay client's retry and credential handling that could leak the access token or be steered by a
    hostile relay answer?
13. **Process.** Beyond the review of the code, would you review the documents (`docs/wire-format.md`,
    `docs/relay-protocol.md`) as the specification and treat a mismatch between the two as a finding?

## 8. Layers with no review round yet

Review rounds so far (AI only): core primitives, log, trust. **No review round of any kind has covered:**

| Layer or part                                                 | Where                                  | Notes                                                                                      |
| ------------------------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------ |
| End-to-end session                                            | `src/core/session.ts`                  | New after the four rounds; tests and an independent reference exist, no adversarial review |
| Encrypted file                                                | `src/core/file.ts`                     | Same                                                                                       |
| Sealed envelope                                               | `src/core/envelope.ts`                 | Same                                                                                       |
| Mailbox and per-day exchange                                  | `src/post/`                            | Same                                                                                       |
| Relay client, framing, conformance runner, protocol document  | `src/relay/`, `docs/relay-protocol.md` | Never run against the real servers                                                         |
| Push encryption, VAPID, ring request, service worker template | `src/push/`, `docs/push.md`            | RFC vectors pass; no real push service                                                     |
| Browser layer                                                 | `src/browser/`, `docs/browser.md`      | Never run in a real browser                                                                |
| Transfer (QR, audio, direct connection)                       | being added                            | Not part of this guide; unreviewed and unfinished                                          |

The earlier rounds also did not review how the layers are composed (no integration layer exists yet).
