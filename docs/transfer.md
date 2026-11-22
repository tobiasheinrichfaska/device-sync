# Transfer layer: QR frames, tones, direct connection

**New, not yet reviewed, never run in a real browser.** This document says what `src/transfer/` builds, what
it does not protect, and the numbers and codes the tests hold the code to (`tests/transfer/docs.test.ts`).

The layer moves **opaque bytes** from one device to another without a server of its own: as an animated
sequence of QR codes, as a few tones through the air, or over a WebRTC data channel whose two description
texts the devices exchange by any means. It is optional: an app that only uses a relay never imports it.

**The transfer layer does not authenticate anything.** Its check values (CRC-32 and a 16-bit cut of one) find
damage and frames of another app; anybody can compute them. What gives a transfer meaning is what the app puts
inside: a sealed file or an end-to-end session of the core layer (`docs/wire-format.md`, "Wire format:
end-to-end layer"). A transfer of unsealed bytes is only as trustworthy as the way the two devices met.

The layer is pure where it can be: nothing here reads a clock, draws randomness or touches a browser object.
The transfer id and the session id are parameters, time comes in as a parameter, and the camera, the
microphone, `RTCPeerConnection`, the timers and the clock are injected through narrow interfaces (the camera and
audio ones are in `src/browser/media.ts`; no QR image code is here: a QR scanner turns a camera frame into
bytes, and these bytes go to `FountainReceiver.add`). Every function answers `{ ok: true, value }` or
`{ ok: false, reason }` and never throws on bad input; the reason is a code, not a sentence.

## What is built

| Part                                                        | What it does                                                                                                                                                       |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `createFountainSender`, `parseFrame`                        | a payload becomes an endless sequence of frames (`frame(seq)`, `next()`); the strict reader of one frame; text form `frameToText`/`frameFromText`                  |
| `createFountainReceiver`                                    | collects frames in any order, with loss and repeats; answers with an outcome per frame; `payload()` once complete and checked                                      |
| `encodeToneMessage`, `decodeToneMessage`                    | a message of 1 to 16 octets as samples (`Float32Array`) and back; `createToneListener` is the streaming decoder for a microphone                                   |
| `synthesizeByte`, `decodeTones`, `analyze`                  | the one-octet acknowledgement and the pieces below the message layer                                                                                               |
| `writeDirectText`, `readDirectText`                         | the offer and answer texts of a direct connection; `readSdp` is the strict reader of the description inside; `fingerprintsOf`                                      |
| `directStep`, `initialState`                                | the pure state machine of the handshake (events in, state and actions out; time is a parameter)                                                                    |
| `createDirect` / `DirectConnection`                         | the thin adapter over an injected `RTCPeerConnection`-like peer: `makeOffer`, `acceptOffer`, `acceptAnswer`, `opened`, `send`, `receive`, `drain`, `path`, `close` |
| `chunkMessage`, `ChunkAssembler`                            | messages over the data channel, cut into chunks and put together again with limits                                                                                 |
| `candidatesOfSdp`, `reachability`, `chosenPath`, `pathKind` | what a description and the connection statistics say about the network, as codes, never an address                                                                 |

### Fountain frames

The payload is cut into K blocks. Frames 0 to K-1 carry the blocks as they are; every later frame carries the
XOR of a pseudo-random half of the blocks, chosen from the transfer id and the frame number, so the receiver
recomputes the mix from the header. Any K independent frames rebuild the payload (elimination over GF(2));
with random mixes about K + 2 frames suffice, whichever were missed, in whatever order, with repeats. A
camera reads one shown code several times: the receiver counts such a repeat apart from a frame that brought
nothing new (`repeat` and `redundant`).

Frame (big endian): version `1` (1 octet), transfer id (4), sequence number (4), blocks (2), payload length
(4), payload check (4), one block (1 to 2048 octets), frame check (4). The frame check is CRC-32 over the
domain marker `<appId>-qr:1` and everything before it; the payload check is CRC-32 over `<appId>-qrdata:1` and
the payload. A frame of another app (another `appId`) therefore fails its check. The strict reader accepts one
spelling: the length must fit the block count and block size exactly, blocks and length within the limits.
The text form is unpadded base64url, one spelling.

The receiver stays with the first transfer it sees and ignores frames of another one (`other-transfer`), unless
it was made with `switchOnOther`. When all blocks are known it checks the payload check **and that the padding
after the payload is zero**; on a failure it throws everything away and starts again (`check-failed`, counted in
`checkFailures`): one bad frame that passed its own check does not stop the transfer for good. Memory is
bounded by the limits (at most 1024 rows of at most 2048 octets plus their bit sets); the work per frame is
the reduction against the stored rows, at most about 1024 row operations.

### Tones

A byte is three tones: a start tone, the high nibble, and the low nibble shifted so a tone never repeats the
one before it. Each tone has soft edges. Detection measures the Goertzel power of every tone frequency in a
Hann-windowed frame of about 21 ms and takes a tone only if it is clearly above the median of the others
(`minSnr`) and above a floor (`minPower`). A message is `length | payload | check` as bytes (the check is the
low 16 bits of CRC-32 over the domain marker `<appId>-tone:1`, the length and the payload) and is sent
`repeats` times (2) with a gap, so a burst of noise over one copy leaves the other. Two plans exist as data:
`ultrasonic` (17.5 to 19.4 kHz, needs at least 44.1 kHz sampling) and `audible` (1.5 to 3.4 kHz). A message of
16 octets takes about 5.1 s per copy.

`decodeToneMessage` takes a whole recording. `createToneListener(appId, plan, rate)` takes the microphone's
buffers as they come, keeps only the unanalysed tail and a capped list of symbols, and returns the first
message whose check holds; the app stops listening then (a second copy would be found again).

### The direct connection

Two devices open a WebRTC data channel by exchanging two texts. The caller makes an **offer text**, the callee
takes it and makes an **answer text**, the caller takes that: `<appId>-direct:1.<role>.<session>.<base64url
of the SDP>`. The session is 16 hex characters the caller draws; the answer repeats it, and an answer of another
session is refused. All ICE candidates are inside (no trickle), so each side waits until its candidates are
gathered (`gatherWaitMs`, 5 s) and then takes the description as it is; a description with no candidate at all
is a failure. The texts travel by any means (QR codes, a relay, a message).

`readSdp` accepts a description only if it is printable ASCII with CRLF line ends, within the limits, starts
with `v=0`, has **exactly one media section and that one is `application`** (so a text cannot ask for a camera
or a microphone), and carries at least one DTLS fingerprint line of the usual shape. `fingerprintsOf` returns
those lines: an app that has an authenticated channel (a sealed session) should sign or compare them, because
the fingerprint is what binds the data channel to the description that was exchanged.

The state machine (`directStep`) goes: caller `idle`, `gathering`, `awaiting-answer`, `connecting`, `open`;
callee `idle`, `awaiting-offer`, `gathering`, `connecting`, `open`; `closed` and `failed` are final and ignore
everything. Each waiting phase has a deadline from the configuration (`offerMs`, `setupMs`, `answerMs`,
`connectMs`); a text that does not fit (wrong role, another session) is **refused and changes nothing**, so a
stray text does not end a handshake. The adapter arms one timer for the current deadline and sends the machine
a `tick`. Time must come from a clock that does not jump back (`performance.now`).

Messages over the channel are opaque bytes up to 4 MiB, cut into chunks of at most 16 KiB (what every browser
passes unsplit): version 1, message id (4), chunk index (2), chunk count (2), data. All chunks but the last are
full, the last is not empty unless the message is. The channel is ordered; the assembler takes the chunks in
order and refuses anything else (`out-of-order`, `mismatch`), except that chunk 0 starts a new message and
drops a half-received one. A broken chunk, an out-of-order chunk or more than `inboxMax` unread messages **close
the connection** (`closeReason()` is `protocol` or `overflow`). Text messages on the channel are ignored.

Receiving starts the moment the channel exists, and what arrives before anybody calls `receive` waits in the
bounded inbox: in an earlier implementation a ping that came while the other side still read its statistics
was lost. Sending is queued (two `send` calls never interleave their chunks), waits while the channel's buffer
is above the high-water mark, and `drain()` waits until everything left the device: closing earlier drops what
still waits there.

## What an observer sees, and what is not protected

- **QR frames.** Everyone who can see the screen (or a photo of it) reads the frames and, with K of them, the
  payload. The check values are not secret. Frames carry the transfer id, the number of blocks and the payload
  length in clear. Whoever can show frames can also show forged ones: an attacker with a valid frame format
  can make a receiver throw its progress away (`check-failed`) or, if `switchOnOther` is set, switch to
  another transfer; both only cost time. Put a sealed file or session inside.
- **Tones.** Everyone in earshot (or with a recording) hears the message. 16 octets at most, no secrecy, no
  authentication; ultrasound is inaudible to most people but not to a microphone. Another app's message fails
  the check; the same app's message can be replayed. Use it as an acknowledgement or a hint, not for a secret.
- **Direct connection texts.** The description contains the device's **IP addresses** (host candidates, or
  `.local` names where the browser hides them; STUN-learned public addresses), the ICE credentials and the
  DTLS fingerprint. Whoever sees the texts, including a relay that carried them, learns where the devices are.
  The data channel itself is DTLS-encrypted by the browser against the fingerprint in the description, but
  **nothing here says who the other end is**: a person who can substitute the texts is the other end. Bind the
  fingerprints to an authenticated session of the core layer before trusting the channel. The network
  helpers keep only the kind of an address (family, local or public), never the address.
- A STUN server (optional) learns that the device asked and its public address; without STUN the devices
  connect only on the same network. TURN is not part of this layer.
- No replay protection and no freshness in any of the three: the app must be idempotent.

## Limits

| Name               | Value     | Meaning                                                                   |
| ------------------ | --------- | ------------------------------------------------------------------------- |
| `frameVersion`     | 1         | Fountain frame: version octet                                             |
| `frameHeaderBytes` | 19        | Header: version 1, transfer id 4, sequence 4, blocks 2, length 4, check 4 |
| `frameCheckBytes`  | 4         | Trailer: the check value over everything before it                        |
| `blockBytesMax`    | 2_048     | Largest block (fits a QR code at the lowest correction level)             |
| `blocksMax`        | 1_024     | Most blocks of one payload                                                |
| `payloadMax`       | 1_048_576 | Largest payload of one transfer                                           |
| `seqMax`           | 1_000_000 | Highest frame sequence number                                             |
| `frameBytesMax`    | 2_071     | Largest frame in octets                                                   |
| `frameCharsMax`    | 2_762     | Largest frame as base64url text                                           |
| `framesMax`        | 100_000   | Frames one receiver looks at per transfer before it refuses more          |
| `seenMax`          | 16_384    | Sequence numbers one receiver remembers                                   |
| `toneMessageMax`   | 16        | Tone message: most payload octets                                         |
| `toneCheckBytes`   | 2         | Tone message: octets of check value                                       |
| `toneSymbolsMax`   | 4_096     | Tone listener: most analysis frames kept                                  |
| `textCharsMax`     | 11_000    | Most characters of one offer or answer text                               |
| `sdpCharsMax`      | 8_192     | Most characters of one description                                        |
| `sdpLinesMax`      | 200       | Most lines of a description                                               |
| `sdpLineCharsMax`  | 512       | Longest line of a description                                             |
| `chunkHeaderBytes` | 9         | Data channel chunk: version 1, message id 4, index 2, count 2             |
| `chunkBytes`       | 16_384    | Largest data channel message                                              |
| `messageBytesMax`  | 4_194_304 | Largest message sent over the data channel                                |
| `inboxMax`         | 256       | Unread messages a connection buffers                                      |
| `statsMax`         | 500       | Entries of `getStats()` the path reader looks at                          |
| `highWaterBytes`   | 1_048_576 | A sender waits while more than this is buffered                           |
| `lowWaterBytes`    | 262_144   | The buffer level that wakes a waiting sender                              |

## Codes

| Where                    | Codes                                                                                                                           |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `createFountainSender`   | `bad-app-id`, `bad-payload`, `too-large`, `bad-transfer-id`, `bad-block-size`; `frame(seq)`: `bad-seq`                          |
| `parseFrame`, `add`      | `too-short`, `too-long`, `bad-version`, `bad-check` (also another app), `bad-blocks`, `bad-text` (text form), `too-many-frames` |
| `createFountainReceiver` | `bad-app-id`, `bad-config`                                                                                                      |
| `payload()`              | `incomplete`                                                                                                                    |
| `add` outcomes           | `new`, `redundant`, `repeat`, `other-transfer`, `done`, `check-failed` (these are values, not failures)                         |
| tone functions           | `bad-app-id`, `bad-payload`, `bad-byte`, `bad-rate`, `bad-samples`, `not-found`                                                 |
| direct texts             | `bad-app-id`, `not-text`, `too-long`, `bad-marker`, `bad-format`, `bad-role`, `bad-session`, `bad-sdp`                          |
| handshake refusals       | `unexpected`, `wrong-role`, `wrong-session`, `bad-session`                                                                      |
| handshake failures       | `offer-timeout`, `gather-timeout`, `answer-timeout`, `connect-timeout`, `ice-failed`, `channel-closed`, `setup-failed`          |
| `createDirect`           | `bad-app-id`, `bad-config`, `bad-session`, `bad-stun`                                                                           |
| `DirectConnection`       | `bad-state`, `no-candidates`, `closed`, `timeout` (a read that waited too long), `not-open`, `send-failed`, `send-timeout`      |
| chunks                   | `bad-message`, `bad-id`, `too-large`, `bad-chunk`, `out-of-order`, `mismatch`                                                   |
| `closeReason()`          | `cancelled`, `protocol`, `overflow`, `peer-closed`                                                                              |

## What was not done

- No QR rendering and no QR scanning: a QR library draws the frame bytes (or the text form) and decodes the
  camera frames the app takes from `CameraSource`. Nothing here was run with a real camera, microphone or
  `RTCPeerConnection`; the tests use fakes written for this repository.
- The frame format, the tone message and the texts are **new formats** of this package (the earlier
  implementations' bytes are not readable: another header, a payload check, a frame check, bit-set mixes).
- TURN, trickle ICE and reconnection are not part of the layer: a failed connection starts again with new texts.
