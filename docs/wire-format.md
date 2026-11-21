# Wire format (core layer, format version 2)

Only what the `core` layer puts on the wire or into hashes. Ported from two earlier implementations;
the vectors in `tests/core/` pin the behaviour.

## Encoding

- Binary values travel as **unpadded base64url** (RFC 4648 section 5): alphabet `A-Z a-z 0-9 - _`, no `=`.
- Decoding is **strict**: any other character (including `+`, `/`, `=`, spaces, newlines) is an error;
  a length with one left-over character is an error; the empty text decodes to no bytes.
- `sha256Text(text)` is SHA-256 over the UTF-8 bytes of the text.

## Canonical form

`canonical(value)` is the text that is hashed or signed instead of raw JSON:

- arrays: `[` members joined by `,` `]`, order kept; members that are not JSON values (undefined,
  functions) become `null`;
- objects: members whose value is `undefined` are dropped, the remaining keys are sorted by UTF-16 code
  unit (default JavaScript sort, so `"10"` sorts before `"9"`), each written as
  `JSON.stringify(key):canonical(value)`, joined by `,` inside `{` `}`;
- everything else is `JSON.stringify(value)`, or `null` when that gives nothing (top-level `undefined`).

`checkValue(value)` = base64url(SHA-256(UTF-8(canonical(value)))), always 43 characters.

## Markers

`marker(appId, kind, version)` = `${appId}-${kind}:${version}`. `appId` must match
`^[a-z][a-z0-9]{1,15}$`. Every marker enters hashes, key derivation and AAD, so a different `appId` never
produces the same bytes. All markers of this format use version `2` (`FORMAT_VERSION`).

## Device keys and points

- Per device: a signing pair (ECDSA P-256) and an agreement pair (ECDH P-256). Private halves are
  generated non-extractable.
- A public key travels as the **uncompressed point**: 65 bytes (first byte `0x04`, then X and Y, 32 bytes
  each), base64url, exactly **87 characters**. `isPoint` checks only format; `importPublicKey` also
  rejects points that are not on the curve.

## Check code

For comparing a device aloud: SHA-256 over the UTF-8 text
`${marker(appId, 'device', 2)}|${deviceId}|${sig}|${dh}` (`sig`, `dh` as the base64url points). Take the
first ten bytes as five big-endian 16-bit numbers; each modulo 10000, zero-padded to four digits, joined by
single spaces: `dddd dddd dddd dddd dddd`.
