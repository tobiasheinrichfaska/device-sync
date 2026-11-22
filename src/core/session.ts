// End-to-end encrypted session between two devices that know each other's agreement key (the trust
// layer verified it; this layer never decides whom to trust). Like Noise KK, but symmetric: both
// sides send a `hello` with a fresh ephemeral key. Wire details: docs/wire-format.md, "Session".
import { FORMAT_VERSION, marker } from './markers.ts';
import {
  TAG_BYTES,
  aesKey,
  base64urlLength,
  compareUtf8,
  concat,
  ecdh,
  field,
  hasMembers,
  importPoint,
  isDeviceText,
  isPlain,
  overrideNumbers,
  ownPoint,
  parseJson,
  readBytes,
  sha256,
} from './secure.ts';
import { base64url } from './encoding.ts';

const utf8 = new TextEncoder();
const AGREEMENT = { name: 'ECDH', namedCurve: 'P-256' } as const;

export interface SessionLimits {
  /** The largest message (bytes of plaintext) `seal` accepts and `open` can return. */
  readonly maxPlaintextBytes: number;
  /** Messages per direction under one key; the counter never wraps (at most 2^32). */
  readonly maxMessages: number;
}

export const SESSION_LIMITS: SessionLimits = Object.freeze({
  maxPlaintextBytes: 1_048_576,
  maxMessages: 4_294_967_296,
});

/** The defaults with a partial override on top (own integer members only; `maxMessages` 1 to 2^32). */
export function resolveSessionLimits(override?: Partial<SessionLimits>): SessionLimits {
  const out = overrideNumbers({ ...SESSION_LIMITS }, override);
  return {
    maxPlaintextBytes: out.maxPlaintextBytes,
    maxMessages: Math.min(Math.max(out.maxMessages, 1), SESSION_LIMITS.maxMessages),
  };
}

/** The opening message of one side: its device id and a fresh ephemeral ECDH point. */
export interface Hello {
  readonly device: string;
  readonly eph: string;
}

/** One sealed message as it is read from the wire. `ct` is ciphertext with the 16-byte tag. */
export interface SealedMessage {
  readonly n: number;
  readonly ct: Uint8Array;
}

const MAX_HELLO_CHARS = 1024;
const MESSAGE_OVERHEAD_CHARS = 256;

/** The most characters of one sealed message under these limits (a reader refuses longer text). */
export const maxSealedChars = (limits: SessionLimits): number =>
  base64urlLength(limits.maxPlaintextBytes + TAG_BYTES) + MESSAGE_OVERHEAD_CHARS;

function validHello(value: unknown): value is Hello {
  return (
    isPlain(value) &&
    isDeviceText(value.device) &&
    readBytes(value.eph, 65, 65)?.[0] === 4 &&
    Object.keys(value).length === 2
  );
}

const helloText = (appId: string, hello: Hello): string =>
  `{"m":${JSON.stringify(marker(appId, 'hello', FORMAT_VERSION))},"device":${JSON.stringify(
    hello.device,
  )},"eph":${JSON.stringify(hello.eph)}}`;

/** The wire text of a hello (compact JSON, members in this order). A malformed hello is a TypeError. */
export function encodeHello(appId: string, hello: Hello): string {
  if (!validHello(hello)) throw new TypeError('encodeHello: not a valid hello');
  return helloText(appId, hello);
}

/** A hello from its text, strictly read (exactly the spelling `encodeHello` writes), else undefined. */
export function parseHello(appId: string, text: unknown): Hello | undefined {
  const m = marker(appId, 'hello', FORMAT_VERSION);
  if (typeof text !== 'string' || text.length > MAX_HELLO_CHARS) return undefined;
  if (!text.startsWith(`{"m":${JSON.stringify(m)},"device":`)) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'device', 'eph'])) return undefined;
  const hello = { device: raw.device, eph: raw.eph };
  if (!validHello(hello)) return undefined;
  return helloText(appId, hello) === text ? { device: hello.device, eph: hello.eph } : undefined;
}

const messageText = (appId: string, n: number, ct: string): string =>
  `{"m":${JSON.stringify(marker(appId, 'msg', FORMAT_VERSION))},"n":${n},"ct":"${ct}"}`;

/** A sealed message from its text, strictly read (one spelling, bounded), else undefined. */
export function parseSealedMessage(
  appId: string,
  text: unknown,
  limits?: Partial<SessionLimits>,
): SealedMessage | undefined {
  const m = marker(appId, 'msg', FORMAT_VERSION);
  const lim = resolveSessionLimits(limits);
  if (typeof text !== 'string' || text.length > maxSealedChars(lim)) return undefined;
  if (!text.startsWith(`{"m":${JSON.stringify(m)},"n":`)) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'n', 'ct'])) return undefined;
  const { n } = raw;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0) return undefined;
  const ct = readBytes(raw.ct, TAG_BYTES, lim.maxPlaintextBytes + TAG_BYTES);
  if (!ct || messageText(appId, n, raw.ct as string) !== text) return undefined;
  return { n, ct };
}

export interface SessionParams {
  readonly appId: string;
  /** This device: its id and its agreement pair (the static key the peer was told about). */
  readonly own: { readonly device: string; readonly agreement: CryptoKeyPair };
  /** The peer as the trust layer verified it: its id and its agreement public key (a point). */
  readonly peer: { readonly device: string; readonly dh: string };
  /** The ephemeral pair `createHello` made; one pair opens one session only. */
  readonly ephemeral: CryptoKeyPair;
  readonly ownHello: Hello;
  readonly peerHello: Hello;
  readonly limits?: Partial<SessionLimits>;
}

export type SessionRefusal =
  | 'bad-own'
  | 'bad-peer'
  | 'bad-hello'
  | 'own-hello-mismatch'
  | 'wrong-device'
  | 'same-device'
  | 'same-key'
  | 'mirrored'
  | 'bad-peer-key'
  | 'bad-point'
  | 'ephemeral-reused'
  | 'crypto-failure';

export type SessionOpening =
  | { readonly ok: true; readonly session: EncryptedSession }
  | { readonly ok: false; readonly reason: SessionRefusal };

export type SealRefusal = 'bad-input' | 'too-large' | 'counter-limit';
export type SealResult =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly reason: SealRefusal };

export type OpenRefusal = 'bad-message' | 'counter-limit' | 'replayed' | 'gap' | 'bad-seal';
export type OpenResult =
  | { readonly ok: true; readonly plaintext: Uint8Array }
  | { readonly ok: false; readonly reason: OpenRefusal };

export interface EncryptedSession {
  /** This device's id and the peer's. */
  readonly own: string;
  readonly peer: string;
  /** Messages sealed and accepted so far (the next counters). */
  readonly sent: number;
  readonly received: number;
  /**
   * True once a message of the peer has opened: only then is it shown that the peer holds the
   * keys (a hello alone proves nothing).
   */
  readonly confirmed: boolean;
  /** Seals a message for the peer; the counter moves only when a message is made. */
  seal(plaintext: Uint8Array): Promise<SealResult>;
  /** Opens the peer's next message; a refusal leaves the session exactly as it was. */
  open(text: unknown): Promise<OpenResult>;
}

/** Ephemeral keys that already opened a session: a second session on the same pair would repeat nonces. */
const usedEphemerals = new WeakSet<CryptoKey>();

/** A fresh ephemeral ECDH pair and the hello that carries its public point. */
export async function createHello(
  device: string,
): Promise<{ readonly ephemeral: CryptoKeyPair; readonly hello: Hello }> {
  if (!isDeviceText(device)) throw new TypeError('createHello: not a valid device id');
  const ephemeral = await crypto.subtle.generateKey(AGREEMENT, false, ['deriveBits']);
  const eph = base64url(new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey)));
  return { ephemeral, hello: { device, eph } };
}

/** GCM nonce of message `n`: four zero bytes and the counter, big endian (unique per key and direction). */
export function nonceFor(n: number) {
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setBigUint64(4, BigInt(n));
  return iv;
}

/**
 * Opens the session between this device and a known peer. Refused (a code, never a throw) when
 * anything about the two sides does not fit: ids, keys, hellos, a mirrored hello, a key off the
 * curve, an ephemeral pair that was used already. An invalid `appId` is a TypeError (programming error).
 */
export async function openSession(params: SessionParams): Promise<SessionOpening> {
  const { appId, own, peer, ephemeral, ownHello, peerHello } = params;
  const sessionMarker = marker(appId, 'session', FORMAT_VERSION);
  const msgMarker = marker(appId, 'msg', FORMAT_VERSION);
  const limits = resolveSessionLimits(params.limits);
  const refuse = (reason: SessionRefusal): SessionOpening => ({ ok: false, reason });

  if (!isPlain(own) || !isDeviceText(own.device)) return refuse('bad-own');
  if (!isPlain(peer) || !isDeviceText(peer.device)) return refuse('bad-peer');
  if (!validHello(ownHello) || !validHello(peerHello)) return refuse('bad-hello');
  if (ownHello.device !== own.device) return refuse('own-hello-mismatch');
  if (peerHello.device !== peer.device) return refuse('wrong-device');
  if (own.device === peer.device) return refuse('same-device');
  if (ownHello.eph === peerHello.eph) return refuse('mirrored');
  if (readBytes(peer.dh, 65, 65)?.[0] !== 4) return refuse('bad-peer-key');

  let ownDh: string | undefined;
  let ephPublic: string | undefined;
  try {
    ownDh = await ownPoint(own.agreement);
    ephPublic = await ownPoint(ephemeral);
  } catch {
    return refuse('bad-own');
  }
  if (ownDh === undefined) return refuse('bad-own');
  if (ephPublic !== ownHello.eph) return refuse('own-hello-mismatch');
  // the static pair as the "ephemeral" one would give the four secrets static terms: no forward secrecy
  if (ephPublic === ownDh) return refuse('bad-own');
  if (peer.dh === ownDh) return refuse('same-key');

  const peerEph = await importPoint(peerHello.eph);
  if (!peerEph) return refuse('bad-point');
  const peerStatic = await importPoint(peer.dh);
  if (!peerStatic) return refuse('bad-peer-key');

  // Synchronously check-and-mark: two concurrent openings on one pair cannot both pass.
  if (usedEphemerals.has(ephemeral.privateKey)) return refuse('ephemeral-reused');
  usedEphemerals.add(ephemeral.privateKey);

  let sendKey: CryptoKey;
  let receiveKey: CryptoKey;
  try {
    // Four ECDH results, in an order both sides agree on: `lo` is the device whose id is smaller
    // by UTF-8 bytes. ee: ephemeral x ephemeral (forward secrecy). The two crossed terms make an
    // impersonation with a stolen static key fail (key-compromise impersonation); ss binds both
    // static keys.
    const iAmLo = compareUtf8(own.device, peer.device) < 0;
    const ee = await ecdh(ephemeral.privateKey, peerEph);
    const myEphPeerStatic = await ecdh(ephemeral.privateKey, peerStatic);
    const myStaticPeerEph = await ecdh(own.agreement.privateKey, peerEph);
    const ss = await ecdh(own.agreement.privateKey, peerStatic);
    const ikm = iAmLo
      ? concat(ee, myEphPeerStatic, myStaticPeerEph, ss)
      : concat(ee, myStaticPeerEph, myEphPeerStatic, ss);
    const lo = iAmLo
      ? { device: own.device, dh: ownDh, eph: ownHello.eph }
      : { device: peer.device, dh: peer.dh, eph: peerHello.eph };
    const hi = iAmLo
      ? { device: peer.device, dh: peer.dh, eph: peerHello.eph }
      : { device: own.device, dh: ownDh, eph: ownHello.eph };
    const part = (p: { device: string; dh: string; eph: string }): string =>
      `${field(p.device)}|${field(p.dh)}|${field(p.eph)}`;
    const salt = await sha256(`${sessionMarker}|${part(lo)}|${part(hi)}`);
    sendKey = await aesKey(ikm, salt, `${sessionMarker}|key|${field(own.device)}`);
    receiveKey = await aesKey(ikm, salt, `${sessionMarker}|key|${field(peer.device)}`);
  } catch {
    // no session was made, no key was used: the pair stays usable
    usedEphemerals.delete(ephemeral.privateKey);
    return refuse('crypto-failure');
  }

  const ownId = own.device;
  const peerId = peer.device;
  const aad = (sender: string, receiver: string, n: number) =>
    utf8.encode(`${msgMarker}|${field(sender)}|${field(receiver)}|${n}`);
  let sent = 0;
  let received = 0;
  let confirmed = false;

  const session: EncryptedSession = {
    own: ownId,
    peer: peerId,
    get sent() {
      return sent;
    },
    get received() {
      return received;
    },
    get confirmed() {
      return confirmed;
    },
    async seal(plaintext) {
      if (!(plaintext instanceof Uint8Array)) return { ok: false, reason: 'bad-input' };
      if (plaintext.length > limits.maxPlaintextBytes) return { ok: false, reason: 'too-large' };
      if (sent >= limits.maxMessages) return { ok: false, reason: 'counter-limit' };
      // The counter is taken before the first await, so concurrent calls get different numbers.
      const n = sent;
      sent += 1;
      const ct = new Uint8Array(
        await crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: new Uint8Array(nonceFor(n)),
            additionalData: aad(ownId, peerId, n),
          },
          sendKey,
          new Uint8Array(plaintext),
        ),
      );
      return { ok: true, text: messageText(appId, n, base64url(ct)) };
    },
    async open(text) {
      const message = parseSealedMessage(appId, text, limits);
      if (!message) return { ok: false, reason: 'bad-message' };
      const verdict = (n: number): OpenRefusal | undefined =>
        n >= limits.maxMessages
          ? 'counter-limit'
          : n < received
            ? 'replayed'
            : n > received
              ? 'gap'
              : undefined;
      const early = verdict(message.n);
      if (early) return { ok: false, reason: early };
      let plaintext: Uint8Array;
      try {
        plaintext = new Uint8Array(
          await crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: new Uint8Array(nonceFor(message.n)),
              additionalData: aad(peerId, ownId, message.n),
            },
            receiveKey,
            new Uint8Array(message.ct),
          ),
        );
      } catch {
        return { ok: false, reason: 'bad-seal' };
      }
      // Decided again after the await: a concurrent call may have taken this number meanwhile.
      const late = verdict(message.n);
      if (late) return { ok: false, reason: late };
      received += 1;
      confirmed = true;
      return { ok: true, plaintext };
    },
  };
  return { ok: true, session };
}
