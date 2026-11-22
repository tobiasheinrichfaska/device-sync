// A sealed envelope: one message for SEVERAL reader devices that third devices can carry without
// learning who wrote it, who may read it or how many readers there are (up to a multiple of 8).
// The content is encrypted once; its key is wrapped for every reader ("fan slot") with a fresh
// ephemeral key x the reader's agreement key. The slots are padded with random ones and shuffled.
// Inside, the AUTHOR signs app, sender, channel, day and content, so a carrier cannot relabel it.
// Wire details and what is and is not hidden: docs/wire-format.md, "Envelope".
import { base64url, sha256Text } from './encoding.ts';
import { isDay } from './day.ts';
import { importPublicKey } from './keys.ts';
import { FORMAT_VERSION, marker } from './markers.ts';
import { signText, verifyText } from './signature.ts';
import {
  TAG_BYTES,
  aesKey,
  decodeUtf8,
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

const utf8 = new TextEncoder();
const AGREEMENT = { name: 'ECDH', namedCurve: 'P-256' } as const;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const ID_BYTES = 16;
/** A fan slot is the wrapped 32-byte content key plus the 16-byte tag. */
const SLOT_BYTES = KEY_BYTES + TAG_BYTES;
const SIGNATURE_BYTES = 64;
const ZERO_IV = new Uint8Array(IV_BYTES);
const MAX_ENVELOPE_BYTES_CEILING = 1 << 24;
const MAX_FAN_GROUPS = 512;

/** The fan is filled up with random slots to a multiple of this: the number of readers hides in it. */
export const FAN_GROUP = 8;

export interface EnvelopeLimits {
  /** The whole wire text of an envelope, in bytes (it is ASCII). */
  readonly maxEnvelopeBytes: number;
  /** Fan slots: readers plus padding. Rounded down to a multiple of 8, at least 8. */
  readonly maxFans: number;
}

export const ENVELOPE_LIMITS: EnvelopeLimits = Object.freeze({
  maxEnvelopeBytes: 11_000,
  maxFans: 64,
});

/** The defaults with a partial override on top (own, safe, non-negative integers; fans clamped). */
export function resolveEnvelopeLimits(override?: Partial<EnvelopeLimits>): EnvelopeLimits {
  const out = overrideNumbers({ ...ENVELOPE_LIMITS }, override);
  const groups = Math.min(Math.max(Math.floor(out.maxFans / FAN_GROUP), 1), MAX_FAN_GROUPS);
  return {
    maxEnvelopeBytes: Math.min(out.maxEnvelopeBytes, MAX_ENVELOPE_BYTES_CEILING),
    maxFans: groups * FAN_GROUP,
  };
}

/** The largest ciphertext / body (bytes) that can fit into an envelope of this size. */
const payloadCeiling = (lim: EnvelopeLimits): number => Math.floor((lim.maxEnvelopeBytes * 3) / 4);

/** What a carrier sees and stores: the id, the day, and the exact wire text. Immutable. */
export interface Envelope {
  readonly id: string;
  readonly day: string;
  readonly text: string;
}

// Envelopes made by `sealEnvelope` or read by `readEnvelope` are frozen and remembered here, so
// the mailbox need not read an envelope it already read (a hand-made object is read again).
// The app id is remembered with it: an envelope of another app is never "known". So are its size and
// its number of fan slots: it was read under SOME limits, and a mailbox with tighter ones must not
// take it on trust.
const known = new WeakMap<
  object,
  { readonly appId: string; readonly size: number; readonly fans: number }
>();

function make(appId: string, id: string, day: string, text: string, fans: number): Envelope {
  const envelope = Object.freeze({ id, day, text });
  known.set(envelope, { appId, size: text.length, fans });
  return envelope;
}

/**
 * True for an envelope of this app that this module made or read itself (not for a look-alike) and,
 * when `limits` are given, that is within them (it may have been read under larger ones).
 */
export function isKnownEnvelope(
  value: unknown,
  appId: string,
  limits?: Partial<EnvelopeLimits>,
): value is Envelope {
  if (typeof value !== 'object' || value === null) return false;
  const entry = known.get(value);
  if (entry?.appId !== appId) return false;
  if (!limits) return true;
  const lim = resolveEnvelopeLimits(limits);
  return entry.size <= lim.maxEnvelopeBytes && entry.fans <= lim.maxFans;
}

/** The members of an envelope as they sit on the wire (the id is computed from them). */
export interface EnvelopeParts {
  readonly day: string;
  readonly eph: string;
  readonly iv: string;
  readonly ct: string;
  readonly k: readonly string[];
}

/**
 * The id: the first 16 bytes of SHA-256 over every member, each length-prefixed, base64url (22
 * characters). A changed copy cannot pass under the id of the real envelope.
 */
export function envelopeId(appId: string, parts: EnvelopeParts): string {
  const text = `${marker(appId, 'envid', FORMAT_VERSION)}|${field(parts.day)}|${field(
    parts.eph,
  )}|${field(parts.iv)}|${field(parts.ct)}|${parts.k.length}|${parts.k.map(field).join('|')}`;
  return base64url(sha256Text(text).slice(0, ID_BYTES));
}

const envelopeText = (appId: string, id: string, p: EnvelopeParts): string =>
  `{"m":"${marker(appId, 'envelope', FORMAT_VERSION)}","id":"${id}","day":"${p.day}","eph":"${
    p.eph
  }","iv":"${p.iv}","ct":"${p.ct}","k":[${p.k.map((slot) => `"${slot}"`).join(',')}]}`;

/**
 * An envelope from its parts (the id is computed). Lower level than `sealEnvelope`: nothing is
 * encrypted; for tools and tests that need a well-formed envelope. A malformed part is a TypeError.
 */
export function buildEnvelope(
  appId: string,
  parts: EnvelopeParts,
  limits?: Partial<EnvelopeLimits>,
): Envelope {
  const id = envelopeId(appId, parts);
  const text = envelopeText(appId, id, parts);
  const read = readEnvelope(appId, text, limits);
  if (!read) throw new TypeError('buildEnvelope: the parts do not make a valid envelope');
  return read;
}

/**
 * An envelope from an already parsed JSON value, strictly: exactly these members in this order, every
 * member canonical, the id the one of its content, the text within the size limit. Else undefined.
 * Never throws.
 */
export function envelopeFromValue(
  appId: string,
  raw: unknown,
  limits?: Partial<EnvelopeLimits>,
): Envelope | undefined {
  const m = marker(appId, 'envelope', FORMAT_VERSION);
  const lim = resolveEnvelopeLimits(limits);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'id', 'day', 'eph', 'iv', 'ct', 'k'])) {
    return undefined;
  }
  const { id, day, eph, iv, ct, k } = raw;
  if (raw.m !== m || typeof id !== 'string' || !readBytes(id, ID_BYTES, ID_BYTES)) return undefined;
  if (!isDay(day) || typeof eph !== 'string' || typeof iv !== 'string') return undefined;
  if (typeof ct !== 'string' || readBytes(eph, 65, 65)?.[0] !== 4) return undefined;
  if (!readBytes(iv, IV_BYTES, IV_BYTES) || !readBytes(ct, TAG_BYTES, payloadCeiling(lim))) {
    return undefined;
  }
  if (!Array.isArray(k) || k.length < FAN_GROUP || k.length > lim.maxFans) return undefined;
  if (k.length % FAN_GROUP !== 0) return undefined;
  const slots: string[] = [];
  for (const slot of k as unknown[]) {
    if (typeof slot !== 'string' || !readBytes(slot, SLOT_BYTES, SLOT_BYTES)) return undefined;
    slots.push(slot);
  }
  const parts: EnvelopeParts = { day, eph, iv, ct, k: slots };
  if (envelopeId(appId, parts) !== id) return undefined;
  const text = envelopeText(appId, id, parts);
  return text.length > lim.maxEnvelopeBytes ? undefined : make(appId, id, day, text, slots.length);
}

/** An envelope from its wire text: exactly one spelling, bounded before parsing. Else undefined. */
export function readEnvelope(
  appId: string,
  text: unknown,
  limits?: Partial<EnvelopeLimits>,
): Envelope | undefined {
  const lim = resolveEnvelopeLimits(limits);
  if (typeof text !== 'string' || text.length > lim.maxEnvelopeBytes) return undefined;
  if (!text.startsWith(`{"m":"${marker(appId, 'envelope', FORMAT_VERSION)}","id":"`)) {
    return undefined;
  }
  const envelope = envelopeFromValue(appId, parseJson(text), lim);
  return envelope?.text === text ? envelope : undefined;
}

/** The members every key and the content tag are bound to: app, day and the ephemeral key. */
const headerText = (appId: string, day: string, eph: string): string =>
  `${marker(appId, 'envelope', FORMAT_VERSION)}|header|${field(day)}|${field(eph)}`;

async function slotKey(
  appId: string,
  secret: Uint8Array,
  header: string,
  dh: string,
): Promise<CryptoKey> {
  return aesKey(
    secret,
    await sha256(header),
    `${marker(appId, 'envelope', FORMAT_VERSION)}|slot|${field(dh)}`,
  );
}

/** What the author signs: app, sender, channel, day and the content, every field length-prefixed. */
const signedText = (
  appId: string,
  from: string,
  channel: string,
  day: string,
  body: string,
): string =>
  `${marker(appId, 'envsig', FORMAT_VERSION)}|${field(from)}|${field(channel)}|${field(day)}|${field(
    body,
  )}`;

const innerText = (from: string, channel: string, sig: string, body: string): string =>
  `{"from":${JSON.stringify(from)},"channel":${JSON.stringify(channel)},"sig":"${sig}","body":"${body}"}`;

/**
 * Fisher-Yates with 4 random bytes per element (`bytes.length` must be at least 4 x the list):
 * a copy, the input is not touched. The modulo bias is below 2^-26 per step.
 */
export function shuffled<T>(list: readonly T[], bytes: Uint8Array): T[] {
  const out = [...list];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = view.getUint32(4 * i) % (i + 1);
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
}

export interface EnvelopeSealParams {
  readonly appId: string;
  /** The author: its device id and its signing PRIVATE key (ECDSA P-256). */
  readonly author: { readonly device: string; readonly signing: CryptoKey };
  /** The agreement public keys (points) of the reader devices, as the trust layer verified them. */
  readonly recipients: readonly string[];
  /** Which stream of the app the content belongs to (a device-id-like text; the app decides). */
  readonly channel: string;
  /** The day it is sealed (`YYYY-MM-DD`): a carrier drops it after a while. */
  readonly day: string;
  /** The content: opaque bytes. */
  readonly body: Uint8Array;
  /**
   * `random(n)` gives n fresh random bytes (a CSPRNG in production). Used for the content key, the
   * nonce, the padding slots and the shuffle. Sealing also draws one ephemeral key pair from WebCrypto.
   */
  readonly random: (length: number) => Uint8Array;
  readonly limits?: Partial<EnvelopeLimits>;
}

export type EnvelopeSealRefusal =
  | 'bad-author'
  | 'bad-channel'
  | 'bad-day'
  | 'bad-input'
  | 'bad-random'
  | 'no-recipients'
  | 'too-many-recipients'
  | 'bad-recipient'
  | 'too-large'
  | 'crypto-failure';

export type EnvelopeSealed =
  | { readonly ok: true; readonly envelope: Envelope }
  | { readonly ok: false; readonly reason: EnvelopeSealRefusal };

/**
 * Seals `body` for the recipients. A recipient listed twice is one reader; the fan is padded with
 * random slots to a multiple of 8 and shuffled. Refusals are codes; nothing is changed by a refusal.
 */
export async function sealEnvelope(params: EnvelopeSealParams): Promise<EnvelopeSealed> {
  const { appId, author, recipients, channel, day, body, random } = params;
  marker(appId, 'envelope', FORMAT_VERSION);
  const lim = resolveEnvelopeLimits(params.limits);
  const refuse = (reason: EnvelopeSealRefusal): EnvelopeSealed => ({ ok: false, reason });
  if (!isPlain(author) || !isDeviceText(author.device)) return refuse('bad-author');
  const signing = author.signing as CryptoKey | null | undefined;
  if (
    typeof signing !== 'object' ||
    signing === null ||
    signing.type !== 'private' ||
    signing.algorithm?.name !== 'ECDSA' ||
    !signing.usages?.includes('sign')
  ) {
    return refuse('bad-author');
  }
  if (!isDeviceText(channel)) return refuse('bad-channel');
  if (!isDay(day)) return refuse('bad-day');
  if (!(body instanceof Uint8Array)) return refuse('bad-input');
  if (typeof random !== 'function') return refuse('bad-random');
  if (!Array.isArray(recipients) || recipients.length === 0) return refuse('no-recipients');
  if (recipients.length > lim.maxFans) return refuse('too-many-recipients');
  const readers: string[] = [];
  const seen = new Set<string>();
  for (const dh of recipients as unknown[]) {
    if (typeof dh !== 'string' || readBytes(dh, 65, 65)?.[0] !== 4) return refuse('bad-recipient');
    if (!seen.has(dh)) {
      seen.add(dh);
      readers.push(dh);
    }
  }
  if (body.length > payloadCeiling(lim)) return refuse('too-large');
  const keys: CryptoKey[] = [];
  for (const dh of readers) {
    const key = await importPoint(dh);
    if (!key) return refuse('bad-recipient');
    keys.push(key);
  }
  const fans = Math.ceil(readers.length / FAN_GROUP) * FAN_GROUP;
  const draw = (length: number): Uint8Array<ArrayBuffer> | undefined => {
    try {
      const bytes = random(length);
      return bytes instanceof Uint8Array && bytes.length === length
        ? new Uint8Array(bytes)
        : undefined;
    } catch {
      return undefined;
    }
  };
  const contentKey = draw(KEY_BYTES);
  const iv = draw(IV_BYTES);
  const padding = Array.from({ length: fans - readers.length }, () => draw(SLOT_BYTES));
  const order = draw(4 * fans);
  if (!contentKey || !iv || !order || padding.some((slot) => slot === undefined)) {
    return refuse('bad-random');
  }
  try {
    const bodyText = base64url(body);
    const sig = await signText(
      author.signing,
      signedText(appId, author.device, channel, day, bodyText),
    );
    const pair = await crypto.subtle.generateKey(AGREEMENT, false, ['deriveBits']);
    const eph = base64url(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
    const header = headerText(appId, day, eph);
    const slots: string[] = [];
    for (const [index, dh] of readers.entries()) {
      const kek = await slotKey(
        appId,
        await ecdh(pair.privateKey, keys[index] as CryptoKey),
        header,
        dh,
      );
      const slot = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ZERO_IV }, kek, contentKey);
      slots.push(base64url(new Uint8Array(slot)));
    }
    for (const slot of padding) slots.push(base64url(slot as Uint8Array));
    const key = await crypto.subtle.importKey('raw', contentKey, 'AES-GCM', false, ['encrypt']);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: utf8.encode(header) },
        key,
        utf8.encode(innerText(author.device, channel, sig, bodyText)),
      ),
    );
    const parts: EnvelopeParts = {
      day,
      eph,
      iv: base64url(iv),
      ct: base64url(ct),
      k: shuffled(slots, order),
    };
    const id = envelopeId(appId, parts);
    const text = envelopeText(appId, id, parts);
    return text.length > lim.maxEnvelopeBytes
      ? refuse('too-large')
      : { ok: true, envelope: make(appId, id, day, text, parts.k.length) };
  } catch {
    return refuse('crypto-failure');
  }
}

export interface EnvelopeOpenParams {
  readonly appId: string;
  /** This device's agreement pair (the public half is read from it). */
  readonly own: { readonly agreement: CryptoKeyPair };
  /** The wire text, or an envelope that was read or sealed here. */
  readonly envelope: string | Envelope;
  /**
   * Asked once, with the author id found INSIDE the envelope: the author's signing public key (a
   * point) as the trust layer knows it, or undefined for a device that is not trusted.
   */
  readonly authorKey: (from: string) => string | undefined | Promise<string | undefined>;
  readonly limits?: Partial<EnvelopeLimits>;
}

export type EnvelopeRefusal =
  | 'bad-own'
  | 'not-an-envelope'
  | 'bad-point'
  | 'not-for-me'
  | 'damaged'
  | 'unknown-author'
  | 'bad-signature';

export type EnvelopeOpened =
  | {
      readonly ok: true;
      readonly id: string;
      readonly from: string;
      readonly channel: string;
      readonly day: string;
      readonly body: Uint8Array;
    }
  | { readonly ok: false; readonly reason: EnvelopeRefusal };

/**
 * Opens an envelope with this device's agreement key and checks the author's signature. Cost for an
 * envelope that is NOT for this device: one point check, one ECDH, one key derivation and at most
 * `maxFans` small AES-GCM trials; for one that is: one more decryption of the content, one
 * signature check. Never throws on foreign input.
 */
export async function openEnvelope(params: EnvelopeOpenParams): Promise<EnvelopeOpened> {
  const { appId, own } = params;
  marker(appId, 'envelope', FORMAT_VERSION);
  const lim = resolveEnvelopeLimits(params.limits);
  const refuse = (reason: EnvelopeRefusal): EnvelopeOpened => ({ ok: false, reason });
  if (!isPlain(own) || typeof params.authorKey !== 'function') return refuse('bad-own');
  const ownDh = await ownPoint(own.agreement).catch(() => undefined);
  if (ownDh === undefined) return refuse('bad-own');
  const given = params.envelope;
  const read = readEnvelope(appId, typeof given === 'string' ? given : given?.text, lim);
  const parsed = read && (parseJson(read.text) as Record<string, unknown>);
  if (!read || !parsed) return refuse('not-an-envelope');
  const { eph, iv, ct } = parsed as { eph: string; iv: string; ct: string };
  const slots = parsed.k as string[];
  const ephemeral = await importPoint(eph);
  if (!ephemeral) return refuse('bad-point');
  const header = headerText(appId, read.day, eph);
  let contentKey: Uint8Array<ArrayBuffer> | undefined;
  try {
    const kek = await slotKey(
      appId,
      await ecdh(own.agreement.privateKey, ephemeral),
      header,
      ownDh,
    );
    for (const slot of slots) {
      try {
        const bytes = new Uint8Array(
          await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ZERO_IV },
            kek,
            new Uint8Array(readBytes(slot, SLOT_BYTES, SLOT_BYTES) as Uint8Array),
          ),
        );
        contentKey = bytes;
        break;
      } catch {
        // not our slot
      }
    }
  } catch {
    return refuse('bad-own');
  }
  if (!contentKey) return refuse('not-for-me');
  let plain: string | undefined;
  try {
    const key = await crypto.subtle.importKey('raw', contentKey, 'AES-GCM', false, ['decrypt']);
    plain = decodeUtf8(
      new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: new Uint8Array(readBytes(iv, IV_BYTES, IV_BYTES) as Uint8Array),
            additionalData: utf8.encode(header),
          },
          key,
          new Uint8Array(readBytes(ct, TAG_BYTES, payloadCeiling(lim)) as Uint8Array),
        ),
      ),
    );
  } catch {
    return refuse('damaged');
  }
  const inner = plain === undefined ? undefined : parseJson(plain);
  if (!isPlain(inner) || !hasMembers(inner, ['from', 'channel', 'sig', 'body'])) {
    return refuse('damaged');
  }
  const { from, channel, sig, body } = inner;
  if (!isDeviceText(from) || !isDeviceText(channel) || typeof sig !== 'string') {
    return refuse('damaged');
  }
  const bytes = typeof body === 'string' ? readBytes(body, 0, payloadCeiling(lim)) : undefined;
  if (!bytes || !readBytes(sig, SIGNATURE_BYTES, SIGNATURE_BYTES)) return refuse('damaged');
  if (innerText(from, channel, sig, body as string) !== plain) return refuse('damaged');
  let keyText: string | undefined;
  try {
    keyText = await params.authorKey(from);
  } catch {
    keyText = undefined;
  }
  const author = typeof keyText === 'string' ? await importPublicKey(keyText, 'sig') : undefined;
  if (!author) return refuse('unknown-author');
  const text = signedText(appId, from, channel, read.day, body as string);
  if (!(await verifyText(author, text, sig))) return refuse('bad-signature');
  return { ok: true, id: read.id, from, channel, day: read.day, body: new Uint8Array(bytes) };
}
