// An encrypted file for ONE named recipient device (hand it over by any channel). The key comes from
// a fresh ephemeral key of the file x the recipient's static key, and from the sender's static key x
// the recipient's static key: only these two devices can make or read it. The payload is opaque
// bytes; what is in them (and how they are serialised) is up to the app. Wire details:
// docs/wire-format.md, "Encrypted file".
import { base64url } from './encoding.ts';
import { FORMAT_VERSION, marker } from './markers.ts';
import {
  TAG_BYTES,
  aesKey,
  base64urlLength,
  concat,
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
const IV_BYTES = 12;
const FILE_OVERHEAD_CHARS = 512;

export interface FileLimits {
  /** The largest payload (bytes) `sealFile` accepts and `openFile` returns. */
  readonly maxPlaintextBytes: number;
}

export const FILE_LIMITS: FileLimits = Object.freeze({ maxPlaintextBytes: 33_554_432 });

/** The defaults with a partial override on top (own integer members only). */
export function resolveFileLimits(override?: Partial<FileLimits>): FileLimits {
  return overrideNumbers({ ...FILE_LIMITS }, override);
}

/** The most bytes of a file under these limits (a reader refuses longer input before it parses). */
export const maxFileBytes = (limits: FileLimits): number =>
  base64urlLength(limits.maxPlaintextBytes + TAG_BYTES) + FILE_OVERHEAD_CHARS + 2 * 1024;

interface RawFile {
  readonly from: string;
  readonly to: string;
  readonly eph: string;
  readonly iv: string;
  readonly ct: string;
}

const fileText = (appId: string, f: RawFile): string =>
  `{"m":${JSON.stringify(marker(appId, 'file', FORMAT_VERSION))},"from":${JSON.stringify(
    f.from,
  )},"to":${JSON.stringify(f.to)},"eph":"${f.eph}","iv":"${f.iv}","ct":"${f.ct}"}`;

interface ParsedFile extends RawFile {
  readonly ivBytes: Uint8Array;
  readonly ctBytes: Uint8Array;
}

/** A file read strictly: exactly the spelling `sealFile` writes, bounded, canonical; else undefined. */
function readFile(appId: string, file: unknown, lim: FileLimits): ParsedFile | undefined {
  if (!(file instanceof Uint8Array) || file.length > maxFileBytes(lim)) return undefined;
  const text = decodeUtf8(file);
  if (text === undefined) return undefined;
  if (!text.startsWith(`{"m":${JSON.stringify(marker(appId, 'file', FORMAT_VERSION))},"from":`)) {
    return undefined;
  }
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'from', 'to', 'eph', 'iv', 'ct'])) return undefined;
  const { from, to, eph, iv, ct } = raw;
  if (!isDeviceText(from) || !isDeviceText(to) || from === to) return undefined;
  if (typeof eph !== 'string' || typeof iv !== 'string' || typeof ct !== 'string') return undefined;
  if (readBytes(eph, 65, 65)?.[0] !== 4) return undefined;
  const ivBytes = readBytes(iv, IV_BYTES, IV_BYTES);
  const ctBytes = readBytes(ct, TAG_BYTES, lim.maxPlaintextBytes + TAG_BYTES);
  if (!ivBytes || !ctBytes) return undefined;
  if (fileText(appId, { from, to, eph, iv, ct }) !== text) return undefined;
  return { from, to, eph, iv, ct, ivBytes, ctBytes };
}

/**
 * Who sent the file to whom, read before opening (to find the sender's key). Strict: anything that
 * is not exactly a file of this app gives undefined. Never throws on foreign input.
 */
export function readFileHeader(
  appId: string,
  file: unknown,
  limits?: Partial<FileLimits>,
): { readonly from: string; readonly to: string } | undefined {
  const parsed = readFile(appId, file, resolveFileLimits(limits));
  return parsed && { from: parsed.from, to: parsed.to };
}

/** The text that is both the HKDF salt (hashed) and the AAD: app, both ids, both static keys, the ephemeral key. */
const headerText = (
  appId: string,
  from: string,
  to: string,
  fromDh: string,
  toDh: string,
  eph: string,
): string =>
  `${marker(appId, 'file', FORMAT_VERSION)}|${field(from)}|${field(to)}|${field(fromDh)}|${field(
    toDh,
  )}|${field(eph)}`;

async function fileKey(appId: string, ikm: Uint8Array, header: string): Promise<CryptoKey> {
  return aesKey(ikm, await sha256(header), `${marker(appId, 'file', FORMAT_VERSION)}|key`);
}

export interface FileSealParams {
  readonly appId: string;
  readonly own: { readonly device: string; readonly agreement: CryptoKeyPair };
  /** The recipient as the trust layer verified it. */
  readonly to: { readonly device: string; readonly dh: string };
  readonly payload: Uint8Array;
  /** 12 random bytes: the GCM nonce (the key is fresh per file, so a repeat would still be harmless). */
  readonly random: Uint8Array;
  readonly limits?: Partial<FileLimits>;
}

export type FileSealRefusal =
  | 'bad-own'
  | 'bad-recipient'
  | 'same-device'
  | 'same-key'
  | 'bad-random'
  | 'bad-input'
  | 'too-large'
  | 'crypto-failure';

export type FileSealed =
  | { readonly ok: true; readonly file: Uint8Array }
  | { readonly ok: false; readonly reason: FileSealRefusal };

/** The file for `to`: the bytes of one compact JSON text. Refusals are codes. */
export async function sealFile(params: FileSealParams): Promise<FileSealed> {
  const { appId, own, to, payload, random } = params;
  marker(appId, 'file', FORMAT_VERSION);
  const lim = resolveFileLimits(params.limits);
  const refuse = (reason: FileSealRefusal): FileSealed => ({ ok: false, reason });
  if (!isPlain(own) || !isDeviceText(own.device)) return refuse('bad-own');
  if (!isPlain(to) || !isDeviceText(to.device) || readBytes(to.dh, 65, 65)?.[0] !== 4) {
    return refuse('bad-recipient');
  }
  if (own.device === to.device) return refuse('same-device');
  if (!(random instanceof Uint8Array) || random.length !== IV_BYTES) return refuse('bad-random');
  if (!(payload instanceof Uint8Array)) return refuse('bad-input');
  if (payload.length > lim.maxPlaintextBytes) return refuse('too-large');
  const ownDh = await ownPoint(own.agreement).catch(() => undefined);
  if (ownDh === undefined) return refuse('bad-own');
  if (ownDh === to.dh) return refuse('same-key');
  const recipient = await importPoint(to.dh);
  if (!recipient) return refuse('bad-recipient');
  try {
    const pair = await crypto.subtle.generateKey(AGREEMENT, false, ['deriveBits']);
    const eph = base64url(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
    const ikm = concat(
      await ecdh(pair.privateKey, recipient),
      await ecdh(own.agreement.privateKey, recipient),
    );
    const header = headerText(appId, own.device, to.device, ownDh, to.dh, eph);
    const key = await fileKey(appId, ikm, header);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: new Uint8Array(random), additionalData: utf8.encode(header) },
        key,
        new Uint8Array(payload),
      ),
    );
    const text = fileText(appId, {
      from: own.device,
      to: to.device,
      eph,
      iv: base64url(random),
      ct: base64url(ct),
    });
    return { ok: true, file: utf8.encode(text) };
  } catch {
    return refuse('crypto-failure');
  }
}

export interface FileOpenParams {
  readonly appId: string;
  readonly own: { readonly device: string; readonly agreement: CryptoKeyPair };
  /** The sender as the trust layer verified it: its id and agreement public key. */
  readonly from: { readonly device: string; readonly dh: string };
  readonly file: Uint8Array;
  readonly limits?: Partial<FileLimits>;
}

export type FileRefusal =
  | 'bad-own'
  | 'bad-sender'
  | 'not-a-file'
  | 'wrong-recipient'
  | 'wrong-sender'
  | 'bad-point'
  | 'cannot-open';

export type FileOpened =
  | { readonly ok: true; readonly from: string; readonly payload: Uint8Array }
  | { readonly ok: false; readonly reason: FileRefusal };

/** Opens a file for this device from the named sender. Never throws on foreign input. */
export async function openFile(params: FileOpenParams): Promise<FileOpened> {
  const { appId, own, from, file } = params;
  marker(appId, 'file', FORMAT_VERSION);
  const lim = resolveFileLimits(params.limits);
  const refuse = (reason: FileRefusal): FileOpened => ({ ok: false, reason });
  if (!isPlain(own) || !isDeviceText(own.device)) return refuse('bad-own');
  if (!isPlain(from) || !isDeviceText(from.device) || readBytes(from.dh, 65, 65)?.[0] !== 4) {
    return refuse('bad-sender');
  }
  const parsed = readFile(appId, file, lim);
  if (!parsed) return refuse('not-a-file');
  if (parsed.to !== own.device) return refuse('wrong-recipient');
  if (parsed.from !== from.device) return refuse('wrong-sender');
  const ownDh = await ownPoint(own.agreement).catch(() => undefined);
  if (ownDh === undefined) return refuse('bad-own');
  const ephemeral = await importPoint(parsed.eph);
  const sender = await importPoint(from.dh);
  if (!ephemeral || !sender) return refuse('bad-point');
  try {
    const ikm = concat(
      await ecdh(own.agreement.privateKey, ephemeral),
      await ecdh(own.agreement.privateKey, sender),
    );
    const header = headerText(appId, parsed.from, parsed.to, from.dh, ownDh, parsed.eph);
    const key = await fileKey(appId, ikm, header);
    const payload = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: new Uint8Array(parsed.ivBytes),
          additionalData: utf8.encode(header),
        },
        key,
        new Uint8Array(parsed.ctBytes),
      ),
    );
    return { ok: true, from: parsed.from, payload };
  } catch {
    return refuse('cannot-open');
  }
}
