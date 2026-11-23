// Proof of possession of revision 2 (docs/relay-protocol.md, "Revision 2"): a certificate alone is
// worth nothing; every request that carries one is signed with the device's private key. The text
// that is signed, the value of the header and a signer over a WebCrypto key pair live here. Nothing
// reads a clock or a random number: the time is a parameter, and ECDSA draws its own nonce inside
// WebCrypto, so two requests of one second are two different signatures (the relay takes each once).
import { base64url } from '../core/encoding.ts';
import { readBytes } from '../core/secure.ts';

/** What signs for one device: its public key (raw, uncompressed, canonical base64url) and a signature function. */
export interface PossessionSigner {
  /** The raw uncompressed P-256 point, 65 bytes, 87 characters of canonical base64url. */
  readonly publicKey: string;
  /** ECDSA P-256 / SHA-256, IEEE P1363 (64 bytes, as WebCrypto gives it). May throw or reject. */
  sign(data: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

/** The names of the two request headers of revision 2 (lower case). They are configuration of the pair. */
export interface RelayHeaderNames {
  /** Carries `<t>.<signature>`. */
  readonly possession: string;
  /** Carries the protocol revision the client announces (1 to 3 digits). */
  readonly version: string;
}

/** The neutral names this document proposes. The existing relay servers use older names (open point 15). */
export const DEFAULT_HEADER_NAMES: RelayHeaderNames = {
  possession: 'x-relay-signature',
  version: 'x-relay-protocol',
};

/** A header name: `x-` and lower-case letters, digits, hyphens. */
export const isHeaderName = (v: unknown): v is string =>
  typeof v === 'string' && /^x-[a-z0-9-]{1,40}$/.test(v);

/** A raw public key: 65 bytes, the first one 4, canonical base64url. (Whether it lies on the curve is for WebCrypto.) */
export function isRawPublicKey(v: unknown): v is string {
  const bytes = readBytes(v, 65, 65);
  return typeof v === 'string' && v.length === 87 && bytes !== undefined && bytes[0] === 4;
}

const utf8 = new TextEncoder();

/** SHA-256 of a UTF-8 body, base64url (the empty body gives the well-known `47DEQp...`). */
export async function bodyHash(body: string): Promise<string> {
  return base64url(
    new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', utf8.encode(body))),
  );
}

/** The text that is signed: `v1`, method, path, time, hash of the body, certificate, joined by line feeds. */
export function possessionText(
  method: string,
  path: string,
  t: number,
  hashOfBody: string,
  certificate: string,
): string {
  return `v1\n${method}\n${path}\n${t}\n${hashOfBody}\n${certificate}`;
}

/** The value of the possession header: `<t>.<signature>`; undefined when the signer fails or answers badly. */
export async function possessionValue(o: {
  readonly signer: PossessionSigner;
  readonly method: string;
  /** The path of the address, for example `/v1/collect`'s wire form `/v1/abholen`. */
  readonly path: string;
  /** The exact body text that is sent. */
  readonly body: string;
  readonly certificate: string;
  readonly nowMs: number;
}): Promise<string | undefined> {
  try {
    const t = Math.floor(o.nowMs / 1000);
    if (!Number.isSafeInteger(t) || t < 1) return undefined;
    const text = possessionText(o.method, o.path, t, await bodyHash(o.body), o.certificate);
    const signature = await o.signer.sign(utf8.encode(text));
    if (!(signature instanceof Uint8Array) || signature.length !== 64) return undefined;
    return `${t}.${base64url(signature)}`;
  } catch {
    return undefined;
  }
}

/**
 * A signer over a WebCrypto ECDSA P-256 key pair: `privateKey` signs (it may be non-extractable),
 * `publicKey` is the pair's public key (its raw export is the identity the relay certifies).
 */
export async function signerFromKeys(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<PossessionSigner> {
  const raw = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', publicKey));
  const text = base64url(raw);
  if (!isRawPublicKey(text)) throw new TypeError('not an uncompressed P-256 public key');
  return {
    publicKey: text,
    sign: async (data) =>
      new Uint8Array(
        await globalThis.crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          privateKey,
          data as BufferSource,
        ),
      ),
  };
}
