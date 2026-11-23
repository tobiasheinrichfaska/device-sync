// Device keys that can leave the key store: for an identity that lives INSIDE an encrypted store of the
// app (for example a separate identity that signs and seals for a channel and is kept in an encrypted
// archive), not for ordinary devices, whose private keys are never extractable (`generateDeviceKeys`).
//
// Decision: this layer does NOT encrypt. The export is one plain JSON text holding the PRIVATE keys;
// wrapping it (a passphrase, the archive's own key) is the app's job, because only the app knows what
// the store around it protects, and a second, weaker wrapper here would be a false comfort. Whoever reads
// the text owns the identity: treat it like a password. The import makes non-extractable keys again.
import { base64url, fromBase64url } from './encoding.ts';
import { hasDuplicateKeys } from './json.ts';
import { publicKeys, type DeviceKeys, type PublicKeys } from './keys.ts';
import { hasMembers, isPlain, parseJson } from './secure.ts';

const SIGNING = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const AGREEMENT = { name: 'ECDH', namedCurve: 'P-256' } as const;
const COORDINATE = /^[A-Za-z0-9_-]{43}$/;

export interface KeyJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
  readonly d: string;
}

export interface ExportedKeys {
  readonly v: 1;
  readonly sig: KeyJwk;
  readonly dh: KeyJwk;
}

/**
 * New keys whose private halves CAN be exported. Only for an identity the app keeps inside an
 * encrypted store (see above); a device's own keys come from `generateDeviceKeys`.
 */
export async function generateExportableDeviceKeys(): Promise<DeviceKeys> {
  return {
    signing: await crypto.subtle.generateKey(SIGNING, true, ['sign', 'verify']),
    agreement: await crypto.subtle.generateKey(AGREEMENT, true, ['deriveBits']),
  };
}

const jwkOf = async (privateKey: CryptoKey): Promise<KeyJwk> => {
  const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', privateKey);
  return { kty, crv, x, y, d } as KeyJwk;
};

export type ExportKeysResult =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly reason: 'not-extractable' };

/**
 * The private keys as one JSON text (members in this order: `v`, `sig`, `dh`, each a JWK of exactly
 * `kty`, `crv`, `x`, `y`, `d`). PLAIN TEXT HOLDING SECRETS: the app encrypts it before it is stored
 * or handed on. `not-extractable` for keys made by `generateDeviceKeys`.
 */
export async function exportDeviceKeys(keys: DeviceKeys): Promise<ExportKeysResult> {
  try {
    const exported: ExportedKeys = {
      v: 1,
      sig: await jwkOf(keys.signing.privateKey),
      dh: await jwkOf(keys.agreement.privateKey),
    };
    return { ok: true, text: JSON.stringify(exported) };
  } catch {
    return { ok: false, reason: 'not-extractable' };
  }
}

export type ImportKeysFailure = 'unreadable' | 'bad-key' | 'inconsistent' | 'wrong-keys';

export type ImportKeysResult =
  | { readonly ok: true; readonly keys: DeviceKeys; readonly public: PublicKeys }
  | { readonly ok: false; readonly reason: ImportKeysFailure };

const readJwk = (value: unknown): KeyJwk | undefined => {
  if (!isPlain(value) || !hasMembers(value, ['kty', 'crv', 'x', 'y', 'd'])) return undefined;
  const { kty, crv, x, y, d } = value;
  if (kty !== 'EC' || crv !== 'P-256') return undefined;
  for (const part of [x, y, d]) {
    if (typeof part !== 'string' || !COORDINATE.test(part)) return undefined;
    // one spelling: the spare bits of the last character are zero
    if (base64url(fromBase64url(part)) !== part) return undefined;
  }
  return { kty, crv, x: x as string, y: y as string, d: d as string };
};

/**
 * Keys from the text `exportDeviceKeys` made (strictly: one spelling, no member too many, duplicate
 * keys refused), as NON-extractable keys. The private and public halves must belong together (checked
 * by a signature and by a key agreement; a mismatch is `inconsistent`). `expect` (the public keys the
 * identity is known by, for example from the device list) must match, else `wrong-keys`. Never throws.
 */
export async function importDeviceKeys(
  text: unknown,
  options: { readonly expect?: PublicKeys } = {},
): Promise<ImportKeysResult> {
  const fail = (reason: ImportKeysFailure): ImportKeysResult => ({ ok: false, reason });
  if (typeof text !== 'string' || text.length > 4000 || hasDuplicateKeys(text)) {
    return fail('unreadable');
  }
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['v', 'sig', 'dh']) || raw.v !== 1) {
    return fail('unreadable');
  }
  const sig = readJwk(raw.sig);
  const dh = readJwk(raw.dh);
  if (!sig || !dh) return fail('unreadable');
  try {
    const publicOf = ({ kty, crv, x, y }: KeyJwk): JsonWebKey => ({ kty, crv, x, y });
    const signing: CryptoKeyPair = {
      privateKey: await crypto.subtle.importKey('jwk', sig, SIGNING, false, ['sign']),
      publicKey: await crypto.subtle.importKey('jwk', publicOf(sig), SIGNING, true, ['verify']),
    };
    const agreement: CryptoKeyPair = {
      privateKey: await crypto.subtle.importKey('jwk', dh, AGREEMENT, false, ['deriveBits']),
      publicKey: await crypto.subtle.importKey('jwk', publicOf(dh), AGREEMENT, true, []),
    };
    // the halves belong together
    const probe = new Uint8Array([1, 2, 3]);
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      signing.privateKey,
      probe,
    );
    const signed = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      signing.publicKey,
      signature,
      probe,
    );
    const ephemeral = await crypto.subtle.generateKey(AGREEMENT, false, ['deriveBits']);
    const a = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'ECDH', public: ephemeral.publicKey },
        agreement.privateKey,
        256,
      ),
    );
    const b = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'ECDH', public: agreement.publicKey },
        ephemeral.privateKey,
        256,
      ),
    );
    if (!signed || a.length !== b.length || a.some((v, i) => v !== b[i])) {
      return fail('inconsistent');
    }
    const keys: DeviceKeys = { signing, agreement };
    const pub = await publicKeys(keys);
    if (options.expect && (options.expect.sig !== pub.sig || options.expect.dh !== pub.dh)) {
      return fail('wrong-keys');
    }
    return { ok: true, keys, public: pub };
  } catch {
    return fail('bad-key');
  }
}
