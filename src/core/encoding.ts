import { sha256 } from '@noble/hashes/sha2.js';

const utf8 = new TextEncoder();

/** Unpadded base64url (RFC 4648 section 5). */
export function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return globalThis.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Strict inverse of `base64url`: only [A-Za-z0-9_-]; anything else (padding, spaces) throws. */
export function fromBase64url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('not base64url');
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = globalThis.atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/** SHA-256 of the UTF-8 encoding of a text. */
export function sha256Text(text: string): Uint8Array {
  return sha256(utf8.encode(text));
}
