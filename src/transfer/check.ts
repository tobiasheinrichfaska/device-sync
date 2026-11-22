// A 32-bit check value (CRC-32, IEEE) over a domain marker followed by the data. It catches damage and
// frames of another app (a different `appId` gives a different marker); it is NOT a defence against a
// person who can compute a CRC, which is everybody. Authentication belongs to the layer above.
import { marker } from '../core/markers.ts';

const TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

const utf8 = new TextEncoder();

export function crc32(parts: readonly Uint8Array[]): number {
  let c = 0xffffffff;
  for (const part of parts)
    for (let i = 0; i < part.length; i++)
      c = (TABLE[(c ^ (part[i] as number)) & 0xff] as number) ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** The marker bytes of `(appId, kind)`, or undefined when `appId` is not a valid one. */
export function domainBytes(appId: unknown, kind: string): Uint8Array | undefined {
  try {
    return utf8.encode(marker(appId as string, kind, 1));
  } catch {
    return undefined;
  }
}

/** CRC-32 over the domain marker and then the parts. */
export function domainCheck(domain: Uint8Array, ...parts: Uint8Array[]): number {
  return crc32([domain, ...parts]);
}
