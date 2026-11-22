// What an envelope of a channel carries: one compact JSON text, members in this order:
//   {"v":1,"stand":<version vector of the sender's replica of the channel>,"changes":[<change>,...]}
// The channel itself and the author are not in the body: they are in the envelope, under its signature.
// The reader is strict (one member list, duplicate keys refused, every change read by the log's
// parser, bounded before it parses) and never throws.
import { hasDuplicateKeys } from '../core/json.ts';
import { decodeUtf8, hasMembers, isPlain, parseJson } from '../core/secure.ts';
import {
  parseChange,
  parseVector,
  resolveLimits,
  type Change,
  type ParseOptions,
  type VersionVector,
} from '../log/index.ts';

export const CHANNEL_BODY_VERSION = 1;
const utf8 = new TextEncoder();

export interface ChannelBody {
  readonly stand: VersionVector;
  readonly changes: readonly Change[];
}

export function writeChannelBody(stand: VersionVector, changes: readonly Change[]): Uint8Array {
  return utf8.encode(
    `{"v":${CHANNEL_BODY_VERSION},"stand":${JSON.stringify(stand)},"changes":${JSON.stringify(changes)}}`,
  );
}

/** The most bytes a reader takes (before it parses anything). */
export const maxBodyBytes = (options: ParseOptions = {}): number =>
  resolveLimits(options.limits).maxMessageChars * 4 + 4096;

export function readChannelBody(
  bytes: unknown,
  options: ParseOptions = {},
): ChannelBody | undefined {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.length === 0 ||
    bytes.length > maxBodyBytes(options)
  ) {
    return undefined;
  }
  const text = decodeUtf8(bytes);
  if (text === undefined || !text.startsWith('{"v":1,"stand":')) return undefined;
  try {
    if (hasDuplicateKeys(text)) return undefined;
    const raw = parseJson(text);
    if (!isPlain(raw) || !hasMembers(raw, ['v', 'stand', 'changes'])) return undefined;
    if (raw.v !== CHANNEL_BODY_VERSION || !Array.isArray(raw.changes)) return undefined;
    if (raw.changes.length > resolveLimits(options.limits).maxChanges) return undefined;
    const stand = parseVector(raw.stand, options);
    if (!stand) return undefined;
    const changes: Change[] = [];
    for (const entry of raw.changes as unknown[]) {
      const change = parseChange(entry, options);
      if (!change) return undefined;
      changes.push(change);
    }
    return { stand, changes };
  } catch {
    return undefined;
  }
}
