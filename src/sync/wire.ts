// The packet: what the sealed file of one relay exchange carries. One compact JSON text, members in
// this order:
//   {"m":"<app>-sync:1","r":"<16 hex>","msg":<one message of the log exchange>}
// `r` names the pull round (chosen by the asker, 64 random bits); `msg` is exactly a message of
// docs/wire-format.md, "Exchange" (`stand` asks, `changes` pieces answer; `done` is never sent). The
// reader is strict (one member list, duplicate keys refused, the message read by the log's parser) and
// bounded before it parses. Never throws.
import { hasDuplicateKeys } from '../core/json.ts';
import { marker } from '../core/markers.ts';
import { decodeUtf8, hasMembers, isPlain, parseJson } from '../core/secure.ts';
import {
  parseSyncMessage,
  resolveLimits,
  type ParseOptions,
  type SyncMessage,
} from '../log/index.ts';

const ROUND = /^[0-9a-f]{16}$/;
const utf8 = new TextEncoder();

export const syncMark = (appId: string): string => marker(appId, 'sync', 1);

/** Whether a round id is well-formed (16 lower-case hex digits). */
export const isRoundId = (text: unknown): text is string =>
  typeof text === 'string' && ROUND.test(text);

export function writePacket(appId: string, round: string, message: SyncMessage): Uint8Array {
  return utf8.encode(`{"m":"${syncMark(appId)}","r":"${round}","msg":${JSON.stringify(message)}}`);
}

export interface Packet {
  readonly round: string;
  readonly message: SyncMessage;
  /** The message as read from the text: `receiveJudged` takes it again, strictly. */
  readonly raw: unknown;
}

/** Whether the bytes begin like a packet of this app (a cheap look before the strict reader). */
export function looksLikePacket(appId: string, bytes: Uint8Array): boolean {
  const head = utf8.encode(`{"m":"${syncMark(appId)}","r":"`);
  return bytes.length > head.length && head.every((b, i) => bytes[i] === b);
}

/** The most bytes of a packet a reader takes (one message of the exchange plus the frame around it). */
export const maxPacketBytes = (options: ParseOptions): number =>
  resolveLimits(options.limits).maxMessageChars * 4 + 256;

export function readPacket(
  appId: string,
  bytes: unknown,
  options: ParseOptions = {},
): Packet | undefined {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return undefined;
  if (bytes.length > maxPacketBytes(options) || !looksLikePacket(appId, bytes)) return undefined;
  const text = decodeUtf8(bytes);
  if (text === undefined) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || !hasMembers(raw, ['m', 'r', 'msg'])) return undefined;
  if (hasDuplicateKeys(text)) return undefined;
  if (raw.m !== syncMark(appId) || !isRoundId(raw.r)) return undefined;
  const message = parseSyncMessage(raw.msg, options);
  return message && { round: raw.r, message, raw: raw.msg };
}
