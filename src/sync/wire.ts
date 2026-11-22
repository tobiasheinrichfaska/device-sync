// The packet: what the sealed file of one relay exchange carries. One compact JSON text, members in
// this order. Two shapes:
//   {"m":"<app>-sync:2","r":"<16 hex>","s":"<set>","msg":<one message of the log exchange>}
//   {"m":"<app>-sync:2","r":"<16 hex>","post":"<one message text of the mailbox exchange>"}
// `r` names the round (chosen by the asker, 64 random bits); `s` names the data set the message is
// about; `msg` is exactly a message of docs/wire-format.md, "Exchange" (`stand` asks, `changes` pieces
// answer; `done` is never sent); `post` is exactly a message text of "Mailbox". The reader is strict
// (one member list per shape, duplicate keys refused, the message read by the log's or the post
// layer's parser, set names of one spelling) and bounded before it parses. Never throws.
import { hasDuplicateKeys } from '../core/json.ts';
import { marker } from '../core/markers.ts';
import { decodeUtf8, hasMembers, isPlain, parseJson } from '../core/secure.ts';
import {
  parseSyncMessage,
  resolveLimits,
  type ParseOptions,
  type SyncMessage,
} from '../log/index.ts';
import {
  maxMessageChars,
  readPostMessage,
  resolvePostLimits,
  type PostLimits,
} from '../post/index.ts';

const ROUND = /^[0-9a-f]{16}$/;
const SET = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,79}$/;
const utf8 = new TextEncoder();

export const syncMark = (appId: string): string => marker(appId, 'sync', 2);

/** Whether a round id is well-formed (16 lower-case hex digits). */
export const isRoundId = (text: unknown): text is string =>
  typeof text === 'string' && ROUND.test(text);

/** Whether a data set name is well-formed: 1 to 80 of letters, digits and `:._-`, starting with a letter or digit. */
export const isSetName = (text: unknown): text is string =>
  typeof text === 'string' && SET.test(text);

export function writePacket(
  appId: string,
  round: string,
  set: string,
  message: SyncMessage,
): Uint8Array {
  return utf8.encode(
    `{"m":"${syncMark(appId)}","r":"${round}","s":${JSON.stringify(set)},"msg":${JSON.stringify(message)}}`,
  );
}

/** A packet of the mailbox exchange: `text` is one message text of the post layer. */
export function writePostPacket(appId: string, round: string, text: string): Uint8Array {
  return utf8.encode(`{"m":"${syncMark(appId)}","r":"${round}","post":${JSON.stringify(text)}}`);
}

export type Packet =
  | {
      readonly kind: 'log';
      readonly round: string;
      readonly set: string;
      readonly message: SyncMessage;
      /** The message as read from the text: `receiveJudged` takes it again, strictly. */
      readonly raw: unknown;
    }
  | { readonly kind: 'post'; readonly round: string; readonly text: string };

/** Whether the bytes begin like a packet of this app (a cheap look before the strict reader). */
export function looksLikePacket(appId: string, bytes: Uint8Array): boolean {
  const head = utf8.encode(`{"m":"${syncMark(appId)}","r":"`);
  return bytes.length > head.length && head.every((b, i) => bytes[i] === b);
}

/** The most bytes of a packet a reader takes (one message of either exchange plus the frame around it). */
export const maxPacketBytes = (options: ParseOptions, post?: Partial<PostLimits>): number =>
  Math.max(
    resolveLimits(options.limits).maxMessageChars * 4,
    maxMessageChars(resolvePostLimits(post)) * 6,
  ) + 256;

export function readPacket(
  appId: string,
  bytes: unknown,
  options: ParseOptions = {},
  post?: Partial<PostLimits>,
): Packet | undefined {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return undefined;
  if (bytes.length > maxPacketBytes(options, post) || !looksLikePacket(appId, bytes)) {
    return undefined;
  }
  const text = decodeUtf8(bytes);
  if (text === undefined) return undefined;
  const raw = parseJson(text);
  if (!isPlain(raw) || hasDuplicateKeys(text)) return undefined;
  if (raw.m !== syncMark(appId) || !isRoundId(raw.r)) return undefined;
  if (hasMembers(raw, ['m', 'r', 's', 'msg'])) {
    if (!isSetName(raw.s)) return undefined;
    const message = parseSyncMessage(raw.msg, options);
    return message && { kind: 'log', round: raw.r, set: raw.s, message, raw: raw.msg };
  }
  if (hasMembers(raw, ['m', 'r', 'post'])) {
    if (typeof raw.post !== 'string') return undefined;
    return readPostMessage(appId, raw.post, post)
      ? { kind: 'post', round: raw.r, text: raw.post }
      : undefined;
  }
  return undefined;
}
