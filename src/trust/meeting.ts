import { FORMAT_VERSION, importPublicKey, marker, signText, verifyText } from '../core/index.ts';
import { resolveValidators } from './ids.ts';
import type { Introduction, ProtocolOptions } from './types.ts';
import { decodeUtf8, isCount, isPlain, isSignature, parseIntroduction, parseJson } from './wire.ts';

/** How old a meeting code may be (the showing device renews it every `MEETING_RENEW_MS`). */
export const MEETING_VALID_MS = 120_000;
export const MEETING_RENEW_MS = 30_000;
/** How far ahead of this device's clock a code may be (clocks differ a little). */
export const MEETING_AHEAD_MS = 60_000;
const MAX_BYTES = 2000;

/** A meeting code as read: the introduction, the role, when it was shown and the device's signature. */
export interface MeetingCode {
  readonly introduction: Introduction;
  readonly role: string;
  readonly time: number;
  readonly private?: true;
  readonly proof: string;
}

const MEMBERS = ['m', 'device', 'name', 'sig', 'dh', 'role', 'time', 'private', 'proof'];

/** What the device signs: the marker and every field of the code, `|`-separated. */
export function meetingSigningText(
  appId: string,
  who: Introduction,
  role: string,
  time: number,
  isPrivate: boolean,
): string {
  const head = marker(appId, 'meeting', FORMAT_VERSION);
  return `${head}|${who.device}|${who.name}|${who.sig}|${who.dh}|${role}|${time}|${isPrivate ? 1 : 0}`;
}

/** The bytes of the code in their one spelling: compact JSON, members in this order. */
function encode(appId: string, c: MeetingCode): Uint8Array {
  const json = JSON.stringify({
    m: marker(appId, 'meeting', FORMAT_VERSION),
    device: c.introduction.device,
    name: c.introduction.name,
    sig: c.introduction.sig,
    dh: c.introduction.dh,
    role: c.role,
    time: c.time,
    ...(c.private === true ? { private: true } : {}),
    proof: c.proof,
  });
  return new TextEncoder().encode(json);
}

/**
 * The code a device shows to another in person (as QR bytes): its introduction, its role, the
 * time and its signature over all of it. A photo passed on is worthless after `MEETING_VALID_MS`.
 * Throws for input that could never be read back (a programming error).
 */
export async function signMeetingCode(
  o: ProtocolOptions,
  who: Introduction,
  role: string,
  time: number,
  signingKey: CryptoKey,
  isPrivate = false,
): Promise<Uint8Array> {
  const valid = resolveValidators(o.valid);
  if (!parseIntroduction(who, valid)) throw new Error('invalid introduction');
  if (!valid.role(role)) throw new Error('invalid role');
  if (!isCount(time)) throw new Error('invalid time');
  if (isPrivate && !valid.privateRoles(role)) throw new Error('role may not be private');
  const proof = await signText(signingKey, meetingSigningText(o.appId, who, role, time, isPrivate));
  return encode(o.appId, {
    introduction: who,
    role,
    time,
    ...(isPrivate ? { private: true as const } : {}),
    proof,
  });
}

/** A scanned code, strictly read; undefined for anything that is not exactly the shape. Never throws. */
export function parseMeetingCode(o: ProtocolOptions, bytes: Uint8Array): MeetingCode | undefined {
  try {
    if (!(bytes instanceof Uint8Array) || bytes.length > MAX_BYTES) return undefined;
    const text = decodeUtf8(bytes);
    if (text === undefined) return undefined;
    const raw = parseJson(text);
    if (!isPlain(raw) || !Object.keys(raw).every((k) => MEMBERS.includes(k))) return undefined;
    if (raw.m !== marker(o.appId, 'meeting', FORMAT_VERSION)) return undefined;
    const valid = resolveValidators(o.valid);
    const introduction = parseIntroduction(raw, valid);
    const { role, time, proof } = raw;
    if (!introduction || typeof role !== 'string' || !valid.role(role)) return undefined;
    if (!isCount(time) || !isSignature(proof)) return undefined;
    if (raw.private !== undefined && raw.private !== true) return undefined;
    if (raw.private === true && !valid.privateRoles(role)) return undefined;
    const code: MeetingCode = {
      introduction,
      role,
      time,
      ...(raw.private === true ? { private: true as const } : {}),
      proof,
    };
    // One spelling only: duplicate members, other order, spaces or escapes are not the code.
    return new TextDecoder().decode(encode(o.appId, code)) === text ? code : undefined;
  } catch {
    return undefined;
  }
}

export type MeetingCheck =
  { readonly ok: true } | { readonly ok: false; readonly reason: 'expired' | 'ahead' | 'changed' };

/** Whether a scanned code is from now and signed by the device it names. */
export async function checkMeetingCode(
  o: ProtocolOptions,
  code: MeetingCode,
  now: number,
): Promise<MeetingCheck> {
  if (now - code.time > MEETING_VALID_MS) return { ok: false, reason: 'expired' };
  if (code.time - now > MEETING_AHEAD_MS) return { ok: false, reason: 'ahead' };
  const key = await importPublicKey(code.introduction.sig, 'sig');
  const text = meetingSigningText(
    o.appId,
    code.introduction,
    code.role,
    code.time,
    code.private === true,
  );
  return key && (await verifyText(key, text, code.proof))
    ? { ok: true }
    : { ok: false, reason: 'changed' };
}
