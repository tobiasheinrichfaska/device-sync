import { FORMAT_VERSION, base64url, fromBase64url, marker } from '../core/index.ts';
import { resolveValidators } from './ids.ts';
import type { DeviceEntry, Introduction, ProtocolOptions, Voucher } from './types.ts';
import {
  decodeUtf8,
  isCode,
  isCount,
  isPlain,
  isProof,
  parseIntroduction,
  parseJson,
} from './wire.ts';

/** An invitation lives 24 hours. */
export const INVITATION_MS = 24 * 60 * 60 * 1000;
const FRAGMENT = '#join=';
const MAX_PAYLOAD = 2000;
const MAX_TEXT = 4000;
const utf8 = new TextEncoder();

/** The invitation as the new device sees it (after `#join=` in a link, a pasted text or a scanned code). */
export interface Invitation {
  /** The inviting device. */
  readonly from: Introduction;
  readonly role: string;
  /** One-time code: 16 random bytes, base64url. Only the inviter keeps it besides the link. */
  readonly code: string;
  /** Valid until (ms since 1970); at this instant it is over. */
  readonly until: number;
  /** The name the inviter suggests for the new device. */
  readonly newName?: string;
  /** The inviter's relay id, so the answer can go there. */
  readonly relayId?: string;
  readonly private?: true;
}

/** What the inviting device keeps until the new device answers (never leaves it). */
export interface OpenInvitation {
  readonly role: string;
  readonly code: string;
  readonly until: number;
  readonly private?: true;
}

/** The answer of the new device. */
export interface Reply {
  /** The inviting device the answer is for. */
  readonly to: string;
  readonly introduction: Introduction;
  readonly proof: string;
}

export type InviteError =
  'not-allowed' | 'bad-inviter' | 'bad-random' | 'bad-role' | 'bad-name' | 'private-role';

export type Creation =
  | { readonly ok: true; readonly invitation: Invitation; readonly open: OpenInvitation }
  | { readonly ok: false; readonly reason: InviteError };

/**
 * A new invitation from `inviter` (its entry with its role) for a device of `role`. Only an inviter
 * the voucher's `mayInvite` allows may invite that role (without `mayInvite`: only one that can
 * vouch). `random` = 16 random bytes (the one-time code). A private device must have a role
 * `privateRoles` allows.
 */
export function createInvitation(
  o: ProtocolOptions & { readonly voucher: Voucher },
  inviter: DeviceEntry,
  role: string,
  random: Uint8Array,
  now: number,
  extra: { readonly newName?: string; readonly private?: boolean } = {},
): Creation {
  const valid = resolveValidators(o.valid);
  if (!parseIntroduction(inviter, valid)) return { ok: false, reason: 'bad-inviter' };
  const allowed = o.voucher.mayInvite
    ? o.voucher.mayInvite(inviter, role)
    : o.voucher.canVouch(inviter, [inviter]);
  if (!allowed) return { ok: false, reason: 'not-allowed' };
  if (!(random instanceof Uint8Array) || random.length !== 16 || !isCount(now)) {
    return { ok: false, reason: 'bad-random' };
  }
  if (!valid.role(role)) return { ok: false, reason: 'bad-role' };
  if (extra.newName !== undefined && !valid.name(extra.newName)) {
    return { ok: false, reason: 'bad-name' };
  }
  const isPrivate = extra.private === true;
  if (isPrivate && !valid.privateRoles(role)) return { ok: false, reason: 'private-role' };
  const code = base64url(random);
  const until = now + INVITATION_MS;
  const invitation: Invitation = {
    from: { device: inviter.device, name: inviter.name, sig: inviter.sig, dh: inviter.dh },
    role,
    code,
    until,
    ...(extra.newName !== undefined ? { newName: extra.newName } : {}),
    ...(inviter.relayId !== undefined && valid.relayId(inviter.relayId)
      ? { relayId: inviter.relayId }
      : {}),
    ...(isPrivate ? { private: true as const } : {}),
  };
  const open: OpenInvitation = {
    role,
    code,
    until,
    ...(isPrivate ? { private: true as const } : {}),
  };
  return { ok: true, invitation, open };
}

const MEMBERS = [
  'm',
  'device',
  'name',
  'sig',
  'dh',
  'role',
  'code',
  'until',
  'newName',
  'relayId',
  'private',
];

function invitationJson(appId: string, e: Invitation): string {
  return JSON.stringify({
    m: marker(appId, 'invite', FORMAT_VERSION),
    device: e.from.device,
    name: e.from.name,
    sig: e.from.sig,
    dh: e.from.dh,
    role: e.role,
    code: e.code,
    until: e.until,
    ...(e.newName !== undefined ? { newName: e.newName } : {}),
    ...(e.relayId !== undefined ? { relayId: e.relayId } : {}),
    ...(e.private === true ? { private: true } : {}),
  });
}

/** The link: the page without its fragment, then `#join=` and the invitation as base64url JSON. */
export function invitationLink(appId: string, page: string, e: Invitation): string {
  const base = page.split('#')[0] ?? page;
  return `${base}${FRAGMENT}${base64url(utf8.encode(invitationJson(appId, e)))}`;
}

/** An invitation from a link or pasted text: strictly read, else undefined. Never throws. */
export function parseInvitation(o: ProtocolOptions, text: string): Invitation | undefined {
  try {
    if (typeof text !== 'string' || text.length > MAX_TEXT) return undefined;
    const at = text.lastIndexOf(FRAGMENT);
    if (at < 0) return undefined;
    const payload = text.slice(at + FRAGMENT.length).trim();
    if (payload.length === 0 || payload.length > MAX_PAYLOAD) return undefined;
    if (!/^[A-Za-z0-9_-]+$/.test(payload)) return undefined;
    const json = decodeUtf8(fromBase64url(payload));
    if (json === undefined) return undefined;
    const raw = parseJson(json);
    if (!isPlain(raw) || !Object.keys(raw).every((k) => MEMBERS.includes(k))) return undefined;
    if (raw.m !== marker(o.appId, 'invite', FORMAT_VERSION)) return undefined;
    const valid = resolveValidators(o.valid);
    const from = parseIntroduction(raw, valid);
    const { role, code, until, newName, relayId } = raw;
    if (!from || typeof role !== 'string' || !valid.role(role)) return undefined;
    if (!isCode(code) || !isCount(until)) return undefined;
    if (newName !== undefined && !(typeof newName === 'string' && valid.name(newName))) {
      return undefined;
    }
    if (relayId !== undefined && !(typeof relayId === 'string' && valid.relayId(relayId))) {
      return undefined;
    }
    if (raw.private !== undefined && raw.private !== true) return undefined;
    if (raw.private === true && !valid.privateRoles(role)) return undefined;
    const e: Invitation = {
      from,
      role,
      code,
      until,
      ...(typeof newName === 'string' ? { newName } : {}),
      ...(typeof relayId === 'string' ? { relayId } : {}),
      ...(raw.private === true ? { private: true as const } : {}),
    };
    // One spelling only (no duplicate members, other order, escapes, a re-encoded payload).
    return invitationJson(o.appId, e) === json && base64url(utf8.encode(json)) === payload
      ? e
      : undefined;
  } catch {
    return undefined;
  }
}

/** What the inviter keeps, strictly read and still valid at `now` (it ends at `until`). */
export function parseOpenInvitation(
  o: ProtocolOptions,
  raw: unknown,
  now: number,
): OpenInvitation | undefined {
  if (!isPlain(raw)) return undefined;
  if (!Object.keys(raw).every((k) => ['role', 'code', 'until', 'private'].includes(k))) {
    return undefined;
  }
  const { role, code, until } = raw;
  const valid = resolveValidators(o.valid);
  if (typeof role !== 'string' || !valid.role(role) || !isCode(code)) return undefined;
  if (!isCount(until) || !(now < until)) return undefined;
  if (raw.private !== undefined && raw.private !== true) return undefined;
  if (raw.private === true && !valid.privateRoles(role)) return undefined;
  return { role, code, until, ...(raw.private === true ? { private: true as const } : {}) };
}

/** What the proof covers: marker, inviter, role and the new device's whole introduction. */
export function proofText(appId: string, inviter: string, role: string, neu: Introduction): string {
  const head = marker(appId, 'invite', FORMAT_VERSION);
  return `${head}|${inviter}|${role}|${neu.device}|${neu.name}|${neu.sig}|${neu.dh}`;
}

const hmacKey = (code: string, usage: KeyUsage) =>
  crypto.subtle.importKey(
    'raw',
    new Uint8Array(fromBase64url(code)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    [usage],
  );

/** The new device's proof that it holds the one-time code (HMAC-SHA-256 keyed by the code, base64url). */
export async function invitationProof(
  appId: string,
  invitation: Pick<Invitation, 'from' | 'role' | 'code'>,
  neu: Introduction,
): Promise<string> {
  const text = proofText(appId, invitation.from.device, invitation.role, neu);
  const mac = await crypto.subtle.sign(
    'HMAC',
    await hmacKey(invitation.code, 'sign'),
    utf8.encode(text),
  );
  return base64url(new Uint8Array(mac));
}

function replyJson(appId: string, r: Reply): string {
  return JSON.stringify({
    m: marker(appId, 'reply', FORMAT_VERSION),
    to: r.to,
    device: r.introduction.device,
    name: r.introduction.name,
    sig: r.introduction.sig,
    dh: r.introduction.dh,
    proof: r.proof,
  });
}

/** The answer as text (base64url JSON): the new device's introduction and its proof, for the inviter named. */
export function replyText(appId: string, r: Reply): string {
  return base64url(utf8.encode(replyJson(appId, r)));
}

/** An answer from a pasted text, strictly read, else undefined. Never throws. */
export function parseReply(o: ProtocolOptions, text: string): Reply | undefined {
  try {
    if (typeof text !== 'string') return undefined;
    const payload = text.trim();
    if (payload.length === 0 || payload.length > MAX_PAYLOAD) return undefined;
    if (!/^[A-Za-z0-9_-]+$/.test(payload)) return undefined;
    const json = decodeUtf8(fromBase64url(payload));
    if (json === undefined) return undefined;
    const raw = parseJson(json);
    const members = ['m', 'to', 'device', 'name', 'sig', 'dh', 'proof'];
    if (!isPlain(raw) || !Object.keys(raw).every((k) => members.includes(k))) return undefined;
    if (raw.m !== marker(o.appId, 'reply', FORMAT_VERSION)) return undefined;
    const valid = resolveValidators(o.valid);
    const introduction = parseIntroduction(raw, valid);
    const { to, proof } = raw;
    if (!introduction || typeof to !== 'string' || !valid.deviceId(to) || !isProof(proof)) {
      return undefined;
    }
    const reply: Reply = { to, introduction, proof };
    return replyJson(o.appId, reply) === json && base64url(utf8.encode(json)) === payload
      ? reply
      : undefined;
  } catch {
    return undefined;
  }
}

export type ReplyCheck =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly reason:
        | 'no-invitation'
        | 'expired'
        | 'wrong-inviter'
        | 'own-device'
        | 'bad-introduction'
        | 'not-allowed'
        | 'bad-proof';
    };

/**
 * The inviting device checks an answer against the invitation it keeps. Given `inviter` and a
 * voucher, `mayInvite` is asked again (the inviter may have lost the right meanwhile).
 */
export async function checkReply(
  o: ProtocolOptions & { readonly voucher?: Voucher },
  open: OpenInvitation | undefined,
  ownDevice: string,
  reply: Reply,
  now: number,
  inviter?: DeviceEntry,
): Promise<ReplyCheck> {
  if (!open) return { ok: false, reason: 'no-invitation' };
  if (!(now < open.until)) return { ok: false, reason: 'expired' };
  if (reply.to !== ownDevice) return { ok: false, reason: 'wrong-inviter' };
  const valid = resolveValidators(o.valid);
  if (!parseIntroduction(reply.introduction, valid))
    return { ok: false, reason: 'bad-introduction' };
  if (reply.introduction.device === ownDevice) return { ok: false, reason: 'own-device' };
  if (inviter && o.voucher) {
    const allowed = o.voucher.mayInvite
      ? o.voucher.mayInvite(inviter, open.role)
      : o.voucher.canVouch(inviter, [inviter]);
    if (!allowed) return { ok: false, reason: 'not-allowed' };
  }
  if (!isProof(reply.proof) || !isCode(open.code)) return { ok: false, reason: 'bad-proof' };
  const text = proofText(o.appId, ownDevice, open.role, reply.introduction);
  let good = false;
  try {
    good = await crypto.subtle.verify(
      'HMAC',
      await hmacKey(open.code, 'verify'),
      new Uint8Array(fromBase64url(reply.proof)),
      utf8.encode(text),
    );
  } catch {
    good = false;
  }
  return good ? { ok: true } : { ok: false, reason: 'bad-proof' };
}
