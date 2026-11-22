// Revision 2 of the relay protocol (docs/relay-protocol.md, "Revision 2"): the formats of certificate
// `c1`, invitation `e2` and founder ticket `g1`, the strict readers of every answer of that revision,
// and the two role rules. Every reader takes the TEXT of a body and returns a fresh value or
// `undefined`; none throws; unknown members, wrong types, a spelling that is not canonical and
// anything over its bound make the whole answer unreadable. The relay checks the MACs and
// signatures; the device only reads what it needs and checks that the answer is for this app,
// this device and this key.
import { readBytes } from '../core/secure.ts';
import { isPlain } from '../core/secure.ts';
import { isCalendarDay, isDevice, isInt, members, object } from './strict.ts';
import { isRawPublicKey } from './possession.ts';

const APP = '[a-z][a-z0-9]{1,15}';
const GROUP_PART = '(?!standard\\.)[a-z0-9-]{1,20}';
const DEVICE_PART = 'geraet-[0-9a-f]{32}';
const ROLE_PART = '(?:buero|ohne|lb:[A-Za-z0-9_-]{1,40})';
const BIS = '[1-9][0-9]{0,11}';

/** A group of devices (a school, a club): lower case, digits, hyphen, 1 to 20; never `standard`. */
export const RELAY_GROUP = /^(?!standard$)[a-z0-9-]{1,20}$/;
/** The role of a device at the relay: `buero` (office), `ohne` (none) or `lb:<id>` (one member's devices). */
export const RELAY_ROLE = /^(buero|ohne|lb:[A-Za-z0-9_-]{1,40})$/;
const CERTIFICATE = new RegExp(
  `^c1\\.(${APP})\\.(${GROUP_PART})\\.(${DEVICE_PART})\\.(${ROLE_PART})\\.([A-Za-z0-9_-]{87})\\.(${BIS})\\.([A-Za-z0-9_-]{43})$`,
);
const INVITATION2 = new RegExp(
  `^e2\\.(${APP})\\.(${GROUP_PART})\\.(${DEVICE_PART})\\.(${ROLE_PART})\\.(${BIS})\\.([A-Za-z0-9_-]{22})\\.([A-Za-z0-9_-]{43})$`,
);
const FOUNDER = new RegExp(
  `^g1\\.(${APP})\\.(${GROUP_PART})\\.(${BIS})\\.([A-Za-z0-9_-]{22})\\.([A-Za-z0-9_-]{86})$`,
);
const SHORT_WORD = /^[a-z0-9-]{1,30}$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_SMALL = 20_000;

// ── the tokens ───────────────────────────────────────────────────────────────────────────────────

export interface Certificate {
  readonly app: string;
  readonly group: string;
  readonly device: string;
  readonly role: string;
  /** The device's public key, raw, 87 characters. */
  readonly key: string;
  /** End, seconds since 1970. */
  readonly endS: number;
}

/** A certificate `c1.<app>.<group>.<device>.<role>.<key>.<bis>.<mac>`: its parts, or undefined. The MAC is the relay's to check. */
export function readCertificate(text: unknown): Certificate | undefined {
  if (typeof text !== 'string' || text.length > 400) return undefined;
  const m = CERTIFICATE.exec(text);
  if (!m || !isRawPublicKey(m[5]) || !readBytes(m[7], 32, 32)) return undefined;
  const endS = Number(m[6]);
  if (!Number.isSafeInteger(endS)) return undefined;
  return {
    app: m[1] as string,
    group: m[2] as string,
    device: m[3] as string,
    role: m[4] as string,
    key: m[5] as string,
    endS,
  };
}

export interface InvitationR2 {
  readonly app: string;
  readonly group: string;
  /** The device that invited. */
  readonly inviter: string;
  /** The role of the device that takes the invitation (the inviter sets it). */
  readonly role: string;
  readonly endS: number;
}

/** An invitation `e2.<app>.<group>.<inviter>.<role>.<bis>.<random>.<mac>`: its parts, or undefined. */
export function readInvitationR2(text: unknown): InvitationR2 | undefined {
  if (typeof text !== 'string' || text.length > 300) return undefined;
  const m = INVITATION2.exec(text);
  if (!m || !readBytes(m[6], 16, 16) || !readBytes(m[7], 32, 32)) return undefined;
  const endS = Number(m[5]);
  if (!Number.isSafeInteger(endS)) return undefined;
  return {
    app: m[1] as string,
    group: m[2] as string,
    inviter: m[3] as string,
    role: m[4] as string,
    endS,
  };
}

/** A founder ticket `g1.<app>.<group>.<bis>.<random>.<signature>`: its parts, or undefined. */
export function readFounderTicket(
  text: unknown,
): { readonly app: string; readonly group: string; readonly endS: number } | undefined {
  if (typeof text !== 'string' || text.length > 300) return undefined;
  const m = FOUNDER.exec(text);
  if (!m || !readBytes(m[4], 16, 16) || !readBytes(m[5], 64, 64)) return undefined;
  const endS = Number(m[3]);
  return Number.isSafeInteger(endS)
    ? { app: m[1] as string, group: m[2] as string, endS }
    : undefined;
}

// ── roles ────────────────────────────────────────────────────────────────────────────────────────

/** What a device of relay role `role` may give a device it invites: the office any role, an `lb:<id>` device only its own, others nothing. */
export function canInvite(role: string, forRole: string): boolean {
  if (!RELAY_ROLE.test(role) || !RELAY_ROLE.test(forRole)) return false;
  if (role === 'buero') return true;
  return role.startsWith('lb:') && forRole === role;
}

/**
 * What a device may block: every device itself, the office every device of its group, an `lb:<id>`
 * device the devices of its own role. `targetRole` undefined = the relay does not know the target
 * (after its restart); only the office and a device blocking itself may then block.
 */
export function canBlock(role: string, targetRole: string | undefined, self: boolean): boolean {
  if (self || role === 'buero') return true;
  return role.startsWith('lb:') && targetRole === role;
}

/** The relay role for an app role: the same text where the relay can hold it (not `ohne`), else `ohne`: never more rights than the app meant. */
export function relayRoleOf(appRole: unknown): string {
  return typeof appRole === 'string' && RELAY_ROLE.test(appRole) && appRole !== 'ohne'
    ? appRole
    : 'ohne';
}

// ── what a relay says about itself ───────────────────────────────────────────────────────────────

/** The techniques a relay serves for a group and prefers, and the ways a device can enrol. */
export interface Procedures {
  /** `zugang` (the old access, group `1` only) and `zertifikat`. */
  readonly offered: readonly string[];
  readonly preferred: string;
  /** `nachweis`, `einladung` (old); `einladung2`, `gruender`, `passwort` (new). */
  readonly enrolWays: readonly string[];
}

export interface RelayInfo {
  /** The revision of the protocol the relay speaks (`v`). */
  readonly revision: number;
  readonly abilities: readonly string[];
  readonly procedures?: Procedures;
}

function words(x: unknown): string[] | undefined {
  if (!Array.isArray(x) || x.length > 10) return undefined;
  return x.every((w) => typeof w === 'string' && SHORT_WORD.test(w))
    ? [...(x as string[])]
    : undefined;
}

/** The `verfahren` object. */
export function readProcedures(raw: unknown): Procedures | undefined {
  if (!isPlain(raw) || !members(raw, ['angeboten', 'bevorzugt', 'einschreiben'])) return undefined;
  const offered = words(raw['angeboten']);
  const enrolWays = words(raw['einschreiben']);
  const preferred = raw['bevorzugt'];
  if (!offered || !enrolWays || typeof preferred !== 'string' || !SHORT_WORD.test(preferred)) {
    return undefined;
  }
  return { offered, preferred, enrolWays };
}

/**
 * The members `v`, `faehigkeiten`, `verfahren` of an answer (all optional, but the other two only
 * with `v`). `null` = something is wrong; `undefined` = the relay said nothing about itself.
 */
export function readInfo(o: Record<string, unknown>): RelayInfo | null | undefined {
  const { v, faehigkeiten, verfahren } = o;
  if (v === undefined)
    return faehigkeiten === undefined && verfahren === undefined ? undefined : null;
  if (!isInt(v, 1, 99)) return null;
  let abilities: string[] = [];
  if (faehigkeiten !== undefined) {
    if (!Array.isArray(faehigkeiten) || faehigkeiten.length > 20) return null;
    if (!faehigkeiten.every((a) => typeof a === 'string' && SHORT_WORD.test(a))) return null;
    abilities = [...(faehigkeiten as string[])];
  }
  if (verfahren === undefined) return { revision: v, abilities };
  const procedures = readProcedures(verfahren);
  return procedures ? { revision: v, abilities, procedures } : null;
}

const INFO_MEMBERS = ['v', 'faehigkeiten', 'verfahren'] as const;

// ── enrolment, renewal, ping ─────────────────────────────────────────────────────────────────────

export interface EnrolAnswerR2 {
  readonly device: string;
  /** The certificate (what the requests carry as Bearer). */
  readonly access: string;
  readonly until: string;
  readonly group: string;
  readonly role: string;
  readonly info?: RelayInfo;
}

const dayOfS = (s: number): string => new Date(s * 1000).toISOString().slice(0, 10);

/**
 * Answer of `einschreiben` (201) to a request that carried our key: the certificate must be for this
 * app, name the device the relay named, carry exactly our key, and `mandant`/`rolle` must be the
 * ones in it; its end day must be the `bis`. A ticket beside the certificate (group `1`) is checked
 * for shape and dropped: the certificate rules.
 */
export function readEnrolAnswerR2(
  text: unknown,
  appId: string,
  key: string,
): EnrolAnswerR2 | undefined {
  const o = object(text, MAX_SMALL);
  if (
    !o ||
    !members(o, ['geraet', 'zertifikat', 'mandant', 'rolle', 'bis'], ['zugang', ...INFO_MEMBERS])
  ) {
    return undefined;
  }
  const { geraet, zertifikat, mandant, rolle, bis, zugang } = o;
  const c = readCertificate(zertifikat);
  if (!isDevice(geraet) || !c || c.app !== appId || c.device !== geraet || c.key !== key) {
    return undefined;
  }
  if (mandant !== c.group || rolle !== c.role || !isCalendarDay(bis) || bis !== dayOfS(c.endS)) {
    return undefined;
  }
  if (zugang !== undefined && !isTicketOf(zugang, appId, geraet)) return undefined;
  const info = readInfo(o);
  if (info === null) return undefined;
  return {
    device: geraet,
    access: zertifikat as string,
    until: bis,
    group: c.group,
    role: c.role,
    ...(info ? { info } : {}),
  };
}

const TICKET =
  /^z1\.([a-z][a-z0-9]{1,15})\.(geraet-[0-9a-f]{32})\.([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{43})$/;
function isTicketOf(text: unknown, appId: string, device: string): boolean {
  if (typeof text !== 'string' || text.length > 200) return false;
  const m = TICKET.exec(text);
  return !!m && m[1] === appId && m[2] === device && !!readBytes(m[4], 32, 32);
}

export interface RenewAnswerR2 {
  readonly access: string;
  readonly until: string;
  readonly info?: RelayInfo;
}

/**
 * Answer of `erneuern` (200) for a certificate: `{ zertifikat, bis }` (and the relay's own
 * members): the same app, device, key, group and role, and an end not earlier than the old one.
 */
export function readRenewAnswerR2(
  text: unknown,
  appId: string,
  current: Certificate,
): RenewAnswerR2 | undefined {
  const o = object(text, MAX_SMALL);
  if (!o || !members(o, ['zertifikat', 'bis'], INFO_MEMBERS)) return undefined;
  const c = readCertificate(o['zertifikat']);
  if (!c || c.app !== appId || c.device !== current.device || c.key !== current.key)
    return undefined;
  if (c.group !== current.group || c.role !== current.role || c.endS < current.endS)
    return undefined;
  if (!isCalendarDay(o['bis']) || o['bis'] !== dayOfS(c.endS)) return undefined;
  const info = readInfo(o);
  if (info === null) return undefined;
  return { access: o['zertifikat'] as string, until: o['bis'], ...(info ? { info } : {}) };
}

/**
 * Answer of `erneuern` (200) to an OLD ticket that sent our key (the step to a certificate):
 * `{ zugang, bis, zertifikat, mandant, rolle }`. The certificate is for this app and device and
 * carries exactly our key; the new ticket is checked for shape and dropped.
 */
export function readUpgradeAnswer(
  text: unknown,
  appId: string,
  device: string,
  key: string,
): EnrolAnswerR2 | undefined {
  const o = object(text, MAX_SMALL);
  if (!o || !members(o, ['zugang', 'bis', 'zertifikat', 'mandant', 'rolle'], INFO_MEMBERS)) {
    return undefined;
  }
  const c = readCertificate(o['zertifikat']);
  if (!c || c.app !== appId || c.device !== device || c.key !== key) return undefined;
  if (o['mandant'] !== c.group || o['rolle'] !== c.role) return undefined;
  if (!isTicketOf(o['zugang'], appId, device) || !isCalendarDay(o['bis'])) return undefined;
  const info = readInfo(o);
  if (info === null) return undefined;
  return {
    device,
    access: o['zertifikat'] as string,
    until: dayOfS(c.endS),
    group: c.group,
    role: c.role,
    ...(info ? { info } : {}),
  };
}

export interface PingAnswer {
  readonly device: string;
  readonly app: string;
  readonly until: string;
  readonly group?: string;
  readonly role?: string;
  readonly info?: RelayInfo;
}

/** Answer of `ping` (200): `{ geraet, app, bis }`, with `mandant`/`rolle` for a certificate and `v`, `faehigkeiten`, `verfahren` for a client that announced its revision. */
export function readPingAnswerR2(text: unknown): PingAnswer | undefined {
  const o = object(text, MAX_SMALL);
  if (!o || !members(o, ['geraet', 'app', 'bis'], ['mandant', 'rolle', ...INFO_MEMBERS])) {
    return undefined;
  }
  const { geraet, app, bis, mandant, rolle } = o;
  if (!isDevice(geraet) || typeof app !== 'string' || !/^[a-z][a-z0-9]{1,15}$/.test(app)) {
    return undefined;
  }
  if (!isCalendarDay(bis)) return undefined;
  if ((mandant === undefined) !== (rolle === undefined)) return undefined;
  if (mandant !== undefined && !(typeof mandant === 'string' && RELAY_GROUP.test(mandant))) {
    return undefined;
  }
  if (rolle !== undefined && !(typeof rolle === 'string' && RELAY_ROLE.test(rolle))) {
    return undefined;
  }
  const info = readInfo(o);
  if (info === null) return undefined;
  return {
    device: geraet,
    app,
    until: bis,
    ...(typeof mandant === 'string' ? { group: mandant } : {}),
    ...(typeof rolle === 'string' ? { role: rolle } : {}),
    ...(info ? { info } : {}),
  };
}

// ── the device list and blocking ─────────────────────────────────────────────────────────────────

/** Who put a device on the relay's list: the old ways name themselves, a device names its id. */
export type IntroducedBy =
  | { readonly by: 'old-access' | 'proof' | 'developer' }
  | { readonly by: 'device'; readonly device: string };

export interface ListedDevice {
  readonly device: string;
  readonly role: string;
  readonly introducedBy: IntroducedBy;
  /** Ms since 1970. */
  readonly sinceMs: number;
  readonly lastMs: number;
  /** `new` = it signs with a certificate, `old` = it still uses the old access. */
  readonly procedure: 'new' | 'old';
  /** The protocol revision it announced last, when it did. */
  readonly protocol?: number;
}

export interface DevicesAnswer {
  readonly devices: readonly ListedDevice[];
  /** The most devices of one group. */
  readonly max: number;
}

/**
 * Answer of `geraete` (200): `{ geraete: [{ geraet, rolle, von, seit, zuletzt, verfahren, p? }], hoechstens }`.
 * Every entry strictly, no device twice, at most twice `hoechstens` entries (the relay may know old
 * accesses beyond the limit), times as the relay writes them (`...T...:..:...sssZ`).
 */
export function readDevicesAnswer(text: unknown): DevicesAnswer | undefined {
  const o = object(text, 300_000);
  if (!o || !members(o, ['geraete', 'hoechstens'])) return undefined;
  const { geraete, hoechstens } = o;
  if (!isInt(hoechstens, 1, 1000) || !Array.isArray(geraete) || geraete.length > hoechstens * 2) {
    return undefined;
  }
  const seen = new Set<string>();
  const devices: ListedDevice[] = [];
  for (const item of geraete) {
    if (
      !isPlain(item) ||
      !members(item, ['geraet', 'rolle', 'von', 'seit', 'zuletzt', 'verfahren'], ['p'])
    ) {
      return undefined;
    }
    const { geraet, rolle, von, seit, zuletzt, verfahren, p } = item;
    if (!isDevice(geraet) || seen.has(geraet)) return undefined;
    if (typeof rolle !== 'string' || !RELAY_ROLE.test(rolle)) return undefined;
    let introducedBy: IntroducedBy;
    if (von === 'alt') introducedBy = { by: 'old-access' };
    else if (von === 'nachweis') introducedBy = { by: 'proof' };
    else if (von === 'entwickler') introducedBy = { by: 'developer' };
    else if (isDevice(von)) introducedBy = { by: 'device', device: von };
    else return undefined;
    if (typeof seit !== 'string' || !ISO_TIME.test(seit)) return undefined;
    if (typeof zuletzt !== 'string' || !ISO_TIME.test(zuletzt)) return undefined;
    const sinceMs = Date.parse(seit);
    const lastMs = Date.parse(zuletzt);
    if (!Number.isFinite(sinceMs) || !Number.isFinite(lastMs)) return undefined;
    if (new Date(sinceMs).toISOString() !== seit || new Date(lastMs).toISOString() !== zuletzt) {
      return undefined;
    }
    if (verfahren !== 'neu' && verfahren !== 'alt') return undefined;
    if (p !== undefined && !isInt(p, 0, 999)) return undefined;
    seen.add(geraet);
    devices.push({
      device: geraet,
      role: rolle,
      introducedBy,
      sinceMs,
      lastMs,
      procedure: verfahren === 'neu' ? 'new' : 'old',
      ...(p === undefined ? {} : { protocol: p }),
    });
  }
  return { devices, max: hoechstens };
}

/** Answer of `sperren` (200): `{ geraet, gesperrt: true }` for the device that was asked about. */
export function readBlockAnswer(text: unknown, device: string): boolean {
  const o = object(text, MAX_SMALL);
  return (
    !!o && members(o, ['geraet', 'gesperrt']) && o['geraet'] === device && o['gesperrt'] === true
  );
}
