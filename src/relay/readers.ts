// Strict readers of every answer of the relay. Each takes the TEXT of a response body and returns a
// fresh value or `undefined`; none throws, whatever the relay sends. A member that is not in the
// protocol, a member of the wrong type, a text that is not canonical base64url where the protocol
// says so, a duplicate key or a size over the documented limit makes the whole answer unreadable.
// What a hostile or buggy relay can make a client allocate is bounded by RELAY_LIMITS.
import { hasDuplicateKeys } from '../core/json.ts';
import { decodeUtf8, isPlain, parseJson, readBytes } from '../core/secure.ts';
import { DROP_REFUSAL_TOKENS } from './kinds.ts';
import { RELAY_LIMITS } from './limits.ts';

export const RELAY_DEVICE_ID = /^geraet-[0-9a-f]{32}$/;
const APP_ID = /^[a-z][a-z0-9]{1,15}$/;
const ACCESS =
  /^z1\.([a-z][a-z0-9]{1,15})\.(geraet-[0-9a-f]{32})\.([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{43})$/;
const INVITATION =
  /^e1\.([a-z][a-z0-9]{1,15})\.([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;
const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;
const WORD = /^[a-z][a-z-]{1,39}$/;
const SHORT_WORD = /^[a-z0-9-]{1,30}$/;
const MAX_MESSAGE_TEXT = 200;

/** Most characters of a collect answer: every possible message in base64url plus the framing. */
export const MAX_COLLECT_TEXT =
  Math.ceil((RELAY_LIMITS.collectBytes * 4) / 3) + RELAY_LIMITS.mailboxMessages * 200 + 2_000;
/** Most characters of every other answer. */
export const MAX_SMALL_TEXT = 20_000;

/** A JSON object from text, once: bounded, no duplicate key, plain. */
function object(text: unknown, maxChars: number): Record<string, unknown> | undefined {
  if (typeof text !== 'string' || text.length > maxChars) return undefined;
  const value = parseJson(text);
  if (!isPlain(value)) return undefined;
  try {
    if (hasDuplicateKeys(text)) return undefined;
  } catch {
    return undefined;
  }
  return value;
}

/** Every key is allowed, every required key is there. */
function members(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value);
  return (
    keys.every((key) => required.includes(key) || optional.includes(key)) &&
    required.every((key) => keys.includes(key))
  );
}

const isDevice = (v: unknown): v is string => typeof v === 'string' && RELAY_DEVICE_ID.test(v);
const isInt = (v: unknown, min: number, max: number): v is number =>
  typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;

/** A calendar day `YYYY-MM-DD` that exists. */
export function isCalendarDay(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  const m = DAY.exec(v);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const date = new Date(Date.UTC(y, mo - 1, d));
  return date.getUTCFullYear() === y && date.getUTCMonth() === mo - 1 && date.getUTCDate() === d;
}

/** An access `z1.<app>.<device>.<end>.<mac>`: its parts, or undefined (the MAC must be canonical). */
export function readAccess(
  text: unknown,
): { readonly app: string; readonly device: string; readonly endS: number } | undefined {
  if (typeof text !== 'string' || text.length > 200) return undefined;
  const m = ACCESS.exec(text);
  if (!m) return undefined;
  const endS = Number(m[3]);
  if (!Number.isSafeInteger(endS) || !readBytes(m[4], 32, 32)) return undefined;
  return { app: m[1] as string, device: m[2] as string, endS };
}

/** An invitation `e1.<app>.<end>.<random>.<mac>`: its app, or undefined. */
export function readInvitation(text: unknown): { readonly app: string } | undefined {
  if (typeof text !== 'string' || text.length > 200) return undefined;
  const m = INVITATION.exec(text);
  if (!m || !readBytes(m[3], 16, 16) || !readBytes(m[4], 32, 32)) return undefined;
  if (!Number.isSafeInteger(Number(m[2]))) return undefined;
  return { app: m[1] as string };
}

// ── enrol, renew, ping, invite ────────────────────────────────────────────────────────────────────

export interface EnrolAnswer {
  readonly device: string;
  readonly access: string;
  readonly until: string;
}

/** Answer of `einschreiben` (201): `{ geraet, zugang, bis }`, the access naming this app and device. */
export function readEnrolAnswer(text: unknown, appId: string): EnrolAnswer | undefined {
  const o = object(text, MAX_SMALL_TEXT);
  if (!o || !members(o, ['geraet', 'zugang', 'bis'])) return undefined;
  const { geraet, zugang, bis } = o;
  if (!isDevice(geraet) || !isCalendarDay(bis) || typeof zugang !== 'string') return undefined;
  const a = readAccess(zugang);
  if (!a || a.app !== appId || a.device !== geraet) return undefined;
  return { device: geraet, access: zugang, until: bis };
}

/** Answer of `erneuern` (200): `{ zugang, bis }`, the access for the same app and device. */
export function readRenewAnswer(
  text: unknown,
  appId: string,
  device: string,
): { readonly access: string; readonly until: string } | undefined {
  const o = object(text, MAX_SMALL_TEXT);
  if (!o || !members(o, ['zugang', 'bis'])) return undefined;
  const { zugang, bis } = o;
  if (!isCalendarDay(bis) || typeof zugang !== 'string') return undefined;
  const a = readAccess(zugang);
  if (!a || a.app !== appId || a.device !== device) return undefined;
  return { access: zugang, until: bis };
}

/** Answer of `ping` (200): `{ geraet, app, bis }`. */
export function readPingAnswer(
  text: unknown,
): { readonly device: string; readonly app: string; readonly until: string } | undefined {
  const o = object(text, MAX_SMALL_TEXT);
  if (!o || !members(o, ['geraet', 'app', 'bis'])) return undefined;
  const { geraet, app, bis } = o;
  if (!isDevice(geraet) || typeof app !== 'string' || !APP_ID.test(app) || !isCalendarDay(bis)) {
    return undefined;
  }
  return { device: geraet, app, until: bis };
}

/** Answer of `einladen` (201): `{ einladung, gueltigS }`, an invitation for this app. */
export function readInviteAnswer(
  text: unknown,
  appId: string,
): { readonly invitation: string; readonly validForS: number } | undefined {
  const o = object(text, MAX_SMALL_TEXT);
  if (!o || !members(o, ['einladung', 'gueltigS'])) return undefined;
  const { einladung, gueltigS } = o;
  const inv = readInvitation(einladung);
  if (!inv || inv.app !== appId || !isInt(gueltigS, 1, 3_600)) return undefined;
  return { invitation: einladung as string, validForS: gueltigS };
}

// ── drop ──────────────────────────────────────────────────────────────────────────────────────────

export type DropEntry =
  | { readonly device: string; readonly ok: true; readonly present: boolean }
  | {
      readonly device: string;
      readonly ok: false;
      /** The wire word of the refusal; the English name is looked up with `kindOfToken`. */
      readonly token: string;
    };

/**
 * Answer of `ablegen` (200): one result per recipient, in the order asked, each naming that
 * recipient. A refusal word this version does not know is kept as its token (the caller treats it as
 * "not stored"). The German sentence `fehler` is checked for size and then dropped.
 */
export function readDropAnswer(text: unknown, asked: readonly string[]): DropEntry[] | undefined {
  const o = object(text, MAX_SMALL_TEXT + asked.length * 400);
  if (!o || !members(o, ['ergebnisse'])) return undefined;
  const list = o['ergebnisse'];
  if (!Array.isArray(list) || list.length !== asked.length) return undefined;
  const out: DropEntry[] = [];
  for (const [i, item] of list.entries()) {
    if (!isPlain(item) || item['geraet'] !== asked[i]) return undefined;
    const device = asked[i] as string;
    if (item['ok'] === true) {
      if (!members(item, ['geraet', 'ok', 'anwesend']) || typeof item['anwesend'] !== 'boolean') {
        return undefined;
      }
      out.push({ device, ok: true, present: item['anwesend'] });
    } else if (item['ok'] === false) {
      if (!members(item, ['geraet', 'ok', 'art', 'fehler'])) return undefined;
      const { art, fehler } = item;
      if (typeof art !== 'string' || !WORD.test(art)) return undefined;
      if (typeof fehler !== 'string' || fehler.length > MAX_MESSAGE_TEXT) return undefined;
      out.push({ device, ok: false, token: art });
    } else return undefined;
  }
  return out;
}

/** Whether a drop refusal word is one of the four this version names. */
export const isKnownDropRefusal = (token: string): boolean => DROP_REFUSAL_TOKENS.includes(token);

// ── collect ───────────────────────────────────────────────────────────────────────────────────────

export interface CollectedMessage {
  readonly from: string;
  readonly content: Uint8Array;
  readonly ageMs: number;
}

export interface CollectAnswer {
  /** In the order the relay gives them (the order of dropping). */
  readonly messages: readonly CollectedMessage[];
  /** Only ids that were asked about, each once. */
  readonly present: readonly string[];
  readonly more: boolean;
}

/**
 * Answer of `abholen` (200): `{ nachrichten, anwesend, mehr }`. At most `mailboxMessages` messages,
 * every content canonical base64url of 1 to `maxContentBytes` bytes and all contents together at
 * most `collectBytes`; `anwesend` holds only ids that were asked, each once.
 */
export function readCollectAnswer(
  text: unknown,
  asked: readonly string[],
): CollectAnswer | undefined {
  const o = object(text, MAX_COLLECT_TEXT);
  if (!o || !members(o, ['nachrichten', 'anwesend', 'mehr'])) return undefined;
  const { nachrichten, anwesend, mehr } = o;
  if (!Array.isArray(nachrichten) || !Array.isArray(anwesend) || typeof mehr !== 'boolean') {
    return undefined;
  }
  if (nachrichten.length > RELAY_LIMITS.mailboxMessages) return undefined;
  if (anwesend.length > Math.min(asked.length, RELAY_LIMITS.maxPresenceAsk)) return undefined;
  const messages: CollectedMessage[] = [];
  let total = 0;
  for (const item of nachrichten) {
    if (!isPlain(item) || !members(item, ['von', 'inhalt', 'alterMs'])) return undefined;
    const { von, inhalt, alterMs } = item;
    if (!isDevice(von) || !isInt(alterMs, 0, RELAY_LIMITS.waitMs)) return undefined;
    const content = readBytes(inhalt, 1, RELAY_LIMITS.maxContentBytes);
    if (!content) return undefined;
    total += content.length;
    if (total > RELAY_LIMITS.collectBytes) return undefined;
    messages.push({ from: von, content: Uint8Array.from(content), ageMs: alterMs });
  }
  const askedSet = new Set(asked);
  const seen = new Set<string>();
  const present: string[] = [];
  for (const id of anwesend) {
    if (!isDevice(id) || !askedSet.has(id) || seen.has(id)) return undefined;
    seen.add(id);
    present.push(id);
  }
  return { messages, present, more: mehr };
}

// ── ring ──────────────────────────────────────────────────────────────────────────────────────────

/** Answer of `klingeln` (200): `{ dienst, ms }`, the push service's status and the time it took. */
export function readRingAnswer(
  text: unknown,
): { readonly service: number; readonly ms: number } | undefined {
  const o = object(text, MAX_SMALL_TEXT);
  if (!o || !members(o, ['dienst', 'ms'])) return undefined;
  const { dienst, ms } = o;
  if (!isInt(dienst, 100, 599) || !isInt(ms, 0, 3_600_000)) return undefined;
  return { service: dienst, ms };
}

// ── error body, health ────────────────────────────────────────────────────────────────────────────

/** A refusal `{ fehler, art }` of the relay: the wire word `art` (the sentence is not kept). */
export function readErrorBody(text: unknown): { readonly token: string } | undefined {
  const o = object(text, MAX_SMALL_TEXT);
  if (!o || !members(o, ['fehler', 'art'])) return undefined;
  const { fehler, art } = o;
  if (typeof fehler !== 'string' || fehler.length > MAX_MESSAGE_TEXT) return undefined;
  if (typeof art !== 'string' || !WORD.test(art)) return undefined;
  return { token: art };
}

export interface HealthAnswer {
  readonly commit: string;
  /** Revision members, present when the relay is of the later admission revision. */
  readonly revision?: number;
  readonly abilities?: readonly string[];
  readonly app?: string;
  readonly adminOpen?: boolean;
}

/**
 * Answer of `GET /gesund` (200). `ok` (true) and `stand` are required. The members of the later
 * admission revision (`v`, `faehigkeiten`, `verfahren`; with a known origin also `app`,
 * `altAbgeschaltet`, `aufnahmeOffen`) are read when present; anything else is refused.
 */
export function readHealthAnswer(text: unknown): HealthAnswer | undefined {
  const o = object(text, MAX_SMALL_TEXT);
  const optional = ['v', 'faehigkeiten', 'verfahren', 'app', 'altAbgeschaltet', 'aufnahmeOffen'];
  if (!o || !members(o, ['ok', 'stand'], optional) || o['ok'] !== true) return undefined;
  const { stand, v, faehigkeiten, verfahren, app, altAbgeschaltet, aufnahmeOffen } = o;
  if (typeof stand !== 'string' || stand.length < 1 || stand.length > 64) return undefined;
  if (v !== undefined && !isInt(v, 1, 99)) return undefined;
  let abilities: string[] | undefined;
  if (faehigkeiten !== undefined) {
    if (!Array.isArray(faehigkeiten) || faehigkeiten.length > 20) return undefined;
    if (!faehigkeiten.every((a) => typeof a === 'string' && SHORT_WORD.test(a))) return undefined;
    abilities = [...(faehigkeiten as string[])];
  }
  if (verfahren !== undefined) {
    if (!isPlain(verfahren) || !members(verfahren, ['angeboten', 'bevorzugt', 'einschreiben'])) {
      return undefined;
    }
    const { angeboten, bevorzugt, einschreiben } = verfahren;
    const words = (x: unknown): boolean =>
      Array.isArray(x) &&
      x.length <= 10 &&
      x.every((w) => typeof w === 'string' && SHORT_WORD.test(w));
    if (!words(angeboten) || !words(einschreiben)) return undefined;
    if (typeof bevorzugt !== 'string' || !SHORT_WORD.test(bevorzugt)) return undefined;
  }
  if (app !== undefined && (typeof app !== 'string' || !APP_ID.test(app))) return undefined;
  if (altAbgeschaltet !== undefined && typeof altAbgeschaltet !== 'boolean') return undefined;
  if (aufnahmeOffen !== undefined && typeof aufnahmeOffen !== 'boolean') return undefined;
  return {
    commit: stand,
    ...(v === undefined ? {} : { revision: v }),
    ...(abilities === undefined ? {} : { abilities }),
    ...(app === undefined ? {} : { app }),
    ...(aufnahmeOffen === undefined ? {} : { adminOpen: aufnahmeOffen }),
  };
}

// ── stored credentials ────────────────────────────────────────────────────────────────────────────

export interface StoredCredentials {
  readonly device: string;
  readonly access: string;
  readonly until: string;
}

/** The text the client keeps in its credential store: `{"v":1,"device":…,"access":…,"until":…}`. */
export function writeStoredCredentials(c: StoredCredentials): string {
  return JSON.stringify({ v: 1, device: c.device, access: c.access, until: c.until });
}

/** Strict reader of the stored text; the access must name this app and the stored device. */
export function readStoredCredentials(text: unknown, appId: string): StoredCredentials | undefined {
  const o = object(text, 2_000);
  if (!o || !members(o, ['v', 'device', 'access', 'until']) || o['v'] !== 1) return undefined;
  const { device, access, until } = o;
  if (!isDevice(device) || !isCalendarDay(until) || typeof access !== 'string') return undefined;
  const a = readAccess(access);
  if (!a || a.app !== appId || a.device !== device) return undefined;
  return { device, access, until };
}

/** UTF-8 text of response bytes (strict), or undefined. */
export const textOfBytes = (bytes: Uint8Array): string | undefined => decodeUtf8(bytes);
