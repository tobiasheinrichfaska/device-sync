// An in-memory REFERENCE server of the relay protocol, version 1 and (config `revision: 2`, the default)
// the admission revision, written from docs/relay-protocol.md
// and nothing else: the conformance cases and the client are tested against it in CI. It has no
// sockets (a `fetch` function calls it directly), an injectable clock, and the OPTIONAL test
// interface of the specification ("Test interface"): reset, advance time, lower limits, stand in for
// the push service. `defect` switches on one deliberate fault, so a test can show that the
// conformance runner notices it.
import {
  createHash,
  createHmac,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify,
} from 'node:crypto';
import { RELAY_LIMITS, type RelayLimits } from '../../src/relay/limits.ts';

export interface RefApp {
  readonly origins: readonly string[];
  /** Raw public keys (87 characters base64url) of the login scripts; empty = no proofs. */
  readonly proofKeys: readonly string[];
  readonly invitations: boolean;
  /** How many groups the app may open; 0 = no new device is taken at all. */
  readonly groups: number;
  readonly blocked?: readonly string[];
  /** Revision 2: groups where only the new procedure (certificate) holds. */
  readonly strict?: readonly string[];
}

/** A developer password of revision 2 (the real server keeps a hash; this test server keeps the text). */
export interface RefPassword {
  readonly app: string;
  readonly group: string;
  readonly password: string;
  /** End, seconds since 1970. */
  readonly until: number;
  readonly max: number;
  readonly alsoWithDevices?: boolean;
}

export type Defect =
  | 'origin-status'
  | 'no-nosniff'
  | 'no-vary'
  | 'cache-allowed'
  | 'expired-as-invalid'
  | 'keep-after-collect'
  | 'cors-for-all'
  | 'unknown-member-ok'
  | 'self-drop-ok'
  | 'reuse-wrong-kind'
  | 'drop-no-order'
  | 'preflight-for-all'
  // revision 2
  | 'possession-unchecked'
  | 'possession-replay'
  | 'blocked-ticket-only'
  | 'role-unchecked'
  | 'group-leak'
  | 'blocked-as-expired'
  | 'founder-reusable'
  | 'preflight-no-headers';

export interface RefConfig {
  readonly secret: Uint8Array;
  readonly apps: Readonly<Record<string, RefApp>>;
  readonly now?: () => number;
  readonly limits?: Partial<RelayLimits>;
  readonly defect?: Defect;
  /** 1 = version 1 only (an older relay); 2 = with the admission revision. Default 2. */
  readonly revision?: 1 | 2;
  /** The two header names of revision 2; default the neutral ones of the document. */
  readonly headers?: { readonly possession: string; readonly version: string };
  /** Raw public keys of the developer (founder tickets). */
  readonly developerKeys?: readonly string[];
  readonly developerPasswords?: readonly RefPassword[];
}

export interface RefRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

export interface RefResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

/** The optional test interface (spec section "Test interface"). */
export interface TestControl {
  reset(): void;
  advanceTime(ms: number): void;
  setLimits(limits: Partial<RelayLimits>): void;
  /** What the stand-in push service answers: an HTTP status, or `unreachable`. */
  setPushResult(result: number | 'unreachable'): void;
}

const DEVICE = /^geraet-[0-9a-f]{32}$/;
const APP = /^[a-z][a-z0-9]{1,15}$/;
const ACCESS =
  /^z1\.([a-z][a-z0-9]{1,15})\.(geraet-[0-9a-f]{32})\.([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{43})$/;
const INVITATION =
  /^e1\.([a-z][a-z0-9]{1,15})\.([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;
const PROOF = /^n1\.([A-Za-z0-9_-]{1,400})\.([A-Za-z0-9_-]{86})$/;
const NONCE = /^[A-Za-z0-9_-]{22}$/;
const NAMED_APP = /^(?:c1|e1|e2|z1|g1)\.([a-z][a-z0-9]{1,15})\./;
const GROUP = /^(?!standard$)[a-z0-9-]{1,20}$/;
const ROLE = /^(buero|ohne|lb:[A-Za-z0-9_-]{1,40})$/;
const RAW_KEY = /^[A-Za-z0-9_-]{87}$/;
const CERT =
  /^c1\.([a-z][a-z0-9]{1,15})\.((?!standard\.)[a-z0-9-]{1,20})\.(geraet-[0-9a-f]{32})\.(buero|ohne|lb:[A-Za-z0-9_-]{1,40})\.([A-Za-z0-9_-]{87})\.([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{43})$/;
const INVITATION2 =
  /^e2\.([a-z][a-z0-9]{1,15})\.((?!standard\.)[a-z0-9-]{1,20})\.(geraet-[0-9a-f]{32})\.(buero|ohne|lb:[A-Za-z0-9_-]{1,40})\.([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;
const FOUNDER =
  /^g1\.([a-z][a-z0-9]{1,15})\.((?!standard\.)[a-z0-9-]{1,20})\.([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{86})$/;
const POSSESSION = /^([1-9][0-9]{0,11})\.([A-Za-z0-9_-]{86})$/;
const VERSION_HEADER = /^[0-9]{1,3}$/;
const VAPID = /^vapid t=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+, k=[A-Za-z0-9_-]{87}$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

const ERRORS: Readonly<Record<string, readonly [number, string]>> = {
  unbekannt: [404, 'unknown endpoint'],
  methode: [405, 'method'],
  herkunft: [403, 'origin'],
  typ: [415, 'type'],
  'zu-gross': [413, 'too large'],
  'zu-langsam': [408, 'too slow'],
  unlesbar: [400, 'unreadable'],
  'zugang-fehlt': [401, 'no access'],
  'zugang-ungueltig': [401, 'access invalid'],
  'zugang-abgelaufen': [401, 'access expired'],
  'app-unbekannt': [403, 'app unknown'],
  gesperrt: [403, 'blocked'],
  'zu-viele-anfragen': [429, 'rate'],
  beschaeftigt: [503, 'busy'],
  'relay-voll': [503, 'relay full'],
  'nachweis-ungueltig': [400, 'proof malformed'],
  'nachweis-nicht-eingerichtet': [403, 'proofs not set up'],
  'nachweis-unterschrift': [403, 'proof signature'],
  'nachweis-abgelaufen': [403, 'proof expired'],
  'einladung-ungueltig': [403, 'invitation invalid'],
  'einladung-abgelaufen': [403, 'invitation expired'],
  'einladen-aus': [403, 'invitations off'],
  verbraucht: [409, 'used'],
  'zu-viele-einschreibungen': [429, 'enrolments'],
  'zu-viele-einladungen': [429, 'invitations'],
  'klingeln-ungueltig': [400, 'ring invalid'],
  'klingeln-zu-oft': [429, 'ring rate'],
  'push-dienst': [502, 'push service'],
  'geraete-voll': [409, 'devices full'],
  'aufnahme-geschlossen': [403, 'admission closed'],
  intern: [500, 'internal'],
  'neue-fassung-noetig': [426, 'new version needed'],
  'besitz-fehlt': [401, 'possession missing'],
  'besitz-ungueltig': [401, 'possession invalid'],
  'besitz-zeit': [401, 'possession time'],
  'rolle-nicht-erlaubt': [403, 'role'],
  'geraet-unbekannt': [404, 'device unknown'],
  'sperrliste-voll': [503, 'blocklist full'],
  'entwickler-nicht-eingerichtet': [403, 'developer not set up'],
  'entwickler-ungueltig': [403, 'developer invalid'],
  'entwickler-abgelaufen': [403, 'developer expired'],
  'entwickler-belegt': [403, 'group taken'],
};

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
const isoDay = (s: number): string => new Date(s * 1000).toISOString().slice(0, 10);

function readBase64url(text: unknown, max: number): Buffer | undefined {
  if (typeof text !== 'string' || !BASE64URL.test(text) || text.length > Math.ceil((max * 4) / 3)) {
    return undefined;
  }
  const bytes = Buffer.from(text, 'base64url');
  return bytes.length <= max && bytes.toString('base64url') === text ? bytes : undefined;
}

function readBytesOk(text: string, length: number): boolean {
  const bytes = Buffer.from(text, 'base64url');
  return bytes.length === length && bytes.toString('base64url') === text;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function only(v: unknown, allowed: readonly string[]): Record<string, unknown> | undefined {
  return isObject(v) && Object.keys(v).every((k) => allowed.includes(k)) ? v : undefined;
}

interface Waiting {
  readonly from: string;
  readonly content: Buffer;
  readonly at: number;
  readonly weight: number;
}

interface Entry {
  role: string;
  from: string;
  sinceMs: number;
  lastMs: number;
  procedure: 'neu' | 'alt';
  p: number | undefined;
}

function rawKey(raw: string): ReturnType<typeof createPublicKey> {
  const bytes = Buffer.from(raw, 'base64url');
  return createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: bytes.subarray(1, 33).toString('base64url'),
      y: bytes.subarray(33, 65).toString('base64url'),
    },
    format: 'jwk',
  });
}

export function createReferenceServer(config: RefConfig) {
  let limits: RelayLimits = { ...RELAY_LIMITS, ...config.limits };
  let offset = 0;
  let pushResult: number | 'unreachable' = 201;
  const wall = config.now ?? Date.now;
  const now = (): number => wall() + offset;
  const defect = config.defect;
  const publicKeys = new Map<string, ReturnType<typeof createPublicKey>[]>();
  const allOrigins = new Set<string>();
  for (const [name, app] of Object.entries(config.apps)) {
    for (const o of app.origins) allOrigins.add(o);
    publicKeys.set(
      name,
      app.proofKeys.map((raw) => {
        const bytes = Buffer.from(raw, 'base64url');
        return createPublicKey({
          key: {
            kty: 'EC',
            crv: 'P-256',
            x: bytes.subarray(1, 33).toString('base64url'),
            y: bytes.subarray(33, 65).toString('base64url'),
          },
          format: 'jwk',
        });
      }),
    );
  }

  let boxes = new Map<string, Waiting[]>();
  let boxBytes = new Map<string, number>();
  let senderBytes = new Map<string, number>();
  let appBytes = new Map<string, number>();
  let totalBytes = 0;
  let presence = new Map<string, number>();
  let windows = new Map<string, number[]>();
  let used = new Map<string, number>();
  /** Revision 2: the devices the relay has seen, per `app:group` (the old access is group `1`). */
  let known = new Map<string, Map<string, Entry>>();
  let blocklist = new Map<string, Map<string, number>>();
  let seenPossession = new Map<string, number>();
  let passwordUses = new Map<number, number>();
  const revision = config.revision ?? 2;
  const headerNames = config.headers ?? {
    possession: 'x-relay-signature',
    version: 'x-relay-protocol',
  };
  const developerKeys = (config.developerKeys ?? []).map((raw) => rawKey(raw));

  const reset = (): void => {
    boxes = new Map();
    boxBytes = new Map();
    senderBytes = new Map();
    appBytes = new Map();
    totalBytes = 0;
    presence = new Map();
    windows = new Map();
    used = new Map();
    known = new Map();
    blocklist = new Map();
    seenPossession = new Map();
    passwordUses = new Map();
    limits = { ...RELAY_LIMITS, ...config.limits };
    offset = 0;
    pushResult = 201;
  };

  function allow(key: string, windowMs: number, max: number): boolean {
    const t = now();
    const list = (windows.get(key) ?? []).filter((x) => x > t - windowMs);
    if (list.length >= max) {
      windows.set(key, list);
      return false;
    }
    list.push(t);
    windows.set(key, list);
    return true;
  }

  function headers(
    origin: string | undefined,
    extra: Record<string, string> = {},
  ): Record<string, string> {
    const h: Record<string, string> = {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': defect === 'cache-allowed' ? 'max-age=60' : 'no-store',
      ...(defect === 'no-nosniff' ? {} : { 'X-Content-Type-Options': 'nosniff' }),
      ...(defect === 'no-vary' ? {} : { Vary: 'Origin' }),
      ...extra,
    };
    if (origin) h['Access-Control-Allow-Origin'] = origin;
    return h;
  }

  const ok = (status: number, data: unknown, origin?: string): RefResponse => ({
    status,
    headers: headers(origin),
    body: JSON.stringify(data),
  });

  function err(art: string, origin?: string, plainOrigin?: string): RefResponse {
    let [status, text] = ERRORS[art] as readonly [number, string];
    if (art === 'herkunft' && defect === 'origin-status') status = 401;
    if (art === 'herkunft' && defect === 'cors-for-all' && plainOrigin) origin = plainOrigin;
    return { status, headers: headers(origin), body: JSON.stringify({ fehler: text, art }) };
  }

  const mac = (head: string, label: string): string =>
    createHmac('sha256', config.secret).update(`${label}:${head}`, 'utf8').digest('base64url');
  const same = (a: string, b: string): boolean => {
    const x = Buffer.from(a, 'base64url');
    const y = Buffer.from(b, 'base64url');
    return x.length === y.length && timingSafeEqual(x, y);
  };

  function tidy(box: Waiting[], key: string): void {
    const t = now();
    while (box[0] && box[0].at <= t - limits.waitMs) {
      const e = box.shift() as Waiting;
      remove(key, e);
    }
  }

  function remove(key: string, e: Waiting): void {
    const app = key.split('|')[0] as string;
    totalBytes -= e.weight;
    boxBytes.set(key, (boxBytes.get(key) ?? 0) - e.weight);
    appBytes.set(app, (appBytes.get(app) ?? 0) - e.weight);
    const sk = `${app}|${e.from}`;
    senderBytes.set(sk, (senderBytes.get(sk) ?? 0) - e.weight);
  }

  const scopeOf = (app: string, group: string): string => `${app}:${group}`;
  function touch(
    app: string,
    group: string,
    device: string,
    role: string,
    procedure: 'neu' | 'alt',
    p: number | undefined,
    from = 'alt',
  ): void {
    const scope = scopeOf(app, group);
    let map = known.get(scope);
    if (!map) known.set(scope, (map = new Map()));
    const t = now();
    const e = map.get(device);
    if (e) {
      e.lastMs = t;
      e.procedure = procedure;
      if (procedure === 'neu') e.role = role;
      e.p = p;
      return;
    }
    if (map.size >= limits.devicesPerApp * 2) return;
    map.set(device, { role, from, sinceMs: t, lastMs: t, procedure, p });
  }
  const devicesTotal = (): number => [...known.values()].reduce((s, x) => s + x.size, 0);
  const groupsOccupied = (app: string): number =>
    [...known].filter(([k, v]) => k.startsWith(`${app}:`) && v.size > 0).length;
  const isBlocked = (app: RefApp, scope: string, device: string, cert: boolean): boolean =>
    app.blocked?.includes(device) === true ||
    ((blocklist.get(scope)?.get(device) ?? 0) > now() &&
      !(defect === 'blocked-ticket-only' && cert));

  // ── enrolment ─────────────────────────────────────────────────────────────────────────────────
  function enrolV1(body: unknown, origin: string): RefResponse {
    const feld = only(body, ['nachweis', 'einladung']);
    if (!feld) return err('unlesbar', origin);
    const { nachweis, einladung } = feld;
    const ways = [nachweis, einladung].filter((w) => w !== undefined);
    if (ways.length !== 1 || typeof ways[0] !== 'string') return err('unlesbar', origin);
    const text = ways[0];
    const nowS = Math.floor(now() / 1000);
    // The app the text names, before its signature is checked.
    let named: string | undefined;
    let payload: Record<string, unknown> | undefined;
    if (typeof nachweis === 'string') {
      const m = PROOF.exec(nachweis);
      if (m) {
        try {
          const inner: unknown = JSON.parse(
            Buffer.from(m[1] as string, 'base64url').toString('utf8'),
          );
          if (isObject(inner)) {
            payload = inner;
            if (typeof inner['app'] === 'string' && APP.test(inner['app'])) named = inner['app'];
          }
        } catch {
          // read below as malformed
        }
      }
    } else named = NAMED_APP.exec(text)?.[1];
    if (named && config.apps[named] && !config.apps[named]?.origins.includes(origin)) {
      return err('herkunft');
    }
    let appName: string;
    let mark: string;
    let endS: number;
    const byInvitation = typeof einladung === 'string';
    if (typeof nachweis === 'string') {
      const m = PROOF.exec(nachweis);
      if (!m || !payload) return err('nachweis-ungueltig', origin);
      const keys = Object.keys(payload);
      if (keys.length !== 4 || !['v', 'app', 'bis', 'n'].every((k) => keys.includes(k))) {
        return err('nachweis-ungueltig', origin);
      }
      const { v, app, bis, n } = payload;
      if (v !== 1 || typeof app !== 'string' || !APP.test(app))
        return err('nachweis-ungueltig', origin);
      if (typeof bis !== 'number' || !Number.isSafeInteger(bis))
        return err('nachweis-ungueltig', origin);
      if (typeof n !== 'string' || !NONCE.test(n)) return err('nachweis-ungueltig', origin);
      const pk = publicKeys.get(app);
      if (!pk) return err('app-unbekannt', origin);
      if (pk.length === 0) return err('nachweis-nicht-eingerichtet', origin);
      const data = Buffer.from(`n1.${m[1]}`, 'ascii');
      const sig = Buffer.from(m[2] as string, 'base64url');
      const good = pk.some((key) => {
        try {
          return verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig);
        } catch {
          return false;
        }
      });
      if (!good) return err('nachweis-unterschrift', origin);
      if (bis <= nowS || bis > nowS + limits.proofMaxSeconds + limits.proofSkewSeconds) {
        return err('nachweis-abgelaufen', origin);
      }
      appName = app;
      mark = `n:${n}`;
      endS = bis;
    } else {
      const m = INVITATION.exec(text);
      if (!m) return err('einladung-ungueltig', origin);
      const head = `e1.${m[1]}.${m[2]}.${m[3]}`;
      if (!same(m[4] as string, mac(head, 'einladung'))) return err('einladung-ungueltig', origin);
      const bis = Number(m[2]);
      if (bis <= nowS) return err('einladung-abgelaufen', origin);
      if (bis > nowS + limits.invitationSeconds) return err('einladung-ungueltig', origin);
      appName = m[1] as string;
      mark = `e:${m[3]}`;
      endS = bis;
      const a = config.apps[appName];
      if (a && !a.invitations) return err('einladen-aus', origin);
    }
    const app = config.apps[appName];
    if (!app) return err('app-unbekannt', origin);
    if (!app.origins.includes(origin)) return err('herkunft');
    if (used.has(mark))
      return err(defect === 'reuse-wrong-kind' ? 'einladung-ungueltig' : 'verbraucht', origin);
    const devices = known.get(scopeOf(appName, '1'));
    if ((devices?.size ?? 0) === 0 && app.groups <= 0) return err('aufnahme-geschlossen', origin);
    if (devicesTotal() >= limits.devicesTotal) return err('relay-voll', origin);
    if ((devices?.size ?? 0) >= limits.devicesPerApp) return err('geraete-voll', origin);
    const per = byInvitation ? limits.enrolInvitePerHour : limits.enrolProofPerHour;
    if (!allow(`${byInvitation ? 'ei' : 'en'}|${appName}`, 3_600_000, per)) {
      return err('zu-viele-einschreibungen', origin);
    }
    used.set(mark, endS * 1000);
    const device = `geraet-${randomBytes(16).toString('hex')}`;
    touch(appName, '1', device, 'ohne', 'alt', undefined, byInvitation ? 'alt' : 'nachweis');
    const access = issueAccess(appName, device, nowS);
    return ok(201, { geraet: device, zugang: access.text, bis: isoDay(access.end) }, origin);
  }

  // ── enrolment, revision 2 ─────────────────────────────────────────────────────────────────────
  const ticketMac = (head: string, label: string): string => mac(head, label);

  function certificate(
    app: string,
    group: string,
    device: string,
    role: string,
    key: string,
    nowS: number,
  ): { text: string; end: number } {
    const end = nowS + limits.certificateDays * 86_400;
    const head = `c1.${app}.${group}.${device}.${role}.${key}.${end}`;
    return { text: `${head}.${ticketMac(head, 'zertifikat')}`, end };
  }

  const info = (app: RefApp | undefined, group: string): Record<string, unknown> => {
    const oldOk = app === undefined || (group === '1' && !app.strict?.includes(group));
    return {
      v: 2,
      faehigkeiten: [
        'mandant',
        'zertifikat',
        'besitznachweis',
        'einladung2',
        'gruender',
        'sperren',
        'geraete',
      ],
      verfahren: {
        angeboten: oldOk ? ['zugang', 'zertifikat'] : ['zertifikat'],
        bevorzugt: 'zertifikat',
        einschreiben: oldOk
          ? ['nachweis', 'einladung', 'einladung2', 'gruender', 'passwort']
          : ['einladung2', 'gruender', 'passwort'],
      },
    };
  };

  function pointOk(raw: unknown): raw is string {
    if (typeof raw !== 'string' || !RAW_KEY.test(raw)) return false;
    try {
      rawKey(raw);
      return Buffer.from(raw, 'base64url').toString('base64url') === raw;
    } catch {
      return false;
    }
  }

  function developerSigned(head: string, signature: string): boolean {
    const sig = Buffer.from(signature, 'base64url');
    return developerKeys.some((key) => {
      try {
        return verify('sha256', Buffer.from(head), { key, dsaEncoding: 'ieee-p1363' }, sig);
      } catch {
        return false;
      }
    });
  }

  function enrolV2(body: unknown, origin: string): RefResponse {
    const feld = only(body, [
      'nachweis',
      'einladung',
      'gruender',
      'passwort',
      'app',
      'mandant',
      'geraetSchluessel',
      'rolle',
    ]);
    if (!feld) return err('unlesbar', origin);
    const { nachweis, einladung, gruender, passwort } = feld;
    const ways = [nachweis, einladung, gruender, passwort].filter((w) => w !== undefined);
    if (ways.length !== 1 || typeof ways[0] !== 'string') return err('unlesbar', origin);
    const key = feld['geraetSchluessel'];
    if (key !== undefined && !pointOk(key)) return err('unlesbar', origin);
    const claimed = feld['rolle'];
    if (claimed !== undefined && !(typeof claimed === 'string' && ROLE.test(claimed))) {
      return err('unlesbar', origin);
    }
    if (passwort === undefined && (feld['app'] !== undefined || feld['mandant'] !== undefined)) {
      return err('unlesbar', origin);
    }
    const nowS = Math.floor(now() / 1000);
    // The app a text names, before its signature: a foreign origin learns nothing.
    let named: string | undefined;
    let payload: Record<string, unknown> | undefined;
    if (typeof nachweis === 'string') {
      const m = PROOF.exec(nachweis);
      if (m) {
        try {
          const inner: unknown = JSON.parse(
            Buffer.from(m[1] as string, 'base64url').toString('utf8'),
          );
          if (isObject(inner)) {
            payload = inner;
            if (typeof inner['app'] === 'string' && APP.test(inner['app'])) named = inner['app'];
          }
        } catch {
          // read below as malformed
        }
      }
    } else if (typeof einladung === 'string') named = NAMED_APP.exec(einladung)?.[1];
    else if (typeof gruender === 'string')
      named = /^g1\.([a-z][a-z0-9]{1,15})\./.exec(gruender)?.[1];
    else if (typeof feld['app'] === 'string') named = feld['app'];
    if (named && config.apps[named] && !config.apps[named]?.origins.includes(origin)) {
      return err('herkunft');
    }
    let appName: string | undefined;
    let mark: string | undefined;
    let endS = 0;
    let group = '1';
    let role = typeof claimed === 'string' ? claimed : 'ohne';
    let from = 'alt';
    let old = false;
    let counter: 'en' | 'ei' = 'en';
    let passwordIndex: number | undefined;
    if (typeof nachweis === 'string') {
      const m = PROOF.exec(nachweis);
      if (!m || !payload) return err('nachweis-ungueltig', origin);
      const keys = Object.keys(payload);
      if (keys.length !== 4 || !['v', 'app', 'bis', 'n'].every((k) => keys.includes(k))) {
        return err('nachweis-ungueltig', origin);
      }
      const { v, app, bis, n } = payload;
      if (v !== 1 || typeof app !== 'string' || !APP.test(app))
        return err('nachweis-ungueltig', origin);
      if (typeof bis !== 'number' || !Number.isSafeInteger(bis))
        return err('nachweis-ungueltig', origin);
      if (typeof n !== 'string' || !NONCE.test(n)) return err('nachweis-ungueltig', origin);
      const pk = publicKeys.get(app);
      if (!pk) return err('app-unbekannt', origin);
      if (pk.length === 0) return err('nachweis-nicht-eingerichtet', origin);
      const data = Buffer.from(`n1.${m[1]}`, 'ascii');
      const sig = Buffer.from(m[2] as string, 'base64url');
      const good = pk.some((k) => {
        try {
          return verify('sha256', data, { key: k, dsaEncoding: 'ieee-p1363' }, sig);
        } catch {
          return false;
        }
      });
      if (!good) return err('nachweis-unterschrift', origin);
      if (bis <= nowS || bis > nowS + limits.proofMaxSeconds + limits.proofSkewSeconds) {
        return err('nachweis-abgelaufen', origin);
      }
      appName = app;
      mark = `n:${n}`;
      endS = bis;
      from = 'nachweis';
      old = true;
    } else if (typeof einladung === 'string') {
      counter = 'ei';
      if (einladung.startsWith('e2.')) {
        const m = INVITATION2.exec(einladung);
        if (!m) return err('einladung-ungueltig', origin);
        const head = `e2.${m[1]}.${m[2]}.${m[3]}.${m[4]}.${m[5]}.${m[6]}`;
        if (!same(m[7] as string, mac(head, 'einladung')))
          return err('einladung-ungueltig', origin);
        const bis = Number(m[5]);
        if (bis <= nowS) return err('einladung-abgelaufen', origin);
        if (bis > nowS + limits.invitationSeconds) return err('einladung-ungueltig', origin);
        if (claimed !== undefined) return err('unlesbar', origin);
        appName = m[1] as string;
        group = m[2] as string;
        role = m[4] as string;
        from = m[3] as string;
        mark = `e:${m[6]}`;
        endS = bis;
        const a = config.apps[appName];
        if (a && isBlocked(a, scopeOf(appName, group), from, true)) {
          return err('einladung-ungueltig', origin);
        }
      } else {
        const m = INVITATION.exec(einladung);
        if (!m) return err('einladung-ungueltig', origin);
        const head = `e1.${m[1]}.${m[2]}.${m[3]}`;
        if (!same(m[4] as string, mac(head, 'einladung')))
          return err('einladung-ungueltig', origin);
        const bis = Number(m[2]);
        if (bis <= nowS) return err('einladung-abgelaufen', origin);
        if (bis > nowS + limits.invitationSeconds) return err('einladung-ungueltig', origin);
        appName = m[1] as string;
        mark = `e:${m[3]}`;
        endS = bis;
        old = true;
      }
      const a = config.apps[appName];
      if (a && !a.invitations) return err('einladen-aus', origin);
    } else if (typeof gruender === 'string') {
      const m = FOUNDER.exec(gruender);
      if (!m || !readBytesOk(m[4] as string, 16) || !readBytesOk(m[5] as string, 64)) {
        return err('entwickler-ungueltig', origin);
      }
      if (developerKeys.length === 0) return err('entwickler-nicht-eingerichtet', origin);
      const head = `g1.${m[1]}.${m[2]}.${m[3]}.${m[4]}`;
      if (!developerSigned(head, m[5] as string)) return err('entwickler-ungueltig', origin);
      const bis = Number(m[3]);
      if (bis <= nowS || bis > nowS + limits.founderMaxSeconds + limits.founderSkewSeconds) {
        return err('entwickler-abgelaufen', origin);
      }
      if (key === undefined) return err('unlesbar', origin);
      appName = m[1] as string;
      group = m[2] as string;
      mark = `g:${m[4]}`;
      endS = bis;
      role = 'buero';
      from = 'entwickler';
      if (claimed !== undefined) return err('unlesbar', origin);
    } else {
      const { app: a, mandant: g } = feld;
      if (typeof a !== 'string' || typeof g !== 'string') return err('unlesbar', origin);
      if (!GROUP.test(g) || key === undefined || claimed !== undefined)
        return err('unlesbar', origin);
      appName = a;
      if (!config.apps[appName]) return err('app-unbekannt', origin);
      const list = config.developerPasswords ?? [];
      if (list.length === 0) return err('entwickler-nicht-eingerichtet', origin);
      if (!allow(`pw|${appName}`, 3_600_000, limits.passwordTriesPerHour)) {
        return err('zu-viele-einschreibungen', origin);
      }
      const at = list.findIndex(
        (x) => x.app === appName && x.group === g && x.password === passwort,
      );
      const entry = list[at];
      if (!entry) return err('entwickler-ungueltig', origin);
      if (entry.until * 1000 <= now() || (passwordUses.get(at) ?? 0) >= entry.max) {
        return err('entwickler-abgelaufen', origin);
      }
      if (!entry.alsoWithDevices && (known.get(scopeOf(appName, g))?.size ?? 0) > 0) {
        return err('entwickler-belegt', origin);
      }
      group = g;
      role = 'buero';
      from = 'entwickler';
      passwordIndex = at;
    }
    const app = appName === undefined ? undefined : config.apps[appName];
    if (!app || appName === undefined) return err('app-unbekannt', origin);
    if (!app.origins.includes(origin)) return err('herkunft');
    if (old && app.strict?.includes(group)) return err('neue-fassung-noetig', origin);
    // The old access means group `1` and is issued only there and where only the new procedure does not hold.
    const withTicket = group === '1' && !app.strict?.includes(group);
    if (key === undefined && !withTicket) return err('unlesbar', origin);
    if (
      mark !== undefined &&
      used.has(mark) &&
      !(defect === 'founder-reusable' && mark.startsWith('g:'))
    ) {
      return err(defect === 'reuse-wrong-kind' ? 'einladung-ungueltig' : 'verbraucht', origin);
    }
    const members = known.get(scopeOf(appName, group));
    if ((members?.size ?? 0) === 0 && groupsOccupied(appName) >= app.groups) {
      return err('aufnahme-geschlossen', origin);
    }
    if (devicesTotal() >= limits.devicesTotal) return err('relay-voll', origin);
    if ((members?.size ?? 0) >= limits.devicesPerApp) return err('geraete-voll', origin);
    const per = counter === 'ei' ? limits.enrolInvitePerHour : limits.enrolProofPerHour;
    if (!allow(`${counter}|${appName}`, 3_600_000, per)) {
      return err('zu-viele-einschreibungen', origin);
    }
    if (mark !== undefined) used.set(mark, endS * 1000);
    if (passwordIndex !== undefined) {
      passwordUses.set(passwordIndex, (passwordUses.get(passwordIndex) ?? 0) + 1);
    }
    const device = `geraet-${randomBytes(16).toString('hex')}`;
    touch(appName, group, device, role, key === undefined ? 'alt' : 'neu', undefined, from);
    const answer: Record<string, unknown> = { geraet: device };
    let end: number;
    if (withTicket) {
      const t = issueAccess(appName, device, nowS);
      answer['zugang'] = t.text;
      end = t.end;
    } else end = nowS + limits.certificateDays * 86_400;
    if (key !== undefined) {
      const c = certificate(appName, group, device, role, key, nowS);
      answer['zertifikat'] = c.text;
      answer['mandant'] = group;
      answer['rolle'] = role;
      Object.assign(answer, info(app, group));
      end = c.end;
    }
    answer['bis'] = isoDay(end);
    return ok(201, answer, origin);
  }

  function issueAccess(app: string, device: string, nowS: number): { text: string; end: number } {
    const end = nowS + limits.accessDays * 86_400;
    const head = `z1.${app}.${device}.${end}`;
    return { text: `${head}.${mac(head, 'zugang')}`, end };
  }

  // ── the request ───────────────────────────────────────────────────────────────────────────────
  async function handle(req: RefRequest): Promise<RefResponse> {
    const h = req.headers;
    const originHeader = h['origin'];
    const knownOrigin =
      originHeader !== undefined && allOrigins.has(originHeader) ? originHeader : undefined;
    if (req.path.includes('?') || req.path.includes('#')) return err('unlesbar', knownOrigin);
    if (req.path === '/gesund') {
      if (req.method !== 'GET') return err('methode');
      if (revision === 1) return ok(200, { ok: true, stand: 'reference' }, knownOrigin);
      const appOfOrigin =
        knownOrigin === undefined
          ? undefined
          : Object.values(config.apps).find((a) => a.origins.includes(knownOrigin));
      const answer: Record<string, unknown> = {
        ok: true,
        stand: 'reference',
        ...info(appOfOrigin, '1'),
      };
      if (appOfOrigin) {
        answer['app'] = Object.keys(config.apps).find((n) => config.apps[n] === appOfOrigin);
        answer['altAbgeschaltet'] = appOfOrigin.strict?.includes('1') === true;
        answer['aufnahmeOffen'] =
          groupsOccupied(answer['app'] as string) < appOfOrigin.groups &&
          devicesTotal() < limits.devicesTotal;
      }
      return ok(200, answer, knownOrigin);
    }
    const endpoint = [
      'ping',
      'einschreiben',
      'erneuern',
      'einladen',
      'ablegen',
      'abholen',
      'klingeln',
      ...(revision === 2 ? ['geraete', 'sperren'] : []),
    ].find((e) => req.path === `/v1/${e}`);
    if (!endpoint) return err('unbekannt');
    if (req.method === 'OPTIONS') {
      if (!knownOrigin || h['access-control-request-method'] !== 'POST') {
        if (defect === 'preflight-for-all' && originHeader) {
          return { status: 204, headers: headers(originHeader), body: '' };
        }
        return err('herkunft');
      }
      return {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': knownOrigin,
          'Access-Control-Allow-Methods': 'POST',
          'Access-Control-Allow-Headers':
            revision === 2 && defect !== 'preflight-no-headers'
              ? `authorization, content-type, ${headerNames.possession}, ${headerNames.version}`
              : 'authorization, content-type',
          'Access-Control-Max-Age': '600',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
          Vary: 'Origin',
        },
        body: '',
      };
    }
    if (req.method !== 'POST') return err('methode', knownOrigin);
    if (!knownOrigin) return err('herkunft', undefined, originHeader);
    const type = (h['content-type'] ?? '').split(';')[0]?.trim().toLowerCase();
    if (type !== 'application/json') return err('typ', knownOrigin);
    const maxBody =
      endpoint === 'ablegen'
        ? limits.maxBodyDrop
        : endpoint === 'klingeln'
          ? limits.maxBodyRing
          : limits.maxBodyBytes;

    interface Me {
      app: string;
      group: string;
      device: string;
      role: string;
      endS: number;
      cert?: { text: string; key: string };
    }
    let me: Me | undefined;
    if (endpoint !== 'einschreiben') {
      const auth = h['authorization'];
      if (!auth?.startsWith('Bearer ')) return err('zugang-fehlt', knownOrigin);
      const text = auth.slice('Bearer '.length);
      const named = NAMED_APP.exec(text)?.[1];
      if (named && config.apps[named] && !config.apps[named]?.origins.includes(knownOrigin)) {
        return err('herkunft');
      }
      const nowS = Math.floor(now() / 1000);
      let appName: string;
      if (revision === 2 && text.startsWith('c1.')) {
        const m = CERT.exec(text);
        if (!m || !readBytesOk(m[5] as string, 65)) return err('zugang-ungueltig', knownOrigin);
        const head = `c1.${m[1]}.${m[2]}.${m[3]}.${m[4]}.${m[5]}.${m[6]}`;
        if (!same(m[7] as string, mac(head, 'zertifikat'))) {
          return err('zugang-ungueltig', knownOrigin);
        }
        if (Number(m[6]) <= nowS) {
          return err(
            defect === 'expired-as-invalid' ? 'zugang-ungueltig' : 'zugang-abgelaufen',
            knownOrigin,
          );
        }
        appName = m[1] as string;
        me = {
          app: appName,
          group: m[2] as string,
          device: m[3] as string,
          role: m[4] as string,
          endS: Number(m[6]),
          cert: { text, key: m[5] as string },
        };
      } else {
        const m = ACCESS.exec(text);
        if (!m) return err('zugang-ungueltig', knownOrigin);
        const head = `z1.${m[1]}.${m[2]}.${m[3]}`;
        if (!same(m[4] as string, mac(head, 'zugang'))) return err('zugang-ungueltig', knownOrigin);
        if (Number(m[3]) <= nowS) {
          return err(
            defect === 'expired-as-invalid' ? 'zugang-ungueltig' : 'zugang-abgelaufen',
            knownOrigin,
          );
        }
        appName = m[1] as string;
        me = {
          app: appName,
          group: '1',
          device: m[2] as string,
          role: known.get(scopeOf(appName, '1'))?.get(m[2] as string)?.role ?? 'ohne',
          endS: Number(m[3]),
        };
      }
      const app = config.apps[appName];
      if (!app) return err('app-unbekannt', knownOrigin);
      if (!app.origins.includes(knownOrigin)) return err('herkunft');
      if (isBlocked(app, scopeOf(appName, me.group), me.device, me.cert !== undefined)) {
        return err(defect === 'blocked-as-expired' ? 'zugang-abgelaufen' : 'gesperrt', knownOrigin);
      }
      if (me.cert === undefined && revision === 2 && app.strict?.includes('1')) {
        return err('neue-fassung-noetig', knownOrigin);
      }
      if (!allow(`req|${me.app}|${me.device}`, 60_000, limits.requestsPerMinute)) {
        return err('zu-viele-anfragen', knownOrigin);
      }
    }
    if (req.body.length > maxBody) return err('zu-gross', knownOrigin);
    // The proof of possession: judged with the body (it is signed), before the body is read as JSON.
    if (me?.cert && defect !== 'possession-unchecked') {
      const value = h[headerNames.possession];
      if (value === undefined) return err('besitz-fehlt', knownOrigin);
      const m = POSSESSION.exec(value);
      if (!m) return err('besitz-ungueltig', knownOrigin);
      const t = Number(m[1]);
      const hash = createHash('sha256').update(req.body).digest('base64url');
      const text = `v1\n${req.method}\n${req.path}\n${t}\n${hash}\n${me.cert.text}`;
      let good = false;
      try {
        good = verify(
          'sha256',
          Buffer.from(text, 'utf8'),
          { key: rawKey(me.cert.key), dsaEncoding: 'ieee-p1363' },
          Buffer.from(m[2] as string, 'base64url'),
        );
      } catch {
        good = false;
      }
      if (!good) return err('besitz-ungueltig', knownOrigin);
      if (Math.abs(t - Math.floor(now() / 1000)) > limits.possessionSkewSeconds) {
        return err('besitz-zeit', knownOrigin);
      }
      const memory = `${me.device}|${m[2]}`;
      if (seenPossession.has(memory) && defect !== 'possession-replay') {
        return err('besitz-ungueltig', knownOrigin);
      }
      seenPossession.set(memory, (t + limits.possessionSkewSeconds + 1) * 1000);
    }
    let raw: unknown;
    try {
      raw = JSON.parse(Buffer.from(req.body).toString('utf8'));
    } catch {
      return err('unlesbar', knownOrigin);
    }
    if (endpoint === 'einschreiben')
      return revision === 2 ? enrolV2(raw, knownOrigin) : enrolV1(raw, knownOrigin);
    if (!me) return err('zugang-fehlt', knownOrigin);
    const versionHeader = revision === 2 ? h[headerNames.version] : undefined;
    const announced =
      versionHeader !== undefined && VERSION_HEADER.test(versionHeader)
        ? Number(versionHeader)
        : undefined;
    touch(me.app, me.group, me.device, me.role, me.cert ? 'neu' : 'alt', announced);
    const t = now();
    const scopeKey = (device: string): string => `${me.app}|${device}`;
    switch (endpoint) {
      case 'ping': {
        const strict = defect === 'unknown-member-ok' ? isObject(raw) : only(raw, []);
        if (!strict) return err('unlesbar', knownOrigin);
        const app = config.apps[me.app];
        return ok(
          200,
          {
            geraet: me.device,
            app: me.app,
            bis: isoDay(me.endS),
            ...(me.cert ? { mandant: me.group, rolle: me.role } : {}),
            ...(me.cert || announced !== undefined ? info(app, me.group) : {}),
          },
          knownOrigin,
        );
      }
      case 'erneuern': {
        const f = only(raw, revision === 2 ? ['geraetSchluessel', 'rolle'] : []);
        if (!f) return err('unlesbar', knownOrigin);
        const nowS = Math.floor(t / 1000);
        const app = config.apps[me.app];
        if (me.cert) {
          // A certificate renews itself: same key, group and role, nothing to claim.
          if (Object.keys(f).length > 0) return err('unlesbar', knownOrigin);
          const c = certificate(me.app, me.group, me.device, me.role, me.cert.key, nowS);
          return ok(
            200,
            { zertifikat: c.text, bis: isoDay(c.end), ...info(app, me.group) },
            knownOrigin,
          );
        }
        const a = issueAccess(me.app, me.device, nowS);
        const key = f['geraetSchluessel'];
        const claimed = f['rolle'];
        if (
          (key !== undefined && !pointOk(key)) ||
          (claimed !== undefined && !(typeof claimed === 'string' && ROLE.test(claimed))) ||
          (claimed !== undefined && key === undefined)
        ) {
          return err('unlesbar', knownOrigin);
        }
        const answer: Record<string, unknown> = { zugang: a.text, bis: isoDay(a.end) };
        if (key !== undefined) {
          const role = typeof claimed === 'string' ? claimed : me.role;
          const c = certificate(me.app, me.group, me.device, role, key as string, nowS);
          answer['zertifikat'] = c.text;
          answer['mandant'] = me.group;
          answer['rolle'] = role;
          const entry = known.get(scopeOf(me.app, me.group))?.get(me.device);
          if (entry) entry.role = role;
          Object.assign(answer, info(app, me.group));
        }
        return ok(200, answer, knownOrigin);
      }
      case 'einladen': {
        const f = only(raw, revision === 2 ? ['rolle'] : []);
        if (!f) return err('unlesbar', knownOrigin);
        if (!config.apps[me.app]?.invitations) return err('einladen-aus', knownOrigin);
        const wanted = f['rolle'];
        if (wanted !== undefined && !(typeof wanted === 'string' && ROLE.test(wanted))) {
          return err('unlesbar', knownOrigin);
        }
        let forRole = 'ohne';
        if (!me.cert) {
          if (wanted !== undefined) return err('unlesbar', knownOrigin);
        } else {
          forRole = typeof wanted === 'string' ? wanted : me.role === 'buero' ? 'ohne' : me.role;
          const may = me.role === 'buero' || (me.role.startsWith('lb:') && forRole === me.role);
          if (!may && defect !== 'role-unchecked') return err('rolle-nicht-erlaubt', knownOrigin);
        }
        if (!allow(`inv|${me.app}|${me.device}`, 3_600_000, limits.invitePerHour)) {
          return err('zu-viele-einladungen', knownOrigin);
        }
        const bis = Math.floor(t / 1000) + limits.invitationSeconds;
        const random = randomBytes(16).toString('base64url');
        const head = me.cert
          ? `e2.${me.app}.${me.group}.${me.device}.${forRole}.${bis}.${random}`
          : `e1.${me.app}.${bis}.${random}`;
        return ok(
          201,
          { einladung: `${head}.${mac(head, 'einladung')}`, gueltigS: limits.invitationSeconds },
          knownOrigin,
        );
      }
      case 'geraete': {
        if (!only(raw, [])) return err('unlesbar', knownOrigin);
        if (!me.cert) return err('rolle-nicht-erlaubt', knownOrigin);
        const scopes =
          defect === 'group-leak'
            ? [...known].filter(([k]) => k.startsWith(`${me.app}:`)).map(([, v]) => v)
            : [known.get(scopeOf(me.app, me.group)) ?? new Map<string, Entry>()];
        const list = scopes
          .flatMap((m) => [...m])
          .filter(
            ([d, e]) =>
              d === me.device ||
              me.role === 'buero' ||
              (me.role.startsWith('lb:') && e.role === me.role),
          )
          .map(([d, e]) => ({
            geraet: d,
            rolle: e.role,
            von: e.from,
            seit: new Date(e.sinceMs).toISOString(),
            zuletzt: new Date(e.lastMs).toISOString(),
            verfahren: e.procedure,
            ...(e.p === undefined ? {} : { p: e.p }),
          }));
        return ok(200, { geraete: list, hoechstens: limits.devicesPerApp }, knownOrigin);
      }
      case 'sperren': {
        const f = only(raw, ['geraet']);
        const target = f?.['geraet'];
        if (typeof target !== 'string' || !DEVICE.test(target)) return err('unlesbar', knownOrigin);
        if (!me.cert) return err('rolle-nicht-erlaubt', knownOrigin);
        const known1 = known.get(scopeOf(me.app, me.group))?.get(target);
        const selfBlock = target === me.device;
        const may =
          selfBlock ||
          me.role === 'buero' ||
          (me.role.startsWith('lb:') && known1?.role === me.role);
        if (!may && defect !== 'role-unchecked') return err('rolle-nicht-erlaubt', knownOrigin);
        if (!allow(`blk|${me.app}|${me.device}`, 3_600_000, limits.blocksPerHour)) {
          return err('zu-viele-einladungen', knownOrigin);
        }
        const scope = scopeOf(me.app, me.group);
        let list = blocklist.get(scope);
        if (!list) blocklist.set(scope, (list = new Map()));
        if (!list.has(target) && list.size >= limits.blocklistPerGroup) {
          return err('sperrliste-voll', knownOrigin);
        }
        list.set(target, t + limits.blockHoldDays * 86_400_000);
        return ok(200, { geraet: target, gesperrt: true }, knownOrigin);
      }
      case 'ablegen': {
        const feld = only(raw, ['an']);
        const list = feld?.['an'];
        if (!Array.isArray(list) || list.length === 0 || list.length > limits.maxRecipients) {
          return err('unlesbar', knownOrigin);
        }
        const pieces: { device: string; content: Buffer }[] = [];
        for (const item of list as unknown[]) {
          const e = only(item, ['geraet', 'inhalt']);
          const content = readBase64url(e?.['inhalt'], limits.maxContentBytes);
          if (!e || typeof e['geraet'] !== 'string' || !DEVICE.test(e['geraet']) || !content) {
            return err('unlesbar', knownOrigin);
          }
          if (content.length === 0) return err('unlesbar', knownOrigin);
          if (e['geraet'] === me.device && defect !== 'self-drop-ok')
            return err('unlesbar', knownOrigin);
          if (pieces.some((p) => p.device === e['geraet'])) return err('unlesbar', knownOrigin);
          pieces.push({ device: e['geraet'], content });
        }
        const results = pieces.map(({ device, content }) => {
          const key = scopeKey(device);
          const box = boxes.get(key) ?? [];
          tidy(box, key);
          const weight = Math.max(content.length, limits.minMessageWeight);
          const sk = `${me.app}|${me.device}`;
          let why: string | undefined;
          if (totalBytes + weight > limits.totalBytes) why = 'voll';
          else if ((appBytes.get(me.app) ?? 0) + weight > limits.appBytes) why = 'app-voll';
          else if ((senderBytes.get(sk) ?? 0) + weight > limits.senderBytes) why = 'absender-voll';
          else if (
            box.length + 1 > limits.mailboxMessages ||
            (boxBytes.get(key) ?? 0) + weight > limits.mailboxBytes
          ) {
            why = 'empfaenger-voll';
          }
          if (why) return { geraet: device, ok: false, art: why, fehler: why };
          box.push({ from: me.device, content, at: t, weight });
          boxes.set(key, box);
          totalBytes += weight;
          boxBytes.set(key, (boxBytes.get(key) ?? 0) + weight);
          appBytes.set(me.app, (appBytes.get(me.app) ?? 0) + weight);
          senderBytes.set(sk, (senderBytes.get(sk) ?? 0) + weight);
          const seen = presence.get(key);
          return {
            geraet: device,
            ok: true,
            anwesend: seen !== undefined && seen > t - limits.presenceMs,
          };
        });
        if (defect === 'drop-no-order') results.reverse();
        return ok(200, { ergebnisse: results }, knownOrigin);
      }
      case 'abholen': {
        const feld = only(raw, ['anwesend']);
        if (!feld) return err('unlesbar', knownOrigin);
        let asked: string[] = [];
        if (feld['anwesend'] !== undefined) {
          const a = feld['anwesend'];
          if (
            !Array.isArray(a) ||
            a.length > limits.maxPresenceAsk ||
            !a.every((x): x is string => typeof x === 'string' && DEVICE.test(x)) ||
            new Set(a).size !== a.length
          ) {
            return err('unlesbar', knownOrigin);
          }
          asked = a;
        }
        const key = scopeKey(me.device);
        presence.set(key, t);
        const box = boxes.get(key) ?? [];
        tidy(box, key);
        const out: Waiting[] = [];
        let bytes = 0;
        if (defect === 'keep-after-collect') {
          // The fault: the messages are handed out but stay in the box.
          out.push(...box);
        } else {
          while (box.length > 0) {
            const e = box[0] as Waiting;
            if (out.length > 0 && bytes + e.content.length > limits.collectBytes) break;
            bytes += e.content.length;
            box.shift();
            remove(key, e);
            out.push(e);
          }
        }
        const more = box.length > 0 && defect !== 'keep-after-collect';
        if (box.length === 0) boxes.delete(key);
        const present = asked.filter((g) => {
          const seen = presence.get(scopeKey(g));
          return g !== me.device && seen !== undefined && seen > t - limits.presenceMs;
        });
        return ok(
          200,
          {
            nachrichten: out.map((e) => ({
              von: e.from,
              inhalt: b64(e.content),
              alterMs: t - e.at,
            })),
            anwesend: present,
            mehr: more,
          },
          knownOrigin,
        );
      }
      case 'klingeln': {
        const r = readRing(raw);
        if (!r) return err('klingeln-ungueltig', knownOrigin);
        if (!allow(`ring|${me.app}|${me.device}`, 3_600_000, limits.ringPerHour)) {
          return err('klingeln-zu-oft', knownOrigin);
        }
        if (pushResult === 'unreachable') return err('push-dienst', knownOrigin);
        return ok(200, { dienst: pushResult, ms: 1 }, knownOrigin);
      }
      default:
        return err('unbekannt');
    }
  }

  function readRing(raw: unknown): boolean {
    const f = only(raw, ['endpunkt', 'vapid', 'ttl', 'dringlichkeit', 'inhalt']);
    if (!f || Object.keys(f).length !== 5) return false;
    const { endpunkt, vapid, ttl, dringlichkeit, inhalt } = f;
    if (typeof endpunkt !== 'string' || endpunkt.length > limits.ringEndpointMax) return false;
    if (!/^https:\/\/[A-Za-z0-9.-]+\/[\x21-\x7e]*$/.test(endpunkt)) return false;
    let url: URL;
    try {
      url = new URL(endpunkt);
    } catch {
      return false;
    }
    if (url.port !== '' || url.username !== '' || url.password !== '') return false;
    const host = url.hostname.toLowerCase();
    const service =
      (host.endsWith('.push.apple.com') && host.length > '.push.apple.com'.length) ||
      host === 'fcm.googleapis.com' ||
      host === 'updates.push.services.mozilla.com' ||
      (host.endsWith('.notify.windows.com') && host.length > '.notify.windows.com'.length);
    if (!service) return false;
    if (typeof vapid !== 'string' || vapid.length > limits.ringVapidMax || !VAPID.test(vapid))
      return false;
    if (typeof ttl !== 'number' || !Number.isInteger(ttl) || ttl < 0 || ttl > limits.ringTtlMax)
      return false;
    if (!['very-low', 'low', 'normal', 'high'].includes(dringlichkeit as string)) return false;
    const bytes = readBase64url(inhalt, limits.ringContentMax);
    return !!bytes && bytes.length > 0;
  }

  const control: TestControl = {
    reset,
    advanceTime(ms) {
      offset += ms;
    },
    setLimits(l) {
      limits = { ...limits, ...l };
    },
    setPushResult(r) {
      pushResult = r;
    },
  };

  /** A `fetch` that calls the server directly. */
  const fetchFn = async (input: string, init: RequestInit = {}): Promise<Response> => {
    const signal = init.signal ?? undefined;
    if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
    const url = new URL(input);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init.headers ?? {}) as Record<string, string>)) {
      headers[k.toLowerCase()] = v;
    }
    const body =
      typeof init.body === 'string' ? new TextEncoder().encode(init.body) : new Uint8Array(0);
    const result = await handle({
      method: (init.method ?? 'GET').toUpperCase(),
      path: url.pathname + url.search + url.hash,
      headers,
      body,
    });
    return new Response(result.status === 204 ? null : result.body, {
      status: result.status,
      headers: result.headers as Record<string, string>,
    });
  };

  return { handle, fetch: fetchFn, control, now };
}
