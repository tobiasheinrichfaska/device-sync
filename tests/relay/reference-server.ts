// An in-memory REFERENCE server of the relay protocol, version 1, written from docs/relay-protocol.md
// and nothing else: the conformance cases and the client are tested against it in CI. It has no
// sockets (a `fetch` function calls it directly), an injectable clock, and the OPTIONAL test
// interface of the specification ("Test interface"): reset, advance time, lower limits, stand in for
// the push service. `defect` switches on one deliberate fault, so a test can show that the
// conformance runner notices it.
import { createHmac, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { RELAY_LIMITS, type RelayLimits } from '../../src/relay/limits.ts';

export interface RefApp {
  readonly origins: readonly string[];
  /** Raw public keys (87 characters base64url) of the login scripts; empty = no proofs. */
  readonly proofKeys: readonly string[];
  readonly invitations: boolean;
  /** How many groups the app may open; 0 = no new device is taken at all. */
  readonly groups: number;
  readonly blocked?: readonly string[];
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
  | 'preflight-for-all';

export interface RefConfig {
  readonly secret: Uint8Array;
  readonly apps: Readonly<Record<string, RefApp>>;
  readonly now?: () => number;
  readonly limits?: Partial<RelayLimits>;
  readonly defect?: Defect;
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
  let known = new Map<string, Set<string>>();

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

  function register(app: string, device: string): void {
    let set = known.get(app);
    if (!set) known.set(app, (set = new Set()));
    if (set.size < limits.devicesPerApp * 2) set.add(device);
  }
  const devicesTotal = (): number => [...known.values()].reduce((s, x) => s + x.size, 0);

  // ── enrolment ─────────────────────────────────────────────────────────────────────────────────
  function enrol(body: unknown, origin: string): RefResponse {
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
    const devices = known.get(appName);
    if ((devices?.size ?? 0) === 0 && app.groups <= 0) return err('aufnahme-geschlossen', origin);
    if (devicesTotal() >= limits.devicesTotal) return err('relay-voll', origin);
    if ((devices?.size ?? 0) >= limits.devicesPerApp) return err('geraete-voll', origin);
    const per = byInvitation ? limits.enrolInvitePerHour : limits.enrolProofPerHour;
    if (!allow(`${byInvitation ? 'ei' : 'en'}|${appName}`, 3_600_000, per)) {
      return err('zu-viele-einschreibungen', origin);
    }
    used.set(mark, endS * 1000);
    const device = `geraet-${randomBytes(16).toString('hex')}`;
    register(appName, device);
    const access = issueAccess(appName, device, nowS);
    return ok(201, { geraet: device, zugang: access.text, bis: isoDay(access.end) }, origin);
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
      return ok(200, { ok: true, stand: 'reference' }, knownOrigin);
    }
    const endpoint = [
      'ping',
      'einschreiben',
      'erneuern',
      'einladen',
      'ablegen',
      'abholen',
      'klingeln',
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
          'Access-Control-Allow-Headers': 'authorization, content-type',
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

    let me: { app: string; device: string } | undefined;
    if (endpoint !== 'einschreiben') {
      const auth = h['authorization'];
      if (!auth?.startsWith('Bearer ')) return err('zugang-fehlt', knownOrigin);
      const text = auth.slice('Bearer '.length);
      const named = NAMED_APP.exec(text)?.[1];
      if (named && config.apps[named] && !config.apps[named]?.origins.includes(knownOrigin)) {
        return err('herkunft');
      }
      const m = ACCESS.exec(text);
      if (!m) return err('zugang-ungueltig', knownOrigin);
      const head = `z1.${m[1]}.${m[2]}.${m[3]}`;
      if (!same(m[4] as string, mac(head, 'zugang'))) return err('zugang-ungueltig', knownOrigin);
      if (Number(m[3]) <= Math.floor(now() / 1000)) {
        return err(
          defect === 'expired-as-invalid' ? 'zugang-ungueltig' : 'zugang-abgelaufen',
          knownOrigin,
        );
      }
      const app = config.apps[m[1] as string];
      if (!app) return err('app-unbekannt', knownOrigin);
      if (!app.origins.includes(knownOrigin)) return err('herkunft');
      if (app.blocked?.includes(m[2] as string)) return err('gesperrt', knownOrigin);
      me = { app: m[1] as string, device: m[2] as string };
      if (!allow(`req|${me.app}|${me.device}`, 60_000, limits.requestsPerMinute)) {
        return err('zu-viele-anfragen', knownOrigin);
      }
    }
    if (req.body.length > maxBody) return err('zu-gross', knownOrigin);
    let raw: unknown;
    try {
      raw = JSON.parse(Buffer.from(req.body).toString('utf8'));
    } catch {
      return err('unlesbar', knownOrigin);
    }
    if (endpoint === 'einschreiben') return enrol(raw, knownOrigin);
    if (!me) return err('zugang-fehlt', knownOrigin);
    register(me.app, me.device);
    const t = now();
    const scopeKey = (device: string): string => `${me.app}|${device}`;
    switch (endpoint) {
      case 'ping': {
        const strict = defect === 'unknown-member-ok' ? isObject(raw) : only(raw, []);
        if (!strict) return err('unlesbar', knownOrigin);
        const end = Number(ACCESS.exec((h['authorization'] as string).slice(7))?.[3]);
        return ok(200, { geraet: me.device, app: me.app, bis: isoDay(end) }, knownOrigin);
      }
      case 'erneuern': {
        if (!only(raw, [])) return err('unlesbar', knownOrigin);
        const a = issueAccess(me.app, me.device, Math.floor(t / 1000));
        return ok(200, { zugang: a.text, bis: isoDay(a.end) }, knownOrigin);
      }
      case 'einladen': {
        if (!only(raw, [])) return err('unlesbar', knownOrigin);
        if (!config.apps[me.app]?.invitations) return err('einladen-aus', knownOrigin);
        if (!allow(`inv|${me.app}|${me.device}`, 3_600_000, limits.invitePerHour)) {
          return err('zu-viele-einladungen', knownOrigin);
        }
        const bis = Math.floor(t / 1000) + limits.invitationSeconds;
        const head = `e1.${me.app}.${bis}.${randomBytes(16).toString('base64url')}`;
        return ok(
          201,
          { einladung: `${head}.${mac(head, 'einladung')}`, gueltigS: limits.invitationSeconds },
          knownOrigin,
        );
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
