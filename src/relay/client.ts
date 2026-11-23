// Client of the relay (docs/relay-protocol.md). `fetch` and the credential store are injected, so it
// runs in a browser, a WebView and a Node test alike. Protocol errors are RESULTS with an error kind,
// never exceptions; the client acts on the kind, never on the relay's text; the access never appears
// in a result, an error or a log. Retries are bounded, with backoff, and only for kinds the protocol
// calls retryable (and, for a request that is not safe to repeat, only where nothing was stored).
import { base64url } from '../core/encoding.ts';
import { kindOfToken, LOCAL_KINDS, type KindClass, type LocalKind } from './kinds.ts';
import { ENDPOINTS, RECOMMENDED_POLL, RELAY_LIMITS } from './limits.ts';
import {
  readBlockAnswer,
  readCertificate,
  readDevicesAnswer,
  readEnrolAnswerR2,
  readPingAnswerR2,
  readFounderTicket,
  readInvitationR2,
  readRenewAnswerR2,
  readUpgradeAnswer,
  RELAY_GROUP,
  RELAY_ROLE,
  type DevicesAnswer,
  type RelayInfo,
} from './admission.ts';
import {
  DEFAULT_HEADER_NAMES,
  isHeaderName,
  isRawPublicKey,
  possessionValue,
  type PossessionSigner,
  type RelayHeaderNames,
} from './possession.ts';
import {
  RELAY_DEVICE_ID,
  MAX_COLLECT_TEXT,
  readAccess,
  readCollectAnswer,
  readDropAnswer,
  readEnrolAnswer,
  readErrorBody,
  readHealthAnswer,
  readInviteAnswer,
  readRenewAnswer,
  readRingAnswer,
  readStoredState,
  writeBlockedMark,
  writeStoredCredentials,
  type CollectAnswer,
  type CollectedMessage,
  type HealthAnswer,
  type InviteAnswer,
  type StoredCredentials,
  type StoredState,
} from './readers.ts';

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** Where the client keeps its credentials: one text. Injected; the package assumes no `localStorage`. */
export interface CredentialStore {
  get(): Promise<string | undefined> | string | undefined;
  set(text: string): Promise<void> | void;
  remove(): Promise<void> | void;
}

/**
 * How a new device gets in. Version 1: a proof of the login script of a test zone, or an invitation
 * `e1` of a device. Revision 2 adds an invitation `e2` (the role and the group come with it), a
 * founder ticket and a developer password (both need the device key, `signer`). `role` is a claim
 * of the new device and is taken only by the old ways (proof, `e1`); the relay cannot check it, so
 * it gives such a device no right to block or list others.
 */
export type Enrolment =
  | { readonly proof: string; readonly role?: string }
  | { readonly invitation: string; readonly role?: string }
  | { readonly founder: string }
  | { readonly password: string; readonly group: string };

/** What an enrolment or the step to a certificate tells the caller. */
export interface EnrolValue {
  readonly device: string;
  readonly until: string;
  /** Certificate only. */
  readonly group?: string;
  readonly role?: string;
  /** What the relay said about itself (revision 2). */
  readonly info?: RelayInfo;
}

/** What a client learns about the revision of the relay. */
export interface RelayRevision {
  /** 1 = version 1 only (nothing said), 2 and up = the admission revision. */
  readonly revision: number;
  readonly abilities: readonly string[];
  readonly procedures?: RelayInfo['procedures'];
}

/** Told once to `onBlocked`: this device's own credential was refused as blocked. */
export interface BlockedInfo {
  readonly device: string;
  /** The day (UTC) the client noted it. */
  readonly day: string;
}

export interface RelayClientOptions {
  /** `https://host` (plain `http` only for localhost); no path, no query. */
  readonly baseUrl: string;
  readonly appId: string;
  readonly fetch: FetchLike;
  readonly store: CredentialStore;
  /** Milliseconds since 1970 (a parameter: no clock is read inside the client). */
  readonly clock: () => number;
  /** Sent as the `Origin` header. Browsers set it themselves and ignore this. */
  readonly origin?: string;
  /** Per attempt. Default 15 000. */
  readonly timeoutMs?: number;
  /** Attempts per call including the first. Default 3. */
  readonly maxAttempts?: number;
  readonly backoffBaseMs?: number;
  readonly backoffCapMs?: number;
  /** Waits; rejects when the signal aborts. Default: a timer. */
  readonly sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  /** In [0, 1): jitter of the backoff. Default `Math.random`. */
  readonly random?: () => number;
  /** Called when the access is of no use any more; a returned enrolment makes the client enrol again once and retry. */
  readonly reenrol?: () => Promise<Enrolment | undefined> | Enrolment | undefined;
  readonly poll?: { readonly busyMs: number; readonly idleMs: number };
  /**
   * Revision 2: signs for this device (its key is certified by the relay). Without it the client
   * speaks version 1 and nothing else. A stored certificate whose key is not this signer's is of no
   * use (`key-missing`, class `reenrol`).
   */
  readonly signer?: PossessionSigner;
  /** The names of the two headers of revision 2; default `DEFAULT_HEADER_NAMES`. */
  readonly headers?: RelayHeaderNames;
  /**
   * Called once when the relay answers a request that carried THIS device's current credential with
   * `gesperrt`, and when the relay confirms this device blocked itself. Never for a network failure,
   * a timeout, another refusal or a credential that is no longer the stored one. By then the client
   * has stored the blocked mark and refuses to enrol again until `forget()`; the package wipes
   * nothing (keys, data and screens are the app's to deal with in this hook).
   */
  readonly onBlocked?: (info: BlockedInfo) => void | Promise<void>;
}

export interface RelayFailure {
  readonly ok: false;
  /** The English name of the relay's kind, or a local kind (`network`, `timeout`, `aborted`, …). */
  readonly kind: string;
  /** The wire word, when the relay sent one. */
  readonly token: string | null;
  readonly status: number | null;
  readonly class: KindClass;
  readonly retryAfterMs: number | null;
  readonly attempts: number;
}

export type RelayResult<T> = { readonly ok: true; readonly value: T } | RelayFailure;

export type DropResult =
  | { readonly device: string; readonly ok: true; readonly present: boolean }
  | {
      readonly device: string;
      readonly ok: false;
      readonly kind: string;
      readonly token: string;
      readonly class: KindClass;
      readonly retryAfterMs: number | null;
    };

export interface DropValue {
  /** In the order of the recipients given. */
  readonly results: readonly DropResult[];
  /** The same by device id (no prototype). */
  readonly byDevice: Readonly<Record<string, DropResult>>;
}

export interface CollectOptions {
  readonly ask?: readonly string[];
  readonly signal?: AbortSignal;
}

export interface CollectAllOptions extends CollectOptions {
  /** Calls of one `collectAll`. Default 10. */
  readonly maxCalls?: number;
  /** Messages and content bytes of one `collectAll`; it stops after the call that reaches them. */
  readonly maxMessages?: number;
  readonly maxBytes?: number;
}

export interface CollectAllValue {
  readonly messages: readonly CollectedMessage[];
  readonly present: readonly string[];
  /** True when the relay still held messages when the loop stopped (a bound was reached or a later call failed). */
  readonly more: boolean;
  /** Set when a later call failed: the messages above were collected (and are gone from the relay). */
  readonly interrupted?: RelayFailure;
}

export interface RingRequest {
  readonly endpoint: string;
  readonly vapid: string;
  readonly ttl: number;
  readonly urgency: 'very-low' | 'low' | 'normal' | 'high';
  readonly content: Uint8Array;
}

/** `none`: nothing stored; `ready`; `stale`: stored but the relay refused it; `blocked`: the blocked mark is stored. */
export type CredentialState = 'none' | 'ready' | 'stale' | 'blocked';

interface Spec<T> {
  readonly endpoint: string;
  readonly method: 'GET' | 'POST';
  readonly body?: string;
  readonly auth: boolean;
  readonly status: number;
  readonly maxChars: number;
  readonly read: (text: string, creds: StoredCredentials | undefined) => T | undefined;
  /** Whether repeating the request after an unclear outcome is harmless. */
  readonly repeatable: boolean;
  readonly signal?: AbortSignal | undefined;
  /** Announce the protocol revision in the version header even for an access without a certificate. */
  readonly announce?: boolean;
}

const PROOF = /^n1\.[A-Za-z0-9_-]{1,400}\.[A-Za-z0-9_-]{86}$/;
const INVITATION =
  /^e1\.[a-z][a-z0-9]{1,15}\.[1-9][0-9]{0,11}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;
/** The protocol revision this client speaks and announces. */
const REVISION = 2;
const URGENCIES = ['very-low', 'low', 'normal', 'high'];
/** Kinds after which nothing was stored or changed: safe to repeat even a drop or an enrolment. */
const NOTHING_DONE = new Set(['rate-limited', 'relay-busy', 'body-too-slow']);

const failure = (
  kind: string,
  cls: KindClass,
  attempts: number,
  token: string | null = null,
  status: number | null = null,
  retryAfterMs: number | null = null,
): RelayFailure => ({ ok: false, kind, token, status, class: cls, retryAfterMs, attempts });

const local = (kind: LocalKind, attempts = 0, status: number | null = null): RelayFailure =>
  failure(kind, LOCAL_KINDS[kind].class, attempts, null, status, LOCAL_KINDS[kind].retryAfterMs);

const defaultSleep = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('aborted'));
    const timer = globalThis.setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      globalThis.clearTimeout(timer);
      reject(new Error('aborted'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });

/** The day `YYYY-MM-DD` (UTC) of a time in ms. */
const dayOf = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

/** Whole days from `fromDay` to `toDay` (both `YYYY-MM-DD`). */
const daysBetween = (fromDay: string, toDay: string): number =>
  Math.round((Date.parse(`${toDay}T00:00:00Z`) - Date.parse(`${fromDay}T00:00:00Z`)) / 86_400_000);

/** The text of a response body, read with a bound: undefined when it is longer or not UTF-8. */
async function readBody(response: Response, maxChars: number): Promise<string | undefined> {
  const maxBytes = maxChars * 3;
  const announced = Number(response.headers.get('content-length'));
  if (Number.isFinite(announced) && announced > maxBytes) return undefined;
  try {
    const reader = response.body?.getReader();
    if (!reader) {
      const text = await response.text();
      return text.length > maxChars ? undefined : text;
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return undefined;
      }
      chunks.push(value);
    }
    const all = new Uint8Array(total);
    let at = 0;
    for (const c of chunks) {
      all.set(c, at);
      at += c.length;
    }
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(all);
  } catch {
    return undefined;
  }
}

export class RelayClient {
  private readonly base: string;
  private readonly timeoutMs: number;
  private readonly maxAttempts: number;
  private readonly backoffBaseMs: number;
  private readonly backoffCapMs: number;
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  private readonly random: () => number;
  private readonly pollBusyMs: number;
  private readonly pollIdleMs: number;
  /** The access text the relay last called of no use; while the store still holds it, calls fail at once. */
  private stale: string | undefined;
  private enrolling: Promise<RelayResult<EnrolValue>> | undefined;
  private renewing: Promise<RelayResult<{ until: string; info?: RelayInfo }>> | undefined;
  private reenrolFlight: Promise<boolean> | undefined;
  private readonly headerNames: RelayHeaderNames;
  /** Devices the hook was told about (once each). */
  private readonly told = new Set<string>();

  constructor(private readonly o: RelayClientOptions) {
    let url: URL;
    try {
      url = new URL(o.baseUrl);
    } catch {
      throw new TypeError('baseUrl is not a URL');
    }
    const localhost = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && localhost)) {
      throw new TypeError('baseUrl must be https (http only for localhost)');
    }
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/') {
      throw new TypeError('baseUrl must be an origin without path, query or login');
    }
    if (typeof o.appId !== 'string' || !/^[a-z][a-z0-9]{1,15}$/.test(o.appId)) {
      throw new TypeError('invalid appId');
    }
    if (o.signer !== undefined && !isRawPublicKey(o.signer.publicKey)) {
      throw new TypeError('the signer needs a raw uncompressed P-256 public key');
    }
    const names = o.headers ?? DEFAULT_HEADER_NAMES;
    if (
      !isHeaderName(names.possession) ||
      !isHeaderName(names.version) ||
      names.possession === names.version
    ) {
      throw new TypeError('invalid header names');
    }
    this.headerNames = names;
    this.base = url.origin;
    this.timeoutMs = o.timeoutMs ?? 15_000;
    this.maxAttempts = Math.max(1, Math.min(10, o.maxAttempts ?? 3));
    this.backoffBaseMs = o.backoffBaseMs ?? 1_000;
    this.backoffCapMs = o.backoffCapMs ?? 30_000;
    this.sleep = o.sleep ?? defaultSleep;
    this.random = o.random ?? Math.random;
    this.pollBusyMs = Math.max(RECOMMENDED_POLL.minMs, o.poll?.busyMs ?? RECOMMENDED_POLL.busyMs);
    this.pollIdleMs = Math.max(this.pollBusyMs, o.poll?.idleMs ?? RECOMMENDED_POLL.idleMs);
  }

  // ── credentials ─────────────────────────────────────────────────────────────────────────────────

  private async loadState(): Promise<StoredState | undefined | 'storage'> {
    try {
      const text = await this.o.store.get();
      return text === undefined ? undefined : readStoredState(text, this.o.appId);
    } catch {
      return 'storage';
    }
  }

  private async credentials(): Promise<StoredCredentials | undefined | 'storage' | 'blocked'> {
    const s = await this.loadState();
    if (s === undefined || s === 'storage') return s;
    return s.kind === 'blocked' ? 'blocked' : s.credentials;
  }

  /** `none`: nothing stored (or unreadable); `stale`: stored but the relay refused it; `blocked`: the blocked mark; `ready` otherwise. */
  async state(): Promise<CredentialState> {
    const c = await this.credentials();
    if (c === 'blocked') return 'blocked';
    if (c === undefined || c === 'storage') return 'none';
    return this.stale === c.access ? 'stale' : 'ready';
  }

  /** This device's id, when enrolled (not when it is marked blocked). */
  async deviceId(): Promise<string | undefined> {
    const c = await this.credentials();
    return c === undefined || c === 'storage' || c === 'blocked' ? undefined : c.device;
  }

  /**
   * The relay refused THIS device's credential as blocked (or confirmed that it blocked itself):
   * the blocked mark replaces the credentials and the hook runs, once. Ignored when the store holds
   * another credential by now (an earlier enrolment refused late), nothing, or the mark already.
   */
  private async noteBlocked(creds: StoredCredentials): Promise<void> {
    const state = await this.loadState();
    if (state !== 'storage') {
      if (state === undefined || state.kind === 'blocked') return;
      if (state.credentials.access !== creds.access) return;
    }
    if (this.told.has(creds.device)) return;
    this.told.add(creds.device);
    const day = dayOf(this.o.clock());
    try {
      await this.o.store.set(writeBlockedMark(creds.device, day));
    } catch {
      // The mark could not be stored: the hook still runs once; the next start asks the relay again.
    }
    this.stale = undefined;
    const hook = this.o.onBlocked;
    if (!hook) return;
    try {
      await hook({ device: creds.device, day });
    } catch {
      // A hook that fails does not break the client; the mark is stored.
    }
  }

  /** Forgets the credentials (the store's `remove`). */
  async forget(): Promise<RelayResult<null>> {
    try {
      await this.o.store.remove();
    } catch {
      return local('storage');
    }
    this.stale = undefined;
    return { ok: true, value: null };
  }

  // ── transport ───────────────────────────────────────────────────────────────────────────────────

  private delayFor(attempt: number, hint: number | null): number {
    const backoff = this.backoffBaseMs * 2 ** (attempt - 1) * (0.5 + this.random() / 2);
    return Math.max(
      RECOMMENDED_POLL.minMs,
      Math.min(this.backoffCapMs, Math.max(backoff, hint ?? 0)),
    );
  }

  private retryable(f: RelayFailure, repeatable: boolean): boolean {
    if (f.class !== 'retry') return false;
    if (repeatable) return true;
    return NOTHING_DONE.has(f.kind);
  }

  /** One attempt: the request, the status, the body. */
  private async attempt<T>(spec: Spec<T>, attempts: number): Promise<RelayResult<T>> {
    let creds: StoredCredentials | undefined;
    if (spec.auth) {
      const c = await this.credentials();
      if (c === 'storage') return local('storage', attempts);
      if (c === 'blocked') return local('blocked-mark', attempts);
      if (c === undefined || this.stale === c.access) return local('no-credentials', attempts);
      creds = c;
    }
    const headers: Record<string, string> = {};
    if (spec.method === 'POST') headers['Content-Type'] = 'application/json';
    if (creds) {
      headers['Authorization'] = `Bearer ${creds.access}`;
      const cert = readCertificate(creds.access);
      if (cert) {
        // A certificate is worth nothing without the proof of possession: signed for this very
        // request, with the key the certificate names.
        const signer = this.o.signer;
        if (!signer || signer.publicKey !== cert.key) return local('key-missing', attempts);
        const value = await possessionValue({
          signer,
          method: spec.method,
          path: `/${spec.endpoint}`,
          body: spec.body ?? '',
          certificate: creds.access,
          nowMs: this.o.clock(),
        });
        if (value === undefined) return local('key-missing', attempts);
        headers[this.headerNames.possession] = value;
        headers[this.headerNames.version] = String(REVISION);
      } else if (spec.announce) {
        headers[this.headerNames.version] = String(REVISION);
      }
    }
    if (this.o.origin) headers['Origin'] = this.o.origin;
    const controller = new AbortController();
    let timedOut = false;
    const timer = globalThis.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.timeoutMs);
    const onCallerAbort = (): void => controller.abort();
    if (spec.signal?.aborted) controller.abort();
    else spec.signal?.addEventListener('abort', onCallerAbort, { once: true });
    try {
      let response: Response;
      try {
        response = await this.o.fetch(`${this.base}/${spec.endpoint}`, {
          method: spec.method,
          headers,
          ...(spec.body === undefined ? {} : { body: spec.body }),
          credentials: 'omit',
          cache: 'no-store',
          redirect: 'error',
          referrerPolicy: 'no-referrer',
          mode: 'cors',
          signal: controller.signal,
        });
      } catch {
        if (spec.signal?.aborted) return local('aborted', attempts);
        return local(timedOut ? 'timeout' : 'network', attempts);
      }
      // `redirect: 'error'` is the rule; a fetch that followed a redirect anyway gives an answer of another
      // address, which is not the relay's.
      if (response.redirected === true || !this.sameOrigin(response.url)) {
        await response.body?.cancel().catch(() => undefined);
        return local('malformed', attempts, response.status);
      }
      const text = await readBody(response, spec.maxChars);
      if (spec.signal?.aborted) return local('aborted', attempts);
      if (text === undefined) {
        if (timedOut) return local('timeout', attempts, response.status);
        return local('malformed', attempts, response.status);
      }
      if (response.status === spec.status) {
        const value = spec.read(text, creds);
        return value === undefined
          ? local('malformed', attempts, response.status)
          : { ok: true, value };
      }
      const failed = this.failureOf(response.status, text, creds, attempts);
      // Only the relay's own 403 with this very word counts, and only for the credential this request carried.
      if (creds && failed.token === 'gesperrt' && failed.status === 403)
        await this.noteBlocked(creds);
      return failed;
    } finally {
      globalThis.clearTimeout(timer);
      spec.signal?.removeEventListener('abort', onCallerAbort);
    }
  }

  /** Whether the address of an answer is the relay's origin (an empty one, as a mock gives, is not judged). */
  private sameOrigin(url: unknown): boolean {
    if (typeof url !== 'string' || url === '') return true;
    try {
      return new URL(url).origin === this.base;
    } catch {
      return false;
    }
  }

  private failureOf(
    status: number,
    text: string,
    creds: StoredCredentials | undefined,
    attempts: number,
  ): RelayFailure {
    const body = readErrorBody(text);
    if (!body) {
      // A gateway or proxy in front of the relay: no protocol body.
      return status === 408 || status === 429 || (status >= 500 && status <= 599)
        ? local('unavailable', attempts, status)
        : local('malformed', attempts, status);
    }
    const kind = kindOfToken(body.token);
    if (!kind) {
      // A word this version does not know: only the status says what to do.
      return status === 429 || (status >= 500 && status <= 599)
        ? local('unavailable', attempts, status)
        : local('malformed', attempts, status);
    }
    if (kind.status === null || kind.status !== status) return local('malformed', attempts, status);
    if (kind.class === 'reenrol' && creds) this.stale = creds.access;
    return failure(kind.name, kind.class, attempts, kind.token, status, kind.retryAfterMs);
  }

  /** The call with bounded retries, and one re-enrolment when the access is no use any more. */
  private async call<T>(spec: Spec<T>): Promise<RelayResult<T>> {
    let attempts = 0;
    let reenrolled = false;
    for (;;) {
      attempts += 1;
      const r = await this.attempt(spec, attempts);
      if (r.ok) return r;
      if (r.class === 'reenrol' && spec.auth && !reenrolled && this.o.reenrol) {
        reenrolled = true;
        const again = await this.runReenrol(spec.signal);
        if (again) {
          attempts -= 1;
          continue;
        }
        return r;
      }
      if (attempts >= this.maxAttempts || !this.retryable(r, spec.repeatable)) return r;
      try {
        await this.sleep(this.delayFor(attempts, r.retryAfterMs), spec.signal);
      } catch {
        return local('aborted', attempts);
      }
    }
  }

  /** One re-enrolment at a time: calls that fail together share it (one proof is used, not several). */
  private runReenrol(signal: AbortSignal | undefined): Promise<boolean> {
    if (this.reenrolFlight) return this.reenrolFlight;
    const p = (async (): Promise<boolean> => {
      let enrolment: Enrolment | undefined;
      try {
        enrolment = await this.o.reenrol?.();
      } catch {
        return false;
      }
      if (!enrolment) return false;
      const r = await this.enrol(enrolment, signal === undefined ? {} : { signal });
      return r.ok;
    })().finally(() => {
      this.reenrolFlight = undefined;
    });
    this.reenrolFlight = p;
    return p;
  }

  // ── endpoints ───────────────────────────────────────────────────────────────────────────────────

  /** `GET /gesund`: no access needed. */
  health(opts: { signal?: AbortSignal } = {}): Promise<RelayResult<HealthAnswer>> {
    return this.call({
      endpoint: ENDPOINTS.health,
      method: 'GET',
      auth: false,
      status: 200,
      maxChars: 60_000,
      read: (t) => readHealthAnswer(t),
      repeatable: true,
      signal: opts.signal,
    });
  }

  /**
   * Enrols this device and stores what the relay gives (an access, or with a `signer` a certificate).
   * One enrolment at a time: a second call while one runs gets the same answer. A proof, an
   * invitation, a founder ticket works once, so a lost answer is not retried (`already-used`
   * follows): the caller fetches a new one. A device that is marked blocked does not enrol itself
   * back (`blocked-mark`): the app calls `forget()` when the person chose to start again.
   */
  enrol(how: Enrolment, opts: { signal?: AbortSignal } = {}): Promise<RelayResult<EnrolValue>> {
    if (this.enrolling) return this.enrolling;
    const p = this.doEnrol(how, opts.signal).finally(() => {
      this.enrolling = undefined;
    });
    this.enrolling = p;
    return p;
  }

  /** The member, the text and what the way allows; undefined when the argument is not shaped as the protocol says. */
  private wayOf(
    how: Enrolment,
  ): { member: string; text: string; old: boolean; role?: string; group?: string } | undefined {
    const appId = this.o.appId;
    const roleOk = (r: unknown): string | undefined =>
      r === undefined ? undefined : typeof r === 'string' && RELAY_ROLE.test(r) ? r : '';
    if ('proof' in how) {
      const role = roleOk(how.role);
      if (typeof how.proof !== 'string' || !PROOF.test(how.proof) || role === '') return undefined;
      return { member: 'nachweis', text: how.proof, old: true, ...(role ? { role } : {}) };
    }
    if ('invitation' in how) {
      const text = how.invitation;
      if (typeof text !== 'string') return undefined;
      if (text.startsWith('e2.')) {
        const e = readInvitationR2(text);
        if (!e || e.app !== appId || how.role !== undefined) return undefined;
        return { member: 'einladung', text, old: false };
      }
      const role = roleOk(how.role);
      if (!INVITATION.test(text) || role === '') return undefined;
      return { member: 'einladung', text, old: true, ...(role ? { role } : {}) };
    }
    if ('founder' in how) {
      const g = readFounderTicket(how.founder);
      if (!g || g.app !== appId || !this.o.signer) return undefined;
      return { member: 'gruender', text: how.founder, old: false };
    }
    if ('password' in how) {
      const pw = how.password;
      if (typeof pw !== 'string' || pw.length < 1 || pw.length > 200 || /\p{Cc}/u.test(pw)) {
        return undefined;
      }
      if (typeof how.group !== 'string' || !RELAY_GROUP.test(how.group) || !this.o.signer) {
        return undefined;
      }
      return { member: 'passwort', text: pw, old: false, group: how.group };
    }
    return undefined;
  }

  private async doEnrol(
    how: Enrolment,
    signal: AbortSignal | undefined,
  ): Promise<RelayResult<EnrolValue>> {
    const state = await this.loadState();
    if (state !== 'storage' && state?.kind === 'blocked') return local('blocked-mark');
    const way = this.wayOf(how);
    if (!way) return local('bad-argument');
    const signer = this.o.signer;
    const request = (withKey: boolean) => {
      const body: Record<string, string> = { [way.member]: way.text };
      if (way.group !== undefined) {
        body['app'] = this.o.appId;
        body['mandant'] = way.group;
      }
      if (withKey && signer) body['geraetSchluessel'] = signer.publicKey;
      if (withKey && way.role !== undefined) body['rolle'] = way.role;
      return this.call<{ creds: StoredCredentials; info?: RelayInfo }>({
        endpoint: `v1/${ENDPOINTS.enrol}`,
        method: 'POST',
        body: JSON.stringify(body),
        auth: false,
        status: 201,
        maxChars: 60_000,
        read: (t) => {
          if (withKey && signer) {
            const a = readEnrolAnswerR2(t, this.o.appId, signer.publicKey);
            return a
              ? {
                  creds: {
                    device: a.device,
                    access: a.access,
                    until: a.until,
                    group: a.group,
                    role: a.role,
                  },
                  ...(a.info ? { info: a.info } : {}),
                }
              : undefined;
          }
          const a = readEnrolAnswer(t, this.o.appId);
          return a ? { creds: { device: a.device, access: a.access, until: a.until } } : undefined;
        },
        repeatable: false,
        signal,
      });
    };
    let r = await request(signer !== undefined);
    // A relay of version 1 does not know the key and refuses the unknown member before it takes
    // the proof or invitation: once more without key and role, for the old ways only.
    if (!r.ok && signer && way.old && r.kind === 'unreadable') r = await request(false);
    if (!r.ok) return r;
    try {
      await this.o.store.set(writeStoredCredentials(r.value.creds));
    } catch {
      return local('storage', 1);
    }
    this.stale = undefined;
    this.told.delete(r.value.creds.device);
    const c = r.value.creds;
    return {
      ok: true,
      value: {
        device: c.device,
        until: c.until,
        ...(c.group !== undefined ? { group: c.group } : {}),
        ...(c.role !== undefined ? { role: c.role } : {}),
        ...(r.value.info ? { info: r.value.info } : {}),
      },
    };
  }

  /** `ping`: whether the access is good, and until when. With a certificate it also says the group and the role. */
  ping(opts: { signal?: AbortSignal } = {}): Promise<
    RelayResult<{
      device: string;
      until: string;
      group?: string;
      role?: string;
      info?: RelayInfo;
    }>
  > {
    return this.pingWith(false, opts.signal);
  }

  private pingWith(announce: boolean, signal?: AbortSignal) {
    return this.call({
      endpoint: `v1/${ENDPOINTS.ping}`,
      method: 'POST',
      body: '{}',
      auth: true,
      status: 200,
      maxChars: 60_000,
      announce,
      read: (t, creds) => {
        const a = readPingAnswerR2(t);
        if (!a || a.app !== this.o.appId || a.device !== creds?.device) return undefined;
        const cert = readCertificate(creds.access);
        // What a relay says about itself only comes to a client that announced its revision.
        if (a.info && !cert && !announce) return undefined;
        // A certificate's ping names its group and role, and they must be the certificate's.
        if (cert && (a.group !== cert.group || a.role !== cert.role)) return undefined;
        if (!cert && (a.group !== undefined || a.role !== undefined)) return undefined;
        return {
          device: a.device,
          until: a.until,
          ...(a.group !== undefined ? { group: a.group } : {}),
          ...(a.role !== undefined ? { role: a.role } : {}),
          ...(a.info ? { info: a.info } : {}),
        };
      },
      repeatable: true,
      signal,
    });
  }

  /**
   * Which revision of the protocol the relay speaks, by what it says about itself: with a credential
   * a `ping` that announces this client's revision (a version-1 relay answers without `v`), without
   * one `GET /gesund`. A ping that fails as a network error without a certificate is tried once more
   * without the announcing header (a version-1 relay refuses unknown headers already at the
   * preflight). A relay that says nothing is revision 1.
   */
  async negotiate(opts: { signal?: AbortSignal } = {}): Promise<RelayResult<RelayRevision>> {
    const c = await this.credentials();
    if (c === 'blocked') return local('blocked-mark');
    const from = (info: RelayInfo | undefined): RelayRevision =>
      info
        ? {
            revision: info.revision,
            abilities: info.abilities,
            ...(info.procedures ? { procedures: info.procedures } : {}),
          }
        : { revision: 1, abilities: [] };
    if (c === undefined || c === 'storage' || this.stale === c.access) {
      const h = await this.health(opts);
      if (!h.ok) return h;
      return {
        ok: true,
        value: {
          revision: h.value.revision ?? 1,
          abilities: h.value.abilities ?? [],
          ...(h.value.procedures ? { procedures: h.value.procedures } : {}),
        },
      };
    }
    let r = await this.pingWith(true, opts.signal);
    if (!r.ok && r.kind === 'network' && !readCertificate(c.access)) {
      r = await this.pingWith(false, opts.signal);
    }
    return r.ok ? { ok: true, value: from(r.value.info) } : r;
  }

  /** `erneuern`: a new access or certificate for the same device, stored. One renewal at a time. */
  renew(
    opts: { signal?: AbortSignal } = {},
  ): Promise<RelayResult<{ until: string; info?: RelayInfo }>> {
    if (this.renewing) return this.renewing;
    const p = this.doRenew(opts.signal).finally(() => {
      this.renewing = undefined;
    });
    this.renewing = p;
    return p;
  }

  private async doRenew(
    signal: AbortSignal | undefined,
  ): Promise<RelayResult<{ until: string; info?: RelayInfo }>> {
    const r = await this.call<{ creds: StoredCredentials; info?: RelayInfo }>({
      endpoint: `v1/${ENDPOINTS.renew}`,
      method: 'POST',
      body: '{}',
      auth: true,
      status: 200,
      maxChars: 60_000,
      read: (t, creds) => {
        if (!creds) return undefined;
        const cert = readCertificate(creds.access);
        if (cert) {
          const a = readRenewAnswerR2(t, this.o.appId, cert);
          return a
            ? {
                creds: {
                  device: creds.device,
                  access: a.access,
                  until: a.until,
                  group: cert.group,
                  role: cert.role,
                },
                ...(a.info ? { info: a.info } : {}),
              }
            : undefined;
        }
        const a = readRenewAnswer(t, this.o.appId, creds.device);
        return a
          ? { creds: { device: creds.device, access: a.access, until: a.until } }
          : undefined;
      },
      repeatable: true,
      signal,
    });
    if (!r.ok) return r;
    try {
      await this.o.store.set(writeStoredCredentials(r.value.creds));
    } catch {
      return local('storage', 1);
    }
    this.stale = undefined;
    return {
      ok: true,
      value: { until: r.value.creds.until, ...(r.value.info ? { info: r.value.info } : {}) },
    };
  }

  /**
   * The step from an old access to a certificate (revision 2): the stored access asks `erneuern`
   * with this device's key (and a role it claims, which the relay cannot check). A version-1 relay
   * refuses the unknown member as `unreadable` and keeps the access. Needs a `signer`.
   */
  async upgrade(
    opts: { signal?: AbortSignal; role?: string } = {},
  ): Promise<RelayResult<EnrolValue>> {
    const signer = this.o.signer;
    const role = opts.role;
    if (!signer || (role !== undefined && !RELAY_ROLE.test(role))) return local('bad-argument');
    const c = await this.credentials();
    if (c === 'storage') return local('storage');
    if (c === 'blocked') return local('blocked-mark');
    if (c === undefined) return local('no-credentials');
    if (readCertificate(c.access)) return local('bad-argument');
    const r = await this.call<{ creds: StoredCredentials; info?: RelayInfo }>({
      endpoint: `v1/${ENDPOINTS.renew}`,
      method: 'POST',
      body: JSON.stringify({
        geraetSchluessel: signer.publicKey,
        ...(role !== undefined && role !== 'ohne' ? { rolle: role } : {}),
      }),
      auth: true,
      status: 200,
      maxChars: 60_000,
      read: (t, creds) => {
        if (!creds) return undefined;
        const a = readUpgradeAnswer(t, this.o.appId, creds.device, signer.publicKey);
        return a
          ? {
              creds: {
                device: a.device,
                access: a.access,
                until: a.until,
                group: a.group,
                role: a.role,
              },
              ...(a.info ? { info: a.info } : {}),
            }
          : undefined;
      },
      repeatable: true,
      signal: opts.signal,
    });
    if (!r.ok) return r;
    try {
      await this.o.store.set(writeStoredCredentials(r.value.creds));
    } catch {
      return local('storage', 1);
    }
    this.stale = undefined;
    const k = r.value.creds;
    return {
      ok: true,
      value: {
        device: k.device,
        until: k.until,
        ...(k.group !== undefined ? { group: k.group } : {}),
        ...(k.role !== undefined ? { role: k.role } : {}),
        ...(r.value.info ? { info: r.value.info } : {}),
      },
    };
  }

  /** Renews when fewer than 30 days of the access or certificate are left (by the stored end day and the clock). */
  async renewIfDue(
    opts: { signal?: AbortSignal } = {},
  ): Promise<RelayResult<{ renewed: boolean; until: string }>> {
    const c = await this.credentials();
    if (c === 'storage') return local('storage');
    if (c === 'blocked') return local('blocked-mark');
    if (c === undefined) return local('no-credentials');
    const left = daysBetween(dayOf(this.o.clock()), c.until);
    if (left >= RELAY_LIMITS.renewBelowDays)
      return { ok: true, value: { renewed: false, until: c.until } };
    const r = await this.renew(opts);
    return r.ok ? { ok: true, value: { renewed: true, until: r.value.until } } : r;
  }

  /**
   * `einladen`: an invitation another device can enrol with (10 minutes, once). With a certificate
   * it is an `e2` that carries the group and the role the invited device gets; `role` (default: none
   * for the office, its own for an `lb:<id>` device) is the inviter's choice and the relay refuses what
   * the inviter's role does not allow (`role-not-allowed`).
   */
  invite(opts: { signal?: AbortSignal; role?: string } = {}): Promise<RelayResult<InviteAnswer>> {
    if (opts.role !== undefined && !RELAY_ROLE.test(opts.role)) {
      return Promise.resolve(local('bad-argument'));
    }
    return this.call({
      endpoint: `v1/${ENDPOINTS.invite}`,
      method: 'POST',
      body: opts.role === undefined ? '{}' : JSON.stringify({ rolle: opts.role }),
      auth: true,
      status: 201,
      maxChars: 60_000,
      read: (t, creds) => {
        const a = readInviteAnswer(t, this.o.appId);
        if (!a) return undefined;
        // An `e2` only for a certificate, and made for this device's group; an old access gets an `e1`.
        const cert = creds ? readCertificate(creds.access) : undefined;
        if (
          a.group !== undefined &&
          (!cert || a.group !== cert.group || a.inviter !== cert.device)
        ) {
          return undefined;
        }
        if (a.group === undefined && cert) return undefined;
        return a;
      },
      repeatable: false,
      signal: opts.signal,
    });
  }

  /** `geraete` (revision 2, certificate only): the devices the relay lists for this group as this device's role may see them. */
  devices(opts: { signal?: AbortSignal } = {}): Promise<RelayResult<DevicesAnswer>> {
    return this.call({
      endpoint: `v1/${ENDPOINTS.devices}`,
      method: 'POST',
      body: '{}',
      auth: true,
      status: 200,
      maxChars: 300_000,
      read: (t) => readDevicesAnswer(t),
      repeatable: true,
      signal: opts.signal,
    });
  }

  /**
   * `sperren` (revision 2, certificate only): blocks a device of this group, as far as this device's
   * role allows (`role-not-allowed` otherwise). The relay keeps the block in RAM for 90 days, so
   * whoever blocks repeats it (`blockplan.ts`). When the device blocks ITSELF and the relay confirms,
   * the blocked mark is stored and `onBlocked` runs, as for a refusal.
   */
  async block(
    device: string,
    opts: { signal?: AbortSignal } = {},
  ): Promise<RelayResult<{ device: string }>> {
    if (typeof device !== 'string' || !RELAY_DEVICE_ID.test(device)) {
      return local('bad-argument');
    }
    const own = await this.credentials();
    const r = await this.call({
      endpoint: `v1/${ENDPOINTS.block}`,
      method: 'POST',
      body: JSON.stringify({ geraet: device }),
      auth: true,
      status: 200,
      maxChars: 60_000,
      read: (t) => (readBlockAnswer(t, device) ? { device } : undefined),
      repeatable: true,
      signal: opts.signal,
    });
    if (
      r.ok &&
      own !== undefined &&
      own !== 'storage' &&
      own !== 'blocked' &&
      own.device === device
    ) {
      await this.noteBlocked(own);
    }
    return r;
  }

  /**
   * `ablegen`: one message per recipient (1 to 50, each once, not this device), each 1 to 64 KB. A
   * refusal of one recipient is a result of that recipient, the others may be stored. A drop is
   * repeated only when nothing was stored (rate limit, busy, slow body), never after an unclear outcome.
   */
  async drop(
    recipients: readonly { readonly device: string; readonly content: Uint8Array }[],
    opts: { signal?: AbortSignal } = {},
  ): Promise<RelayResult<DropValue>> {
    if (!Array.isArray(recipients) || recipients.length < 1) return local('bad-argument');
    if (recipients.length > RELAY_LIMITS.maxRecipients) return local('bad-argument');
    const own = await this.deviceId();
    const seen = new Set<string>();
    for (const r of recipients) {
      if (!r || typeof r.device !== 'string' || !RELAY_DEVICE_ID.test(r.device))
        return local('bad-argument');
      if (!(r.content instanceof Uint8Array)) return local('bad-argument');
      if (r.content.length < 1 || r.content.length > RELAY_LIMITS.maxContentBytes) {
        return local('bad-argument');
      }
      if (seen.has(r.device) || r.device === own) return local('bad-argument');
      seen.add(r.device);
    }
    const ids = recipients.map((r) => r.device);
    const body = JSON.stringify({
      an: recipients.map((r) => ({ geraet: r.device, inhalt: base64url(r.content) })),
    });
    const r = await this.call({
      endpoint: `v1/${ENDPOINTS.drop}`,
      method: 'POST',
      body,
      auth: true,
      status: 200,
      maxChars: 60_000,
      read: (t) => readDropAnswer(t, ids),
      repeatable: false,
      signal: opts.signal,
    });
    if (!r.ok) return r;
    const byDevice = Object.create(null) as Record<string, DropResult>;
    const results = r.value.map((e): DropResult => {
      let item: DropResult;
      if (e.ok) item = { device: e.device, ok: true, present: e.present };
      else {
        const kind = kindOfToken(e.token);
        item = {
          device: e.device,
          ok: false,
          kind: kind?.status === null ? kind.name : 'unknown-refusal',
          token: e.token,
          class: kind?.status === null ? kind.class : 'fatal',
          retryAfterMs: kind?.status === null ? kind.retryAfterMs : null,
        };
      }
      byDevice[e.device] = item;
      return item;
    });
    return { ok: true, value: { results, byDevice } };
  }

  /** `abholen`: collects once. Messages come in the order of dropping and are gone from the relay. */
  collect(opts: CollectOptions = {}): Promise<RelayResult<CollectAnswer>> {
    const ask = opts.ask ?? [];
    if (
      ask.length > RELAY_LIMITS.maxPresenceAsk ||
      new Set(ask).size !== ask.length ||
      !ask.every((id) => typeof id === 'string' && RELAY_DEVICE_ID.test(id))
    ) {
      return Promise.resolve(local('bad-argument'));
    }
    return this.call({
      endpoint: `v1/${ENDPOINTS.collect}`,
      method: 'POST',
      body: ask.length === 0 ? '{}' : JSON.stringify({ anwesend: ask }),
      auth: true,
      status: 200,
      maxChars: MAX_COLLECT_TEXT,
      read: (t) => readCollectAnswer(t, ask),
      repeatable: true,
      signal: opts.signal,
    });
  }

  /**
   * Collects again at once while the relay says `more`, within bounds. What was collected is never
   * lost: when a later call fails, the messages so far are returned with `interrupted` set.
   */
  async collectAll(opts: CollectAllOptions = {}): Promise<RelayResult<CollectAllValue>> {
    const maxCalls = Math.max(1, opts.maxCalls ?? 10);
    const maxMessages = opts.maxMessages ?? 500;
    const maxBytes = opts.maxBytes ?? 8 * 1_048_576;
    const messages: CollectedMessage[] = [];
    let bytes = 0;
    let present: readonly string[] = [];
    for (let call = 1; call <= maxCalls; call += 1) {
      const r = await this.collect(opts);
      if (!r.ok) {
        if (call === 1) return r;
        return { ok: true, value: { messages, present, more: true, interrupted: r } };
      }
      messages.push(...r.value.messages);
      for (const m of r.value.messages) bytes += m.content.length;
      present = r.value.present;
      if (!r.value.more) return { ok: true, value: { messages, present, more: false } };
      if (messages.length >= maxMessages || bytes >= maxBytes) break;
    }
    return { ok: true, value: { messages, present, more: true } };
  }

  /** `klingeln`: hands a finished push request to the relay; the push layer builds it. Not repeated after an unclear outcome. */
  ring(
    request: RingRequest,
    opts: { signal?: AbortSignal } = {},
  ): Promise<RelayResult<{ service: number; ms: number }>> {
    const r = request;
    if (
      !r ||
      typeof r.endpoint !== 'string' ||
      r.endpoint.length < 1 ||
      r.endpoint.length > RELAY_LIMITS.ringEndpointMax ||
      typeof r.vapid !== 'string' ||
      r.vapid.length < 1 ||
      r.vapid.length > RELAY_LIMITS.ringVapidMax ||
      !Number.isInteger(r.ttl) ||
      r.ttl < 0 ||
      r.ttl > RELAY_LIMITS.ringTtlMax ||
      !URGENCIES.includes(r.urgency) ||
      !(r.content instanceof Uint8Array) ||
      r.content.length < 1 ||
      r.content.length > RELAY_LIMITS.ringContentMax
    ) {
      return Promise.resolve(local('bad-argument'));
    }
    const body = JSON.stringify({
      endpunkt: r.endpoint,
      vapid: r.vapid,
      ttl: r.ttl,
      dringlichkeit: r.urgency,
      inhalt: base64url(r.content),
    });
    if (body.length > RELAY_LIMITS.maxBodyRing) return Promise.resolve(local('bad-argument'));
    return this.call({
      endpoint: `v1/${ENDPOINTS.ring}`,
      method: 'POST',
      body,
      auth: true,
      status: 200,
      maxChars: 60_000,
      read: (t) => readRingAnswer(t),
      repeatable: false,
      signal: opts.signal,
    });
  }

  /**
   * Collects in a loop at the documented cadence (about every second while `busy()` says an exchange
   * runs, otherwise every 10 seconds) until the signal aborts or an answer says this client cannot
   * go on (a fatal kind, or the access is of no use and no re-enrolment is possible). After a failure
   * it waits 2, 4, 8 … at most 60 seconds, never less than the kind's hint.
   */
  async poll(
    onBatch: (batch: CollectAllValue) => void | Promise<void>,
    opts: {
      readonly signal: AbortSignal;
      readonly ask?: () => readonly string[];
      readonly busy?: () => boolean;
    },
  ): Promise<RelayFailure> {
    let failures = 0;
    while (!opts.signal.aborted) {
      const r = await this.collectAll({ ask: opts.ask?.() ?? [], signal: opts.signal });
      let wait: number;
      if (r.ok) {
        failures = 0;
        try {
          await onBatch(r.value);
        } catch {
          // A handler that fails does not stop the loop; the messages are the handler's to keep.
        }
        wait = opts.busy?.() ? this.pollBusyMs : this.pollIdleMs;
        if (r.value.interrupted) wait = Math.max(wait, r.value.interrupted.retryAfterMs ?? 0);
      } else {
        if (r.kind === 'aborted') return r;
        if (r.class === 'fatal' || r.class === 'reenrol') return r;
        failures += 1;
        wait = Math.max(Math.min(60_000, 2_000 * 2 ** (failures - 1)), r.retryAfterMs ?? 0);
      }
      try {
        await this.sleep(Math.max(RECOMMENDED_POLL.minMs, wait), opts.signal);
      } catch {
        break;
      }
    }
    return local('aborted');
  }
}

/** The access of a stored credential text, for a caller that needs the expiry second. */
export const accessEnd = (access: string): number | undefined => readAccess(access)?.endS;
