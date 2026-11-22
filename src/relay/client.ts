// Client of the relay (docs/relay-protocol.md). `fetch` and the credential store are injected, so it
// runs in a browser, a WebView and a Node test alike. Protocol errors are RESULTS with an error kind,
// never exceptions; the client acts on the kind, never on the relay's text; the access never appears
// in a result, an error or a log. Retries are bounded, with backoff, and only for kinds the protocol
// calls retryable (and, for a request that is not safe to repeat, only where nothing was stored).
import { base64url } from '../core/encoding.ts';
import { kindOfToken, LOCAL_KINDS, type KindClass, type LocalKind } from './kinds.ts';
import { ENDPOINTS, RECOMMENDED_POLL, RELAY_LIMITS } from './limits.ts';
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
  readPingAnswer,
  readRenewAnswer,
  readRingAnswer,
  readStoredCredentials,
  writeStoredCredentials,
  type CollectAnswer,
  type CollectedMessage,
  type HealthAnswer,
  type StoredCredentials,
} from './readers.ts';

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** Where the client keeps its credentials: one text. Injected; the package assumes no `localStorage`. */
export interface CredentialStore {
  get(): Promise<string | undefined> | string | undefined;
  set(text: string): Promise<void> | void;
  remove(): Promise<void> | void;
}

/** How a new device gets in: a proof of the login script of a test zone, or an invitation of a device. */
export type Enrolment = { readonly proof: string } | { readonly invitation: string };

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

export type CredentialState = 'none' | 'ready' | 'stale';

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
}

const PROOF = /^n1\.[A-Za-z0-9_-]{1,400}\.[A-Za-z0-9_-]{86}$/;
const INVITATION =
  /^e1\.[a-z][a-z0-9]{1,15}\.[1-9][0-9]{0,11}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;
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
  private enrolling: Promise<RelayResult<{ device: string; until: string }>> | undefined;
  private renewing: Promise<RelayResult<{ until: string }>> | undefined;
  private reenrolFlight: Promise<boolean> | undefined;

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

  private async credentials(): Promise<StoredCredentials | undefined | 'storage'> {
    try {
      const text = await this.o.store.get();
      return text === undefined ? undefined : readStoredCredentials(text, this.o.appId);
    } catch {
      return 'storage';
    }
  }

  /** `none`: nothing stored (or unreadable); `stale`: stored but the relay refused it; `ready` otherwise. */
  async state(): Promise<CredentialState> {
    const c = await this.credentials();
    if (c === undefined || c === 'storage') return 'none';
    return this.stale === c.access ? 'stale' : 'ready';
  }

  /** This device's id, when enrolled. */
  async deviceId(): Promise<string | undefined> {
    const c = await this.credentials();
    return c === undefined || c === 'storage' ? undefined : c.device;
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
      if (c === undefined || this.stale === c.access) return local('no-credentials', attempts);
      creds = c;
    }
    const headers: Record<string, string> = {};
    if (spec.method === 'POST') headers['Content-Type'] = 'application/json';
    if (creds) headers['Authorization'] = `Bearer ${creds.access}`;
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
      return this.failureOf(response.status, text, creds, attempts);
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
   * Enrols this device with a proof or an invitation and stores the access. One enrolment at a time:
   * a second call while one runs gets the same answer. A proof or an invitation works once, so a lost
   * answer is not retried (`already-used` follows): the caller fetches a new one.
   */
  enrol(
    how: Enrolment,
    opts: { signal?: AbortSignal } = {},
  ): Promise<RelayResult<{ device: string; until: string }>> {
    if (this.enrolling) return this.enrolling;
    const p = this.doEnrol(how, opts.signal).finally(() => {
      this.enrolling = undefined;
    });
    this.enrolling = p;
    return p;
  }

  private async doEnrol(
    how: Enrolment,
    signal: AbortSignal | undefined,
  ): Promise<RelayResult<{ device: string; until: string }>> {
    const hasProof = 'proof' in how;
    const text = hasProof ? how.proof : how.invitation;
    if (typeof text !== 'string' || !(hasProof ? PROOF : INVITATION).test(text)) {
      return local('bad-argument');
    }
    const body = JSON.stringify(hasProof ? { nachweis: text } : { einladung: text });
    const r = await this.call<StoredCredentials>({
      endpoint: `v1/${ENDPOINTS.enrol}`,
      method: 'POST',
      body,
      auth: false,
      status: 201,
      maxChars: 60_000,
      read: (t) => readEnrolAnswer(t, this.o.appId),
      repeatable: false,
      signal,
    });
    if (!r.ok) return r;
    try {
      await this.o.store.set(writeStoredCredentials(r.value));
    } catch {
      return local('storage', 1);
    }
    this.stale = undefined;
    return { ok: true, value: { device: r.value.device, until: r.value.until } };
  }

  /** `ping`: whether the access is good, and until when. */
  ping(
    opts: { signal?: AbortSignal } = {},
  ): Promise<RelayResult<{ device: string; until: string }>> {
    return this.call({
      endpoint: `v1/${ENDPOINTS.ping}`,
      method: 'POST',
      body: '{}',
      auth: true,
      status: 200,
      maxChars: 60_000,
      read: (t, creds) => {
        const a = readPingAnswer(t);
        return a && a.app === this.o.appId && a.device === creds?.device
          ? { device: a.device, until: a.until }
          : undefined;
      },
      repeatable: true,
      signal: opts.signal,
    });
  }

  /** `erneuern`: a new access for the same device, stored. One renewal at a time. */
  renew(opts: { signal?: AbortSignal } = {}): Promise<RelayResult<{ until: string }>> {
    if (this.renewing) return this.renewing;
    const p = this.doRenew(opts.signal).finally(() => {
      this.renewing = undefined;
    });
    this.renewing = p;
    return p;
  }

  private async doRenew(signal: AbortSignal | undefined): Promise<RelayResult<{ until: string }>> {
    const r = await this.call<StoredCredentials>({
      endpoint: `v1/${ENDPOINTS.renew}`,
      method: 'POST',
      body: '{}',
      auth: true,
      status: 200,
      maxChars: 60_000,
      read: (t, creds) => {
        if (!creds) return undefined;
        const a = readRenewAnswer(t, this.o.appId, creds.device);
        return a ? { device: creds.device, access: a.access, until: a.until } : undefined;
      },
      repeatable: true,
      signal,
    });
    if (!r.ok) return r;
    try {
      await this.o.store.set(writeStoredCredentials(r.value));
    } catch {
      return local('storage', 1);
    }
    this.stale = undefined;
    return { ok: true, value: { until: r.value.until } };
  }

  /** Renews when fewer than 30 days of the access are left (by the stored end day and the clock). */
  async renewIfDue(
    opts: { signal?: AbortSignal } = {},
  ): Promise<RelayResult<{ renewed: boolean; until: string }>> {
    const c = await this.credentials();
    if (c === 'storage') return local('storage');
    if (c === undefined) return local('no-credentials');
    const left = daysBetween(dayOf(this.o.clock()), c.until);
    if (left >= RELAY_LIMITS.renewBelowDays)
      return { ok: true, value: { renewed: false, until: c.until } };
    const r = await this.renew(opts);
    return r.ok ? { ok: true, value: { renewed: true, until: r.value.until } } : r;
  }

  /** `einladen`: an invitation another device can enrol with (10 minutes, once). */
  invite(
    opts: { signal?: AbortSignal } = {},
  ): Promise<RelayResult<{ invitation: string; validForS: number }>> {
    return this.call({
      endpoint: `v1/${ENDPOINTS.invite}`,
      method: 'POST',
      body: '{}',
      auth: true,
      status: 201,
      maxChars: 60_000,
      read: (t) => readInviteAnswer(t, this.o.appId),
      repeatable: false,
      signal: opts.signal,
    });
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
