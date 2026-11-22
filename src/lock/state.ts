// The device lock as a pure state machine over a plain storable value. No clock, no storage and no
// deletion in here: times come in as parameters, the state goes out as text, and what a locked device
// must erase is the app's hook result (`lockCheck`), never an action of the package.
import { hasMembers, isDeviceText, isPlain, parseJson } from '../core/secure.ts';

export const DAY_MS = 86_400_000;
/** Version of the stored state text. */
export const LOCK_STATE_VERSION = 1;

export const LOCK_LIMITS = Object.freeze({
  /** Most days a lock may be configured for. */
  maxDaysCeiling: 3650,
  /** Most sources (names) a state tells apart; contacts from a further one are refused. */
  maxSources: 8,
  /** Longest source name. */
  maxSourceChars: 40,
  /** Longest stored state text. */
  maxStateChars: 2000,
});

const SOURCE = /^[a-z][a-z0-9:_-]{0,39}$/;
const MAX_TIME = Number.MAX_SAFE_INTEGER;
const q = JSON.stringify;

/**
 * Where a time comes from. `device`: the device's own clock when it met a peer (the contact time is the
 * local reading). `remote`: a clock the device does not own (a server's): its time is kept next to the
 * local reading and a time that goes backwards is refused as a replay.
 */
export type LockKind = 'device' | 'remote';
/** When `lockCheck` hands the wipe instruction out: as soon as the device is locked, or at its next contact. */
export type WipeOn = 'locked' | 'contact';

export interface LockState {
  readonly v: 1;
  /** The one source whose contacts count towards the deadline. */
  readonly source: string;
  readonly kind: LockKind;
  readonly maxDays: number;
  /** Elapsed days from which the status is `warn`. */
  readonly warnDays: number;
  /** A contact after the time ran out unlocks again (default false: expiry is final until a new start). */
  readonly revive: boolean;
  readonly wipeOn: WipeOn;
  /** Time of the last counted contact in the units of the source (for `remote`: the server's clock). */
  readonly at: number;
  /** The device clock at that contact. Elapsed time is measured on the device clock from here. */
  readonly local: number;
  /** The highest device clock ever seen (monotonic guard): a clock set back never lowers elapsed time. */
  readonly high: number;
  /** The time ran out (kept once seen, so setting the clock back cannot undo it). */
  readonly expired: boolean;
  /** The device clock stood before its last use by more than `slackMs` (kept once seen). */
  readonly clock: boolean;
  /** The device was removed: final, no contact and no order lifts it (only a new `lockStart`). */
  readonly removed: boolean;
  /** A clock may go back this much (ms) without the `clock` lock (time zone, small correction). */
  readonly slackMs: number;
  /** Only a peer other than the one of the last counted contact renews the deadline (needs `peer`). */
  readonly distinct: boolean;
  /** A peer's file made more than this many ms from the device clock does not count (0 = not checked). */
  readonly skewMs: number;
  /** The peer of the last counted contact, or null. */
  readonly peer: string | null;
  /** When that peer made what it sent (its clock, ms), or null; the next contact must be newer. */
  readonly created: number | null;
  /** An operator lock order is in force. */
  readonly held: boolean;
  /** The device whose order set `held`, or null. */
  readonly by: string | null;
  /** The highest order counter applied (replay and reorder protection of operator orders). */
  readonly opN: number;
  /** The app said it erased what the lock asked for. */
  readonly wiped: boolean;
  /** Last contact per OTHER source (information only; never moves the deadline), sorted by name. */
  readonly others: readonly (readonly [string, number])[];
}

export type LockRefusal =
  'bad-input' | 'bad-config' | 'time-went-back' | 'too-many-sources' | 'not-a-state';

export type LockResult =
  | { readonly ok: true; readonly state: LockState }
  | { readonly ok: false; readonly reason: LockRefusal };

export interface LockConfig {
  readonly source: string;
  readonly kind: LockKind;
  readonly maxDays: number;
  readonly warnDays: number;
  readonly revive?: boolean;
  readonly wipeOn?: WipeOn;
  /** Default 600000 (10 minutes), 0 to 86400000. */
  readonly slackMs?: number;
  readonly distinct?: boolean;
  /** Default 0 (not checked); at most 30 days. */
  readonly skewMs?: number;
}

const isTime = (n: unknown): n is number =>
  typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 && n <= MAX_TIME;
const isDays = (n: unknown): n is number =>
  typeof n === 'number' && Number.isInteger(n) && n >= 1 && n <= LOCK_LIMITS.maxDaysCeiling;
const isSlack = (n: unknown): n is number =>
  typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 && n <= DAY_MS;
const isSkew = (n: unknown): n is number =>
  typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 && n <= 30 * DAY_MS;
export const isSourceName = (s: unknown): s is string => typeof s === 'string' && SOURCE.test(s);

/**
 * A new lock state. Enrolment counts as the first contact: `at` is the time of the source, `local` the
 * device clock now (equal for kind `device`).
 */
export function lockStart(config: LockConfig, at: number, local: number = at): LockResult {
  if (!isTime(at) || !isTime(local)) return { ok: false, reason: 'bad-input' };
  if (
    !isSourceName(config.source) ||
    (config.kind !== 'device' && config.kind !== 'remote') ||
    !isDays(config.maxDays) ||
    !isDays(config.warnDays) ||
    config.warnDays > config.maxDays ||
    (config.slackMs !== undefined && !isSlack(config.slackMs)) ||
    (config.skewMs !== undefined && !isSkew(config.skewMs)) ||
    (config.distinct !== undefined && typeof config.distinct !== 'boolean') ||
    (config.revive !== undefined && typeof config.revive !== 'boolean') ||
    (config.wipeOn !== undefined && config.wipeOn !== 'locked' && config.wipeOn !== 'contact')
  ) {
    return { ok: false, reason: 'bad-config' };
  }
  if (config.kind === 'device' && at !== local) return { ok: false, reason: 'bad-input' };
  return {
    ok: true,
    state: {
      v: 1,
      source: config.source,
      kind: config.kind,
      maxDays: config.maxDays,
      warnDays: config.warnDays,
      revive: config.revive ?? false,
      wipeOn: config.wipeOn ?? 'locked',
      at,
      local,
      high: local,
      expired: false,
      clock: false,
      removed: false,
      slackMs: config.slackMs ?? 600_000,
      distinct: config.distinct ?? false,
      skewMs: config.skewMs ?? 0,
      peer: null,
      created: null,
      held: false,
      by: null,
      opN: 0,
      wiped: false,
      others: [],
    },
  };
}

/** The device clock as the guard sees it: never lower than anything seen before. */
const effective = (s: LockState, now: number): number => Math.max(now, s.high);
const elapsedAt = (s: LockState, eff: number): number => eff - s.local;

export type LockReason = 'removed' | 'operator' | 'clock' | 'expired';
export interface LockStatus {
  readonly status: 'ok' | 'warn' | 'locked';
  /** Whole days left until the deadline, rounded up, 0 when locked. */
  readonly daysLeft: number;
  readonly msLeft: number;
  readonly elapsedMs: number;
  /** The end of the deadline on the device clock (while not locked): last contact plus `maxDays`. */
  readonly deadline: number;
  /** Why it is locked (an operator lock wins when both hold). */
  readonly reason?: LockReason;
}

/** The status at the device clock `now`. Pure: it does not store the highest clock; see `lockObserve`. */
export function lockStatus(state: LockState, now: number): LockStatus {
  const eff = effective(state, isTime(now) ? now : 0);
  const elapsedMs = elapsedAt(state, eff);
  const msLeft = Math.max(0, state.maxDays * DAY_MS - elapsedMs);
  const deadline = state.local + state.maxDays * DAY_MS;
  const base = { daysLeft: Math.ceil(msLeft / DAY_MS), msLeft, elapsedMs, deadline };
  const locked = (reason: LockReason): LockStatus => ({
    status: 'locked',
    ...base,
    daysLeft: 0,
    msLeft: 0,
    reason,
  });
  if (state.removed) return locked('removed');
  if (state.held) return locked('operator');
  if (state.clock || (isTime(now) && now < state.high - state.slackMs)) return locked('clock');
  // as in the earlier implementation: exactly `maxDays` still works, one millisecond more locks
  if (state.expired || elapsedMs > state.maxDays * DAY_MS) return locked('expired');
  return { status: elapsedMs >= state.warnDays * DAY_MS ? 'warn' : 'ok', ...base };
}

/**
 * Takes the device clock into the state: the highest clock seen and the expiry are kept, so a later
 * clock set back cannot undo them. Call it whenever the app starts or comes to the front and store the
 * result; a device whose clock is set back before the app ever looked again cannot be stopped.
 */
export function lockObserve(state: LockState, now: number): LockState {
  if (!isTime(now)) return state;
  const eff = effective(state, now);
  const expired = state.expired || elapsedAt(state, eff) > state.maxDays * DAY_MS;
  const clock = state.clock || now < state.high - state.slackMs;
  if (eff === state.high && expired === state.expired && clock === state.clock) return state;
  return { ...state, high: eff, expired, clock };
}

/** Why a contact did not move the deadline. */
export type NotCounted =
  'other-source' | 'removed' | 'locked' | 'same-peer' | 'old' | 'clock-differs';

export type ContactResult =
  | {
      readonly ok: true;
      readonly state: LockState;
      readonly counted: boolean;
      /** Set when `counted` is false. */
      readonly why?: NotCounted;
    }
  | { readonly ok: false; readonly reason: LockRefusal };

/** What is known about the peer of a contact (kind `device`). Trust in the peer is the caller's check. */
export interface ContactInfo {
  /** The peer's device id; required when the state is `distinct`. */
  readonly peer?: string;
  /** When the peer made what it sent, by its clock (ms): must be newer than the last counted one. */
  readonly created?: number;
}

/**
 * A contact with `source` at `at` (the source's time; the device clock reading `local` for `device`).
 * Only the configured source moves the deadline; a contact from any other source is only noted, so a
 * server-time lock is never advanced by what a peer claims. The caller must only pass a contact whose
 * peer it trusts and whose data do not show this device removed (`lockRemoved`). `counted` is false
 * (with `why`) for another source, for a removed device, for a contact after expiry or a clock lock
 * when the lock does not `revive` (the state then records it), for the same peer twice in a row when
 * `distinct`, for a file not newer than the last one and for a file whose clock differs from the
 * device's by more than `skewMs`. Refused: a `remote` time lower than the last one (an old answer replayed).
 */
export function recordContact(
  state: LockState,
  source: string,
  at: number,
  local: number = at,
  info: ContactInfo = {},
): ContactResult {
  if (!isSourceName(source) || !isTime(at) || !isTime(local)) {
    return { ok: false, reason: 'bad-input' };
  }
  const eff = effective(state, local);
  if (source !== state.source) {
    const i = state.others.findIndex(([n]) => n === source);
    if (i < 0 && state.others.length >= LOCK_LIMITS.maxSources - 1) {
      return { ok: false, reason: 'too-many-sources' };
    }
    const prev = i < 0 ? -1 : (state.others[i] as readonly [string, number])[1];
    const entry: readonly [string, number] = [source, Math.max(prev, at)];
    const rest = state.others.filter(([n]) => n !== source);
    const others = [...rest, entry].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    return {
      ok: true,
      counted: false,
      why: 'other-source',
      state: { ...state, high: eff, others },
    };
  }
  if (state.kind === 'device' && at !== local) return { ok: false, reason: 'bad-input' };
  if (state.kind === 'remote' && at < state.at) return { ok: false, reason: 'time-went-back' };
  if (
    (info.peer !== undefined && !isDeviceText(info.peer)) ||
    (info.created !== undefined && !isTime(info.created)) ||
    (state.distinct && info.peer === undefined)
  ) {
    return { ok: false, reason: 'bad-input' };
  }
  const observed = lockObserve(state, local);
  const no = (why: NotCounted): ContactResult => ({
    ok: true,
    counted: false,
    why,
    state: observed,
  });
  if (observed.removed) return no('removed');
  if ((observed.expired || observed.clock) && !observed.revive) return no('locked');
  if (observed.distinct && info.peer === observed.peer) return no('same-peer');
  if (info.created !== undefined) {
    if (observed.skewMs > 0 && Math.abs(info.created - at) > observed.skewMs)
      return no('clock-differs');
    if (observed.created !== null && info.created <= observed.created) return no('old');
  }
  return {
    ok: true,
    counted: true,
    state: {
      ...observed,
      at: state.kind === 'device' ? eff : Math.max(at, state.at),
      local: eff,
      high: eff,
      expired: false,
      clock: false,
      peer: info.peer ?? null,
      created: info.created ?? null,
    },
  };
}

/** The data show this device removed: locked for good (reason `removed`); only a new `lockStart` helps. */
export const lockRemoved = (state: LockState): LockState =>
  state.removed ? state : { ...state, removed: true };

/**
 * This device's own deadline (e.g. a private device: shorter). A lock that stands stays; `warnDays`
 * must not exceed `maxDays`.
 */
export function lockSetDays(state: LockState, maxDays: number, warnDays: number): LockResult {
  if (!isDays(maxDays) || !isDays(warnDays) || warnDays > maxDays) {
    return { ok: false, reason: 'bad-config' };
  }
  return { ok: true, state: { ...state, maxDays, warnDays } };
}

/** The app says it erased what the lock asked for. */
export const lockMarkWiped = (state: LockState): LockState =>
  state.wiped ? state : { ...state, wiped: true };

export interface LockHooks<T> {
  /** What the app must erase for this lock; the package only hands the answer back. */
  readonly onLocked?: (info: { readonly reason: LockReason; readonly by: string | null }) => T;
}
export interface LockCheck<T> {
  readonly status: LockStatus;
  /** The state with the observed clock; store it. */
  readonly state: LockState;
  /** The hook's answer: set while locked, not yet marked wiped and (for `wipeOn: 'contact'`) at a contact. */
  readonly wipe: T | undefined;
}

/** Status plus the wipe instruction. `atContact`: the app is in contact with the source right now. */
export function lockCheck<T>(
  state: LockState,
  now: number,
  hooks: LockHooks<T> = {},
  atContact = false,
): LockCheck<T> {
  const observed = lockObserve(state, now);
  const status = lockStatus(observed, now);
  let wipe: T | undefined;
  if (
    status.status === 'locked' &&
    !observed.wiped &&
    hooks.onLocked !== undefined &&
    (observed.wipeOn === 'locked' || atContact)
  ) {
    wipe = hooks.onLocked({ reason: status.reason as LockReason, by: observed.by });
  }
  return { status, state: observed, wipe };
}

const ORDER = [
  'v',
  'source',
  'kind',
  'maxDays',
  'warnDays',
  'revive',
  'wipeOn',
  'at',
  'local',
  'high',
  'expired',
  'clock',
  'removed',
  'slackMs',
  'distinct',
  'skewMs',
  'peer',
  'created',
  'held',
  'by',
  'opN',
  'wiped',
  'others',
] as const;

/** The stored text: compact JSON, members in one order. */
export function storeLockState(state: LockState): string {
  return `{${ORDER.map((k) => `${q(k)}:${k === 'others' ? `[${state.others.map((o) => `[${q(o[0])},${o[1]}]`).join(',')}]` : q(state[k])}`).join(',')}}`;
}

/** The strict reader of a stored state: one spelling, bounded, consistent; undefined for anything else. */
export function readLockState(text: unknown): LockState | undefined {
  if (typeof text !== 'string' || text.length > LOCK_LIMITS.maxStateChars) return undefined;
  const v = parseJson(text);
  if (!isPlain(v) || !hasMembers(v, ORDER)) return undefined;
  const others = v.others;
  if (!Array.isArray(others) || others.length > LOCK_LIMITS.maxSources - 1) return undefined;
  const list: [string, number][] = [];
  for (const o of others as unknown[]) {
    if (!Array.isArray(o) || o.length !== 2 || !isSourceName(o[0]) || !isTime(o[1]))
      return undefined;
    list.push([o[0], o[1]]);
  }
  for (let i = 0; i < list.length; i += 1) {
    const n = (list[i] as [string, number])[0];
    if (n === v.source) return undefined;
    if (i > 0 && (list[i - 1] as [string, number])[0] >= n) return undefined;
  }
  const state = {
    v: v.v,
    source: v.source,
    kind: v.kind,
    maxDays: v.maxDays,
    warnDays: v.warnDays,
    revive: v.revive,
    wipeOn: v.wipeOn,
    at: v.at,
    local: v.local,
    high: v.high,
    expired: v.expired,
    clock: v.clock,
    removed: v.removed,
    slackMs: v.slackMs,
    distinct: v.distinct,
    skewMs: v.skewMs,
    peer: v.peer,
    created: v.created,
    held: v.held,
    by: v.by,
    opN: v.opN,
    wiped: v.wiped,
    others: list,
  } as unknown as LockState;
  if (
    state.v !== 1 ||
    !isSourceName(state.source) ||
    (state.kind !== 'device' && state.kind !== 'remote') ||
    !isDays(state.maxDays) ||
    !isDays(state.warnDays) ||
    state.warnDays > state.maxDays ||
    typeof state.revive !== 'boolean' ||
    (state.wipeOn !== 'locked' && state.wipeOn !== 'contact') ||
    !isTime(state.at) ||
    !isTime(state.local) ||
    !isTime(state.high) ||
    state.high < state.local ||
    (state.kind === 'device' && state.at !== state.local) ||
    typeof state.expired !== 'boolean' ||
    typeof state.clock !== 'boolean' ||
    typeof state.removed !== 'boolean' ||
    typeof state.distinct !== 'boolean' ||
    !isSlack(state.slackMs) ||
    !isSkew(state.skewMs) ||
    (state.peer !== null && !isDeviceText(state.peer)) ||
    (state.created !== null && !isTime(state.created)) ||
    typeof state.held !== 'boolean' ||
    typeof state.wiped !== 'boolean' ||
    !isTime(state.opN) ||
    (state.by !== null && !isDeviceText(state.by)) ||
    state.held !== (state.by !== null)
  ) {
    return undefined;
  }
  return storeLockState(state) === text ? state : undefined;
}
