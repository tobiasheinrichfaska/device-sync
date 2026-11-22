// The contact deadline of a device: how long it may work without data contact to another trusted device.
// Pure (the clock comes in as `now`, in ms), storage is the caller's. The package hard-wires no duration and no
// role: the app passes a policy (see `deadlinePolicy`) that says per role and per private flag how long, or that
// there is none.
//
// Rules (the same for every device that has a deadline):
// - the contact that renews the deadline must come from another device than the one of the last renewal
//   (two stolen devices cannot keep each other alive);
// - once the deadline has passed the device stays locked, also when its clock is turned back, until a file from a
//   trusted device arrives that does not show this device removed;
// - a clock that stands before the last use (beyond a small slack) locks the device too;
// - a device shown removed is locked for good (`removed`): only a new enrolment helps.
// A device WITHOUT a deadline (`deadlineMs: null`, for example an administrative role the app exempts) still has the
// clock check and the `removed` lock; only the time limit is missing.

/** A device's own deadline, in ms; `null` = no time limit. */
export type DeadlineMs = number | null;

/** Why a device is locked. */
export type DeadlineLockReason = 'deadline' | 'clock' | 'removed';

/** The stored state. */
export interface DeadlineState {
  readonly v: 1;
  /** The last contact that renewed the deadline: the other device (`null` = founder), when (this clock), `created` = when the other device made the data (its clock). */
  readonly contact: {
    readonly device: string | null;
    readonly time: number;
    readonly created?: number;
  };
  /** The latest moment this device's clock showed; never goes back. */
  readonly used: number;
  readonly deadlineMs: DeadlineMs;
  readonly lock?: { readonly reason: DeadlineLockReason; readonly since: number };
}

export interface DeadlineOptions {
  /** A clock may go back this much without locking. Default 10 minutes. */
  readonly clockSlackMs?: number;
  /** Data whose sender's clock and this device's differ more than this cannot lift a lock. Default 1 day. */
  readonly clockDiffMs?: number;
}

export const DEFAULT_CLOCK_SLACK_MS = 10 * 60 * 1000;
export const DEFAULT_CLOCK_DIFF_MS = 24 * 60 * 60 * 1000;
/** The shortest and the longest time limit that is accepted (a minute, 400 days). */
export const MIN_DEADLINE_MS = 60 * 1000;
export const MAX_DEADLINE_MS = 400 * 24 * 60 * 60 * 1000;

const REASONS: ReadonlySet<string> = new Set(['deadline', 'clock', 'removed']);

/** A usable time limit: a whole number of ms within the bounds, or `null` (none). */
export const isDeadlineMs = (x: unknown): x is DeadlineMs =>
  x === null ||
  (Number.isSafeInteger(x) && (x as number) >= MIN_DEADLINE_MS && (x as number) <= MAX_DEADLINE_MS);

export interface DeadlinePolicyOptions {
  /** The limit of a device that no other rule covers. */
  readonly standardMs: number;
  /** The limit of a private device (shorter), if it differs from `standardMs`. */
  readonly privateMs?: number;
  /** Roles whose devices have NO time limit — only while the device is not private. */
  readonly noLimitRoles?: readonly string[];
  /** A longer limit for a role, instead of none (checked after `noLimitRoles`). */
  readonly roleMs?: Readonly<Record<string, number>>;
}

/**
 * The policy: which limit a device gets from its role and private flag. A private device never gets the exemption of
 * its role (its own limit is `privateMs` or the standard). Throws for a limit that is out of bounds.
 */
export function deadlinePolicy(
  o: DeadlinePolicyOptions,
): (device: { readonly role?: string; readonly private?: boolean }) => DeadlineMs {
  const all = [
    o.standardMs,
    ...(o.privateMs !== undefined ? [o.privateMs] : []),
    ...Object.values(o.roleMs ?? {}),
  ];
  for (const ms of all)
    if (!isDeadlineMs(ms) || ms === null) throw new RangeError('deadline out of bounds');
  const exempt = new Set(o.noLimitRoles ?? []);
  const own = new Map(Object.entries(o.roleMs ?? {}));
  return (device) => {
    if (device.private === true) return o.privateMs ?? o.standardMs;
    if (device.role !== undefined) {
      if (exempt.has(device.role)) return null;
      const ms = own.get(device.role);
      if (ms !== undefined) return ms;
    }
    return o.standardMs;
  };
}

/** A new state: the device was enrolled by `by` (`null` = it founded the group) at `now`, with its limit. */
export function deadlineStart(
  by: string | null,
  now: number,
  deadlineMs: DeadlineMs,
): DeadlineState {
  if (!isDeadlineMs(deadlineMs)) throw new RangeError('deadline out of bounds');
  return { v: 1, contact: { device: by, time: now }, used: now, deadlineMs };
}

/** The stored state, strictly read; `undefined` for none or a damaged one (the caller then locks, never unlocks). */
export function parseDeadline(raw: unknown): DeadlineState | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const r = raw as Record<string, unknown>;
  if (
    r.v !== 1 ||
    !('deadlineMs' in r) ||
    !isDeadlineMs(r.deadlineMs) ||
    !Number.isSafeInteger(r.used)
  )
    return undefined;
  const c = r.contact as Record<string, unknown> | null | undefined;
  if (!c || typeof c !== 'object') return undefined;
  if (!(c.device === null || typeof c.device === 'string') || !Number.isSafeInteger(c.time))
    return undefined;
  if (c.created !== undefined && !Number.isSafeInteger(c.created)) return undefined;
  const l = r.lock as Record<string, unknown> | undefined;
  if (
    l !== undefined &&
    (!l ||
      typeof l !== 'object' ||
      !REASONS.has(l.reason as string) ||
      !Number.isSafeInteger(l.since))
  )
    return undefined;
  return {
    v: 1,
    contact: {
      device: c.device as string | null,
      time: c.time as number,
      ...(c.created !== undefined ? { created: c.created as number } : {}),
    },
    used: r.used as number,
    deadlineMs: r.deadlineMs as DeadlineMs,
    ...(l ? { lock: { reason: l.reason as DeadlineLockReason, since: l.since as number } } : {}),
  };
}

/** The state with a new limit (a role change); a lock stays. */
export function setDeadlineMs(state: DeadlineState, deadlineMs: DeadlineMs): DeadlineState {
  if (!isDeadlineMs(deadlineMs)) throw new RangeError('deadline out of bounds');
  return { ...state, deadlineMs };
}

export interface DeadlineVerdict {
  readonly state: DeadlineState;
  readonly locked: boolean;
  readonly reason?: DeadlineLockReason;
  /** When the limit ends (while not locked and a limit exists). */
  readonly until?: number;
}

const locked = (s: DeadlineState, reason: DeadlineLockReason, since: number): DeadlineState =>
  s.lock ? s : { ...s, lock: { reason, since } };

/** The check at every start and while the app is open. */
export function checkDeadline(
  state: DeadlineState,
  now: number,
  opt: DeadlineOptions = {},
): DeadlineVerdict {
  const slack = opt.clockSlackMs ?? DEFAULT_CLOCK_SLACK_MS;
  let s = state;
  if (!s.lock && now < s.used - slack) s = locked(s, 'clock', s.used);
  if (!s.lock && s.deadlineMs !== null && now - s.contact.time > s.deadlineMs)
    s = locked(s, 'deadline', now);
  if (!s.lock && now > s.used) s = { ...s, used: now };
  if (s.lock) return { state: s, locked: true, reason: s.lock.reason };
  return {
    state: s,
    locked: false,
    ...(s.deadlineMs !== null ? { until: s.contact.time + s.deadlineMs } : {}),
  };
}

export interface DeadlineContact {
  /** The device that made the data. */
  readonly from: string;
  /** Is it trusted here? */
  readonly trusted: boolean;
  /** Do the data show THIS device removed? */
  readonly removed: boolean;
  /** When the sender made the data, by its clock (ms). */
  readonly created: number;
  readonly now: number;
}

export type DeadlineContactReason = 'removed' | 'not-trusted' | 'same-device' | 'clock' | 'old';

export interface DeadlineContactResult {
  readonly state: DeadlineState;
  /** Did it count as a contact (renew the deadline, lift a lock)? */
  readonly counts: boolean;
  readonly reason?: DeadlineContactReason;
}

/**
 * Data from another device were taken in. They renew the deadline (and lift a lock) only when the sender is trusted
 * here, is not the device of the last renewal, the data do not show this device removed, they are newer than the
 * last renewal by the sender's clock, and the sender's clock and this device's agree (else this device's clock is
 * wrong). Data that show this device removed lock it for good.
 */
export function contactDeadline(
  state: DeadlineState,
  c: DeadlineContact,
  opt: DeadlineOptions = {},
): DeadlineContactResult {
  const diff = opt.clockDiffMs ?? DEFAULT_CLOCK_DIFF_MS;
  if (c.removed)
    return {
      state: { ...state, lock: { reason: 'removed', since: c.now } },
      counts: false,
      reason: 'removed',
    };
  if (state.lock?.reason === 'removed') return { state, counts: false, reason: 'removed' };
  if (!c.trusted) return { state, counts: false, reason: 'not-trusted' };
  if (c.from === state.contact.device) return { state, counts: false, reason: 'same-device' };
  if (!Number.isSafeInteger(c.created) || Math.abs(c.created - c.now) > diff)
    return { state, counts: false, reason: 'clock' };
  if (state.contact.created !== undefined && c.created <= state.contact.created)
    return { state, counts: false, reason: 'old' };
  const { lock: _lock, ...rest } = state;
  return {
    state: {
      ...rest,
      contact: { device: c.from, time: c.now, created: c.created },
      used: Math.max(c.now, state.used),
    },
    counts: true,
  };
}
