// Leader election over a broadcast channel, as a pure state machine: no clock, no timer, no channel here.
// Time is an argument; the result says what to send and when to call again.
//
// Assumptions (stated in docs/browser.md): all peers read the same clock; a message sent at time s reaches
// every peer by s + delayMs and messages of one sender arrive in order; a timer set for t runs at t or later
// (a late timer is handled: a leader whose lease ran out steps down instead of acting). Under them:
//
//  - A leader's lease runs from the send time s of its latest beat to s + timeoutMs; it is a leader only
//    while the clock is inside it. A follower takes over only when it has heard nothing for timeoutMs, and
//    the claim then waits delayMs for a better claim. Because timeoutMs > heartbeatMs + delayMs, a follower
//    that has not heard the latest beat has already heard one less than heartbeatMs older and so waits
//    until that beat's lease is over: leases never overlap.
//  - Claims are ordered by (time, id); a candidate that hears a better claim, or a beat, becomes a follower.
//  - A new peer sends `hello` and may claim after 2 * delayMs of silence; a leader answers a hello with a beat.
import { isName } from './limits.ts';

export interface LeaderConfig {
  /** This peer's id: unique among the peers (a random id the caller makes). */
  readonly id: string;
  /** A leader beats at least this often (ms). */
  readonly heartbeatMs: number;
  /** A follower takes over after this much silence; a lease lasts this long (ms). */
  readonly timeoutMs: number;
  /** Largest delay of a message between two peers (ms). */
  readonly delayMs: number;
}

export type LeaderMessage =
  | { readonly t: 'hello' | 'beat' | 'bye'; readonly id: string }
  | { readonly t: 'claim'; readonly id: string; readonly at: number };

export interface LeaderState {
  readonly role: 'follower' | 'candidate' | 'leader' | 'released';
  /** Follower: the time something was last heard (or the time that makes a takeover due). */
  readonly lastSeen: number;
  /** Follower: the leader named by the latest beat. */
  readonly leaderId: string | undefined;
  /** Candidate: the time of the claim. */
  readonly claimAt: number;
  /** Leader: the send time of the latest beat (start of the lease). */
  readonly leaseFrom: number;
}

export interface LeaderStep {
  readonly state: LeaderState;
  readonly send: readonly LeaderMessage[];
  /** The time the machine wants a `tick` (absolute, ms), or undefined. */
  readonly wake: number | undefined;
  readonly gained: boolean;
  readonly lost: boolean;
}

export const LEADER_DEFAULTS = { heartbeatMs: 2_000, timeoutMs: 6_000, delayMs: 2_000 } as const;

/** `bad-config` unless the id is a name and the times are positive integers with the needed margins. */
export function leaderConfigProblem(c: LeaderConfig): 'bad-config' | undefined {
  const posInt = (n: unknown): n is number => Number.isInteger(n) && (n as number) > 0;
  if (!c || !isName(c.id)) return 'bad-config';
  if (!posInt(c.heartbeatMs) || !posInt(c.timeoutMs) || !posInt(c.delayMs)) return 'bad-config';
  if (c.timeoutMs <= c.heartbeatMs + c.delayMs || c.timeoutMs <= 2 * c.delayMs) return 'bad-config';
  return undefined;
}

/** Strict reader of a message from the channel; anything else is undefined. */
export function readLeaderMessage(data: unknown): LeaderMessage | undefined {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return undefined;
  const o = data as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(',');
  if (o['v'] !== 1 || !isName(o['id'])) return undefined;
  const t = o['t'];
  if (t === 'claim') {
    const at = o['at'];
    if (keys !== 'at,id,t,v' || typeof at !== 'number' || !Number.isSafeInteger(at) || at < 0)
      return undefined;
    return { t, id: o['id'], at };
  }
  if ((t === 'hello' || t === 'beat' || t === 'bye') && keys === 'id,t,v')
    return { t, id: o['id'] };
  return undefined;
}

/** The text put on the channel. */
export const writeLeaderMessage = (m: LeaderMessage): unknown => ({ v: 1, ...m });

const step = (
  state: LeaderState,
  send: LeaderMessage[],
  wake: number | undefined,
  gained = false,
  lost = false,
): LeaderStep => ({ state, send, wake, gained, lost });

const follower = (now: number, leaderId: string | undefined): LeaderState => ({
  role: 'follower',
  lastSeen: now,
  leaderId,
  claimAt: 0,
  leaseFrom: 0,
});

/** A new peer: says hello and may claim after 2 * delayMs of silence. */
export function leaderStart(cfg: LeaderConfig, now: number): LeaderStep {
  const s = follower(now - cfg.timeoutMs + 2 * cfg.delayMs, undefined);
  return step(s, [{ t: 'hello', id: cfg.id }], s.lastSeen + cfg.timeoutMs);
}

/** Whether this peer holds a lease at `now`. The one question an app asks before it acts as the leader. */
export const isLeaseValid = (cfg: LeaderConfig, s: LeaderState, now: number): boolean =>
  s.role === 'leader' && now >= s.leaseFrom && now < s.leaseFrom + cfg.timeoutMs;

const beat = (cfg: LeaderConfig, s: LeaderState, now: number): LeaderStep =>
  step({ ...s, leaseFrom: now }, [{ t: 'beat', id: cfg.id }], now + cfg.heartbeatMs);

export function leaderTick(cfg: LeaderConfig, s: LeaderState, now: number): LeaderStep {
  switch (s.role) {
    case 'released':
      return step(s, [], undefined);
    case 'follower':
      if (now >= s.lastSeen + cfg.timeoutMs) {
        const c: LeaderState = { ...s, role: 'candidate', claimAt: now, leaderId: undefined };
        return step(c, [{ t: 'claim', id: cfg.id, at: now }], now + cfg.delayMs);
      }
      return step(s, [], s.lastSeen + cfg.timeoutMs);
    case 'candidate':
      if (now >= s.claimAt + cfg.delayMs) {
        const l: LeaderState = { ...s, role: 'leader', leaseFrom: now };
        return { ...beat(cfg, l, now), gained: true };
      }
      return step(s, [], s.claimAt + cfg.delayMs);
    case 'leader':
      // A timer that ran late: the lease is over, so this peer is no leader any more and does not beat.
      if (now >= s.leaseFrom + cfg.timeoutMs) {
        const f = follower(now, undefined);
        return step(f, [], now + cfg.timeoutMs, false, true);
      }
      if (now >= s.leaseFrom + cfg.heartbeatMs) return beat(cfg, s, now);
      return step(s, [], s.leaseFrom + cfg.heartbeatMs);
  }
}

const better = (m: { at: number; id: string }, mine: { at: number; id: string }): boolean =>
  m.at < mine.at || (m.at === mine.at && m.id < mine.id);

export function leaderMessage(
  cfg: LeaderConfig,
  s: LeaderState,
  m: LeaderMessage,
  now: number,
): LeaderStep {
  if (m.id === cfg.id || s.role === 'released') return step(s, [], wakeOf(cfg, s));
  switch (s.role) {
    case 'follower':
      if (m.t === 'beat') return step(follower(now, m.id), [], now + cfg.timeoutMs);
      if (m.t === 'claim') return step(follower(now, s.leaderId), [], now + cfg.timeoutMs);
      if (m.t === 'bye' && m.id === s.leaderId) {
        // The leader let go: its lease is void, so claim at once.
        return leaderTick(cfg, { ...s, lastSeen: now - cfg.timeoutMs, leaderId: undefined }, now);
      }
      return step(s, [], wakeOf(cfg, s));
    case 'candidate':
      if (m.t === 'beat') return step(follower(now, m.id), [], now + cfg.timeoutMs);
      if (m.t === 'claim' && better(m, { at: s.claimAt, id: cfg.id }))
        return step(follower(now, undefined), [], now + cfg.timeoutMs);
      return step(s, [], wakeOf(cfg, s));
    case 'leader':
      if (m.t === 'hello' || m.t === 'claim') return beat(cfg, s, now);
      if (m.t === 'beat') {
        // Two leaders: outside the assumptions. The lower id stays.
        if (m.id < cfg.id) return step(follower(now, m.id), [], now + cfg.timeoutMs, false, true);
        return beat(cfg, s, now);
      }
      return step(s, [], wakeOf(cfg, s));
  }
}

/** The next wake time of a state (what `leaderTick` would answer without acting). */
function wakeOf(cfg: LeaderConfig, s: LeaderState): number | undefined {
  switch (s.role) {
    case 'released':
      return undefined;
    case 'follower':
      return s.lastSeen + cfg.timeoutMs;
    case 'candidate':
      return s.claimAt + cfg.delayMs;
    case 'leader':
      return s.leaseFrom + cfg.heartbeatMs;
  }
}

/** Lets go: a leader says `bye` so that the others claim at once; everybody else just stops. */
export function leaderRelease(cfg: LeaderConfig, s: LeaderState): LeaderStep {
  const r: LeaderState = { ...s, role: 'released' };
  if (s.role === 'leader') return step(r, [{ t: 'bye', id: cfg.id }], undefined, false, true);
  return step(r, [], undefined);
}
