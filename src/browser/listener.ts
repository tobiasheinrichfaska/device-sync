import { fail, isName, pass, type BrowserResult } from './limits.ts';
import { errorName } from './idb.ts';
import {
  LEADER_DEFAULTS,
  isLeaseValid,
  leaderConfigProblem,
  leaderMessage,
  leaderRelease,
  leaderStart,
  leaderTick,
  readLeaderMessage,
  writeLeaderMessage,
  type LeaderConfig,
  type LeaderState,
  type LeaderStep,
} from './leader.ts';

/** `navigator.locks`, as far as it is used here (no `steal`, no `ifAvailable`: the request waits in line). */
export interface LockManagerLike {
  request(
    name: string,
    options: { signal?: AbortSignal },
    callback: (lock: unknown) => Promise<unknown> | unknown,
  ): Promise<unknown>;
}

/** A `BroadcastChannel`, as far as it is used here. */
export interface ChannelLike {
  postMessage(data: unknown): void;
  onmessage: ((ev: { data: unknown }) => void) | null;
  close(): void;
}

export interface TimerLike {
  set(fn: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

export type ListenerErrorCode = 'locks-failed' | 'channel-failed' | 'callback-threw';

export interface SingleListenerOptions {
  /** Names the lock or the channel: one name per app and device. */
  readonly name: string;
  /** Preferred: waits in line for an exclusive lock; the browser frees it when the tab dies. */
  readonly locks?: LockManagerLike;
  /** Fallback when there are no locks: a channel with heartbeats (needs `id`, `clock`, `timers`). */
  readonly channel?: ChannelLike;
  /** This peer's id, unique among the tabs (a random name); only the channel fallback uses it. */
  readonly id?: string;
  /** Milliseconds, the same clock in every tab (`Date.now`); only the channel fallback uses it. */
  readonly clock?: () => number;
  readonly timers?: TimerLike;
  readonly heartbeatMs?: number;
  readonly timeoutMs?: number;
  readonly delayMs?: number;
  readonly lateMs?: number;
  /** This tab is the listener now. */
  readonly onGain: () => void;
  /** This tab is not the listener any more (called once after each `onGain`, also on `release`). */
  readonly onLose: () => void;
  readonly onError?: (code: ListenerErrorCode) => void;
}

export interface SingleListener {
  /** Gives up the role (a leader at once) and stops everything. Safe to call twice. */
  release(): void;
  /** Whether this tab may act as the listener now (the lease is checked against the clock). */
  isLeader(): boolean;
}

export type ListenerReason = 'bad-config' | 'no-mechanism' | 'locks-failed';

export function createSingleListener(
  o: SingleListenerOptions,
): BrowserResult<SingleListener, ListenerReason> {
  if (!o || !isName(o.name) || typeof o.onGain !== 'function' || typeof o.onLose !== 'function')
    return fail('bad-config');
  const safe = (fn: () => void): void => {
    try {
      fn();
    } catch {
      o.onError?.('callback-threw');
    }
  };
  if (o.locks) return withLocks(o, o.locks, safe);
  if (o.channel) return withChannel(o, o.channel, safe);
  return fail('no-mechanism');
}

function withLocks(
  o: SingleListenerOptions,
  locks: LockManagerLike,
  safe: (fn: () => void) => void,
): BrowserResult<SingleListener, ListenerReason> {
  const ac = new AbortController();
  let leader = false;
  let released = false;
  let free: (() => void) | undefined;
  const settled = (e?: unknown): void => {
    if (leader) {
      leader = false;
      safe(o.onLose);
    }
    if (e !== undefined && !(released && errorName(e) === 'AbortError'))
      o.onError?.('locks-failed');
  };
  const grant = () =>
    new Promise<void>((resolve) => {
      if (released) return resolve();
      leader = true;
      free = resolve;
      safe(o.onGain);
    });
  try {
    locks.request(`device-sync:${o.name}`, { signal: ac.signal }, grant).then(
      () => settled(),
      (e: unknown) => settled(e ?? new Error('locks')),
    );
  } catch {
    return fail('locks-failed');
  }
  return pass({
    isLeader: () => leader,
    release() {
      if (released) return;
      released = true;
      ac.abort();
      free?.();
      if (leader) {
        leader = false;
        safe(o.onLose);
      }
    },
  });
}

function withChannel(
  o: SingleListenerOptions,
  channel: ChannelLike,
  safe: (fn: () => void) => void,
): BrowserResult<SingleListener, ListenerReason> {
  const cfg: LeaderConfig = {
    id: o.id as string,
    heartbeatMs: o.heartbeatMs ?? LEADER_DEFAULTS.heartbeatMs,
    timeoutMs: o.timeoutMs ?? LEADER_DEFAULTS.timeoutMs,
    delayMs: o.delayMs ?? LEADER_DEFAULTS.delayMs,
    lateMs: o.lateMs ?? LEADER_DEFAULTS.lateMs,
  };
  if (typeof o.clock !== 'function' || !o.timers || leaderConfigProblem(cfg))
    return fail('bad-config');
  const { clock, timers } = o;
  let state: LeaderState;
  let handle: unknown;
  let timerSet = false;

  const apply = (s: LeaderStep): void => {
    state = s.state;
    for (const m of s.send) {
      try {
        channel.postMessage(writeLeaderMessage(m));
      } catch {
        o.onError?.('channel-failed');
      }
    }
    if (timerSet) timers.clear(handle);
    timerSet = false;
    if (s.wake !== undefined) {
      handle = timers.set(tick, Math.max(0, s.wake - clock()));
      timerSet = true;
    }
    if (s.lost) safe(o.onLose);
    if (s.gained) safe(o.onGain);
  };
  function tick(): void {
    timerSet = false;
    apply(leaderTick(cfg, state, clock()));
  }
  channel.onmessage = (ev) => {
    const m = readLeaderMessage(ev?.data);
    if (m) apply(leaderMessage(cfg, state, m, clock()));
  };
  const first = leaderStart(cfg, clock());
  state = first.state;
  apply(first);
  return pass({
    isLeader: () => isLeaseValid(cfg, state, clock()),
    release() {
      if (state.role === 'released') return;
      apply(leaderRelease(cfg, state));
      channel.onmessage = null;
      try {
        channel.close();
      } catch {
        // already closed
      }
    },
  });
}
