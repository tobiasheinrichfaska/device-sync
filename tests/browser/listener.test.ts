import { describe, expect, it } from 'vitest';
import {
  createSingleListener,
  type ListenerErrorCode,
  type SingleListener,
} from '../../src/browser/index.ts';
import { FakeLocks, FakeNetwork, VirtualTime } from './fakes.ts';

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

function recorder() {
  const log: string[] = [];
  const errors: ListenerErrorCode[] = [];
  return {
    log,
    errors,
    onGain: () => void log.push('gain'),
    onLose: () => void log.push('lose'),
    onError: (c: ListenerErrorCode) => void errors.push(c),
  };
}

function listen(opts: Parameters<typeof createSingleListener>[0]): SingleListener {
  const r = createSingleListener(opts);
  if (!r.ok) throw new Error(`createSingleListener: ${r.reason}`);
  return r.value;
}

describe('createSingleListener: configuration', () => {
  const base = { onGain: () => undefined, onLose: () => undefined };
  it('refuses bad names, missing callbacks and no mechanism', () => {
    const locks = new FakeLocks().tab('a');
    for (const name of ['', '-x', 'a b', 'x'.repeat(101)])
      expect(createSingleListener({ ...base, name, locks })).toEqual({
        ok: false,
        reason: 'bad-config',
      });
    expect(createSingleListener({ name: 'x', locks } as never)).toEqual({
      ok: false,
      reason: 'bad-config',
    });
    expect(createSingleListener({ ...base, name: 'x' })).toEqual({
      ok: false,
      reason: 'no-mechanism',
    });
  });

  it('the channel fallback needs an id, a clock, timers and a valid timing', () => {
    const t = new VirtualTime();
    const channel = new FakeNetwork(t).channel();
    const ok = { ...base, name: 'x', channel, id: 'a', clock: t.clock, timers: t };
    expect(createSingleListener(ok).ok).toBe(true);
    expect(createSingleListener({ ...ok, id: undefined } as never)).toEqual({
      ok: false,
      reason: 'bad-config',
    });
    expect(createSingleListener({ ...ok, clock: undefined } as never)).toEqual({
      ok: false,
      reason: 'bad-config',
    });
    expect(createSingleListener({ ...ok, timers: undefined } as never)).toEqual({
      ok: false,
      reason: 'bad-config',
    });
    expect(createSingleListener({ ...ok, timeoutMs: 100 })).toEqual({
      ok: false,
      reason: 'bad-config',
    });
  });
});

describe('over a lock manager', () => {
  it('the first tab leads; the lock name is the app name, prefixed; never starts with "-"', async () => {
    const locks = new FakeLocks();
    const r = recorder();
    const l = listen({ name: 'app1', locks: locks.tab('t1'), ...r });
    await flush();
    expect(r.log).toEqual(['gain']);
    expect(l.isLeader()).toBe(true);
    expect(locks.requested).toEqual(['device-sync:app1']);
    expect(locks.requested.every((n) => !n.startsWith('-'))).toBe(true);
  });

  it('a second tab waits; release hands over at once; onLose follows onGain exactly once', async () => {
    const locks = new FakeLocks();
    const a = recorder();
    const b = recorder();
    const la = listen({ name: 'app', locks: locks.tab('a'), ...a });
    await flush();
    const lb = listen({ name: 'app', locks: locks.tab('b'), ...b });
    await flush();
    expect(la.isLeader()).toBe(true);
    expect(lb.isLeader()).toBe(false);
    expect(b.log).toEqual([]);
    la.release();
    expect(a.log).toEqual(['gain', 'lose']); // synchronously
    expect(la.isLeader()).toBe(false);
    await flush();
    expect(lb.isLeader()).toBe(true);
    expect(b.log).toEqual(['gain']);
    la.release(); // twice is harmless
    await flush();
    expect(a.log).toEqual(['gain', 'lose']);
  });

  it('a crashed leader (the browser frees the lock) is replaced; the dead tab hears nothing', async () => {
    const locks = new FakeLocks();
    const a = recorder();
    const b = recorder();
    listen({ name: 'app', locks: locks.tab('a'), ...a });
    await flush();
    const lb = listen({ name: 'app', locks: locks.tab('b'), ...b });
    await flush();
    locks.crash('a');
    await flush();
    expect(lb.isLeader()).toBe(true);
    expect(b.log).toEqual(['gain']);
    expect(a.log).toEqual(['gain']);
  });

  it('release before the lock was granted: never leads, no error, the next tab is not blocked', async () => {
    const locks = new FakeLocks();
    const a = recorder();
    const b = recorder();
    const c = recorder();
    listen({ name: 'app', locks: locks.tab('a'), ...a });
    await flush();
    const lb = listen({ name: 'app', locks: locks.tab('b'), ...b });
    const lc = listen({ name: 'app', locks: locks.tab('c'), ...c });
    await flush();
    lb.release();
    await flush();
    expect(b.log).toEqual([]);
    expect(b.errors).toEqual([]);
    locks.crash('a');
    await flush();
    expect(lc.isLeader()).toBe(true);
    expect(b.log).toEqual([]);
  });

  it('release in the same tick as the request: no lead at all', async () => {
    const locks = new FakeLocks();
    const r = recorder();
    const l = listen({ name: 'app', locks: locks.tab('a'), ...r });
    l.release();
    await flush();
    expect(r.log).toEqual([]);
    expect(r.errors).toEqual([]);
    expect(locks.holder('device-sync:app')).toBeUndefined();
  });

  it('a failing lock manager is reported as a code; a throwing one gives a result', async () => {
    const locks = new FakeLocks();
    locks.rejectWith = { name: 'SecurityError' };
    const r = recorder();
    const l = listen({ name: 'app', locks: locks.tab('a'), ...r });
    await flush();
    expect(r.errors).toEqual(['locks-failed']);
    expect(l.isLeader()).toBe(false);
    locks.rejectWith = undefined;
    locks.throwSync = new Error('boom');
    expect(createSingleListener({ name: 'app', locks: locks.tab('a'), ...r })).toEqual({
      ok: false,
      reason: 'locks-failed',
    });
  });

  it('a callback that throws is reported and does not break the hand-over', async () => {
    const locks = new FakeLocks();
    const errors: string[] = [];
    const log: string[] = [];
    const la = listen({
      name: 'app',
      locks: locks.tab('a'),
      onGain: () => {
        throw new Error('app bug');
      },
      onLose: () => {
        log.push('lose');
        throw new Error('app bug');
      },
      onError: (c) => errors.push(c),
    });
    const b = recorder();
    const lb = listen({ name: 'app', locks: locks.tab('b'), ...b });
    await flush();
    la.release();
    await flush();
    expect(errors).toEqual(['callback-threw', 'callback-threw']);
    expect(log).toEqual(['lose']);
    expect(lb.isLeader()).toBe(true);
  });

  it('two apps with different names do not block each other', async () => {
    const locks = new FakeLocks();
    const a = recorder();
    const b = recorder();
    listen({ name: 'one', locks: locks.tab('t'), ...a });
    listen({ name: 'two', locks: locks.tab('t'), ...b });
    await flush();
    expect(a.log).toEqual(['gain']);
    expect(b.log).toEqual(['gain']);
  });
});

describe('over a broadcast channel (virtual time)', () => {
  const timing = { heartbeatMs: 1000, delayMs: 500, lateMs: 500, timeoutMs: 2500 };

  function tabs(n: number, delay = 300) {
    const time = new VirtualTime();
    const net = new FakeNetwork(time);
    net.delay = delay;
    const out = Array.from({ length: n }, (_, i) => {
      const channel = net.channel();
      const r = recorder();
      const l = listen({
        name: 'app',
        channel,
        id: `tab${i}`,
        clock: time.clock,
        timers: time,
        ...timing,
        ...r,
      });
      return { channel, l, ...r, id: `tab${i}` };
    });
    const leaders = (): string[] => out.filter((t) => t.l.isLeader()).map((t) => t.id);
    return { time, net, tabs: out, leaders };
  }

  it('exactly one of three tabs leads, at every instant; the others follow', () => {
    const s = tabs(3);
    let most = 0;
    for (let t = 0; t <= 20_000; t += 50) {
      s.time.advanceTo(t, () => (most = Math.max(most, s.leaders().length)));
      most = Math.max(most, s.leaders().length);
    }
    expect(most).toBe(1);
    expect(s.leaders().length).toBe(1);
    const gains = s.tabs.reduce((n, t) => n + t.log.filter((e) => e === 'gain').length, 0);
    expect(gains).toBe(1);
  });

  it('release: a leader says bye and another tab leads within 2 * delay + lateness; onLose fires', () => {
    const s = tabs(3);
    s.time.advanceTo(10_000);
    const [first] = s.leaders();
    const leader = s.tabs.find((t) => t.id === first) as (typeof s.tabs)[number];
    const at = s.time.now;
    leader.l.release();
    expect(leader.log).toEqual(['gain', 'lose']);
    expect(leader.channel.closed).toBe(true);
    expect(leader.channel.sent.at(-1)).toEqual({ v: 1, t: 'bye', id: leader.id });
    let ready: number | undefined;
    for (let t = at; t <= at + 5000 && ready === undefined; t += 10) {
      s.time.advanceTo(t);
      if (s.leaders().length === 1) ready = t - at;
    }
    expect(ready).toBeDefined();
    expect(ready as number).toBeLessThanOrEqual(2 * timing.delayMs + timing.lateMs);
    expect(s.leaders()).not.toContain(leader.id);
  });

  it('crash: the dead tab sends nothing more; another leads within the stated time', () => {
    const s = tabs(3);
    s.time.advanceTo(10_000);
    const [first] = s.leaders();
    const dead = s.tabs.find((t) => t.id === first) as (typeof s.tabs)[number];
    s.net.kill(dead.channel);
    const at = s.time.now;
    let ready: number | undefined;
    for (let t = at; t <= at + 20_000 && ready === undefined; t += 10) {
      s.time.advanceTo(t);
      const others = s.leaders().filter((id) => id !== dead.id);
      if (others.length === 1) ready = t - at;
    }
    expect(ready).toBeDefined();
    expect(ready as number).toBeLessThanOrEqual(
      timing.timeoutMs + 2 * timing.delayMs + 2 * timing.lateMs + timing.delayMs,
    );
  });

  it('a leader whose timers stop (a frozen tab) is not a leader by the clock any more', () => {
    const s = tabs(1);
    s.time.advanceTo(10_000);
    expect(s.leaders()).toEqual(['tab0']);
    // Nothing runs for a while: no timer, no beat. `isLeader` reads the clock, so it turns false by itself.
    const frozen = s.time;
    frozen.now = 10_000 + timing.timeoutMs + 100;
    expect(s.tabs[0]?.l.isLeader()).toBe(false);
  });

  it('release is idempotent and silences the tab: no messages, no timers, no callbacks afterwards', () => {
    const s = tabs(2);
    s.time.advanceTo(10_000);
    const t0 = s.tabs[0] as (typeof s.tabs)[number];
    t0.l.release();
    const sent = t0.channel.sent.length;
    const log = [...t0.log];
    t0.l.release();
    s.time.advanceTo(40_000);
    expect(t0.channel.sent.length).toBe(sent);
    expect(t0.log).toEqual(log);
    expect(t0.l.isLeader()).toBe(false);
  });

  it('garbage on the channel and echoes of its own id are ignored', () => {
    const s = tabs(1);
    const t0 = s.tabs[0] as (typeof s.tabs)[number];
    for (const data of [
      null,
      'x',
      5,
      {},
      { v: 1 },
      { v: 1, t: 'beat', id: 'tab0' },
      { v: 1, t: 'claim', id: 'z' },
    ])
      t0.channel.onmessage?.({ data });
    s.time.advanceTo(20_000);
    expect(s.leaders()).toEqual(['tab0']);
  });

  it('a channel that throws on postMessage is reported and the tab keeps running', () => {
    const s = tabs(1);
    const errors: ListenerErrorCode[] = [];
    const time = s.time;
    const channel = new FakeNetwork(time).channel();
    channel.throwOnPost = true;
    const l = listen({
      name: 'app',
      channel,
      id: 'solo',
      clock: time.clock,
      timers: time,
      ...timing,
      onGain: () => undefined,
      onLose: () => undefined,
      onError: (c) => errors.push(c),
    });
    time.advanceTo(time.now + 10_000);
    expect(errors).toContain('channel-failed');
    expect(l.isLeader()).toBe(true);
  });

  it('late timers (a busy tab) never produce two leaders', () => {
    const s = tabs(3);
    s.time.late = timing.lateMs;
    let most = 0;
    for (let t = 0; t <= 30_000; t += 25) {
      s.time.advanceTo(t, () => (most = Math.max(most, s.leaders().length)));
    }
    expect(most).toBe(1);
  });
});
