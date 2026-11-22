// Small fakes for the listener and media tests: a Web Locks manager with tabs that can crash, a virtual
// clock with timers, and a broadcast network on top of it.
import type { ChannelLike, LockManagerLike, TimerLike } from '../../src/browser/index.ts';

interface Waiter {
  tab: string;
  cb: (lock: unknown) => unknown;
  signal: AbortSignal | undefined;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
  onAbort?: () => void;
}

export class FakeLocks {
  private holders = new Map<string, { tab: string; release: () => void } | undefined>();
  private queues = new Map<string, Waiter[]>();
  readonly requested: string[] = [];
  /** Make `request` reject (or throw) like a browser in an insecure context. */
  rejectWith: unknown;
  throwSync: unknown;

  tab(tab: string): LockManagerLike {
    return {
      request: (name, options, cb) => this.request(tab, name, options, cb),
    };
  }

  holder(name: string): string | undefined {
    return this.holders.get(name)?.tab;
  }

  private request(
    tab: string,
    name: string,
    options: { signal?: AbortSignal },
    cb: (lock: unknown) => unknown,
  ): Promise<unknown> {
    this.requested.push(name);
    if (this.throwSync) throw this.throwSync;
    if (this.rejectWith) return Promise.reject(this.rejectWith);
    return new Promise((resolve, reject) => {
      const w: Waiter = { tab, cb, signal: options.signal, resolve, reject };
      if (w.signal?.aborted) return reject({ name: 'AbortError' });
      w.onAbort = () => {
        const q = this.queues.get(name) ?? [];
        const i = q.indexOf(w);
        if (i >= 0) {
          q.splice(i, 1);
          reject({ name: 'AbortError' });
        }
      };
      w.signal?.addEventListener('abort', w.onAbort);
      this.queues.set(name, [...(this.queues.get(name) ?? []), w]);
      this.pump(name);
    });
  }

  private pump(name: string): void {
    if (this.holders.get(name)) return;
    const w = this.queues.get(name)?.shift();
    if (!w) return;
    if (w.onAbort) w.signal?.removeEventListener('abort', w.onAbort);
    let released = false;
    const release = (): void => {
      if (released) return;
      released = true;
      this.holders.set(name, undefined);
      this.pump(name);
    };
    this.holders.set(name, { tab: w.tab, release });
    Promise.resolve()
      .then(() => w.cb({ name }))
      .then(
        (v) => {
          release();
          w.resolve(v);
        },
        (e) => {
          release();
          w.reject(e);
        },
      );
  }

  /** The tab dies: its locks are released by the browser, its callbacks are never told. */
  crash(tab: string): void {
    for (const h of this.holders.values()) if (h?.tab === tab) h.release();
    for (const [name, q] of this.queues)
      this.queues.set(
        name,
        q.filter((w) => w.tab !== tab),
      );
  }
}

/** A virtual clock: timers run in time order when time is advanced. */
export class VirtualTime implements TimerLike {
  now = 0;
  private timers: Array<{ at: number; seq: number; fn: () => void; live: boolean }> = [];
  private seq = 0;
  /** Extra lateness of every timer (ms). */
  late = 0;

  clock = (): number => this.now;

  set(fn: () => void, ms: number): unknown {
    const t = { at: this.now + Math.max(0, ms) + this.late, seq: this.seq++, fn, live: true };
    this.timers.push(t);
    return t;
  }
  clear(handle: unknown): void {
    (handle as { live: boolean }).live = false;
  }
  schedule(at: number, fn: () => void): void {
    this.timers.push({ at, seq: this.seq++, fn, live: true });
  }
  advanceTo(until: number, after?: () => void): void {
    for (;;) {
      this.timers = this.timers.filter((t) => t.live);
      this.timers.sort((a, b) => a.at - b.at || a.seq - b.seq);
      const t = this.timers[0];
      if (!t || t.at > until) break;
      this.timers.shift();
      this.now = Math.max(this.now, t.at);
      t.fn();
      after?.();
    }
    this.now = until;
  }
}

/** Channels of one name: a message reaches every other open channel after `delay` ms. */
export class FakeNetwork {
  private channels: Array<{ ch: FakeChannel; alive: boolean }> = [];
  delay = 0;
  constructor(private time: VirtualTime) {}

  channel(): FakeChannel {
    const ch = new FakeChannel(this);
    this.channels.push({ ch, alive: true });
    return ch;
  }
  /** The tab dies: it neither sends nor receives. */
  kill(ch: FakeChannel): void {
    const e = this.channels.find((c) => c.ch === ch);
    if (e) e.alive = false;
  }
  send(from: FakeChannel, data: unknown): void {
    if (this.channels.some((c) => c.ch === from && !c.alive)) return;
    for (const e of this.channels) {
      if (e.ch === from || !e.alive) continue;
      const copy = structuredClone(data);
      this.time.schedule(this.time.now + this.delay, () => {
        if (e.alive && !e.ch.closed) e.ch.onmessage?.({ data: copy });
      });
    }
  }
}

export class FakeChannel implements ChannelLike {
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  closed = false;
  sent: unknown[] = [];
  throwOnPost = false;
  constructor(private net: FakeNetwork) {}
  postMessage(data: unknown): void {
    if (this.throwOnPost) throw new Error('closed channel');
    this.sent.push(data);
    this.net.send(this, data);
  }
  close(): void {
    this.closed = true;
  }
}
