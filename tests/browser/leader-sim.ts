// A discrete-event simulation of several tabs running the pure leader machine over a broadcast channel with
// bounded, seeded delays and timer lateness, joins, crashes, releases and pauses. One clock for everybody.
import {
  isLeaseValid,
  leaderMessage,
  leaderRelease,
  leaderStart,
  leaderTick,
  type LeaderConfig,
  type LeaderMessage,
  type LeaderState,
  type LeaderStep,
} from '../../src/browser/index.ts';

export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type Kind = 'msg' | 'act' | 'timer';
interface Ev {
  t: number;
  rank: number;
  seq: number;
  kind: Kind;
  peer: string;
  run: () => void;
}

interface Peer {
  id: string;
  cfg: LeaderConfig;
  state: LeaderState | undefined;
  alive: boolean;
  pausedUntil: number;
  epoch: number;
}

export interface SimOptions {
  readonly seed: number;
  readonly cfg: Omit<LeaderConfig, 'id'>;
  /** After a pause, run the peer's timers before the messages that arrived meanwhile. */
  readonly timersFirst?: boolean;
  /** The real network and timers, when they are worse than the configuration says (to provoke violations). */
  readonly net?: { readonly delayMs: number; readonly lateMs: number };
}

export class Sim {
  now = 0;
  readonly peers = new Map<string, Peer>();
  readonly gains: Array<{ t: number; id: string }> = [];
  readonly losses: Array<{ t: number; id: string }> = [];
  readonly violations: string[] = [];
  readonly trace: string[] = [];
  maxValid = 0;
  private queue: Ev[] = [];
  private seq = 0;
  private rand: () => number;
  private lastDelivery = new Map<string, number>();

  constructor(private o: SimOptions) {
    this.rand = rng(o.seed);
  }

  private push(t: number, kind: Kind, peer: string, run: () => void, rank?: number): void {
    const r = rank ?? (kind === 'msg' ? 0 : kind === 'act' ? 1 : 2);
    this.queue.push({ t, rank: r, seq: this.seq++, kind, peer, run });
  }

  private delay(): number {
    const x = this.rand();
    const D = this.o.net?.delayMs ?? this.o.cfg.delayMs;
    return x < 0.25 ? 0 : x < 0.5 ? D : Math.floor(this.rand() * (D + 1));
  }

  private late(): number {
    const x = this.rand();
    const L = this.o.net?.lateMs ?? this.o.cfg.lateMs;
    return x < 0.3 ? 0 : x < 0.6 ? L : Math.floor(this.rand() * (L + 1));
  }

  note(s: string): void {
    this.trace.push(s);
  }

  join(id: string, at: number): void {
    this.peers.set(id, {
      id,
      cfg: { id, ...this.o.cfg },
      state: undefined,
      alive: true,
      pausedUntil: 0,
      epoch: 0,
    });
    this.push(at, 'act', id, () => this.apply(id, leaderStart(this.peers.get(id)!.cfg, this.now)));
  }
  crash(id: string, at: number): void {
    this.push(at, 'act', id, () => {
      const p = this.peers.get(id)!;
      p.alive = false;
      p.epoch++;
    });
  }
  release(id: string, at: number): void {
    this.push(at, 'act', id, () => {
      const p = this.peers.get(id)!;
      if (p.alive && p.state) this.apply(id, leaderRelease(p.cfg, p.state));
    });
  }
  /** The tab does nothing between `from` and `until` (its events wait); its clock reading does not stop. */
  pause(id: string, from: number, until: number): void {
    this.push(from, 'act', id, () => {
      this.peers.get(id)!.pausedUntil = until;
    });
  }

  private apply(id: string, step: LeaderStep): void {
    const p = this.peers.get(id)!;
    p.state = step.state;
    this.trace.push(
      `${this.now} ${id} -> ${step.state.role}${step.gained ? ' GAIN' : ''}${step.lost ? ' LOSE' : ''} send=${step.send.map((m) => m.t + ('at' in m ? '@' + m.at : '')).join(',')}`,
    );
    if (step.gained) this.gains.push({ t: this.now, id });
    if (step.lost) this.losses.push({ t: this.now, id });
    for (const m of step.send) this.broadcast(id, m);
    p.epoch++;
    if (step.wake !== undefined) {
      const epoch = p.epoch;
      // Lateness is counted from the time the timer was due, not from the time it was set.
      const at = Math.max(this.now, step.wake + this.late());
      this.push(at, 'timer', id, () => {
        if (p.epoch !== epoch || !p.alive || !p.state) return;
        this.apply(id, leaderTick(p.cfg, p.state, this.now));
      });
    }
  }

  private broadcast(from: string, m: LeaderMessage): void {
    for (const q of this.peers.values()) {
      if (q.id === from || !q.state) continue; // a peer that has not started hears nothing
      const key = `${from}>${q.id}`;
      const t = Math.max(this.lastDelivery.get(key) ?? 0, this.now + this.delay());
      this.lastDelivery.set(key, t);
      this.push(t, 'msg', q.id, () => {
        if (!q.alive || !q.state) return;
        this.trace.push(`${this.now} ${q.id} <- ${m.t} from ${m.id}`);
        this.apply(q.id, leaderMessage(q.cfg, q.state, m, this.now));
      });
    }
  }

  validLeaders(t = this.now): string[] {
    return [...this.peers.values()]
      .filter((p) => p.alive && p.state && isLeaseValid(p.cfg, p.state, t))
      .map((p) => p.id);
  }

  run(until: number): void {
    for (;;) {
      this.queue.sort((a, b) => a.t - b.t || a.rank - b.rank || a.seq - b.seq);
      const ev = this.queue[0];
      if (!ev || ev.t > until) break;
      this.queue.shift();
      const p = this.peers.get(ev.peer)!;
      if (ev.kind !== 'act' && p.pausedUntil > ev.t) {
        // Deferred to the end of the pause; messages first unless the test asks for timers first.
        const rank = ev.kind === 'timer' && this.o.timersFirst ? -1 : ev.rank;
        this.queue.push({ ...ev, t: p.pausedUntil, rank, seq: this.seq++ });
        continue;
      }
      this.now = ev.t;
      ev.run();
      const valid = this.validLeaders();
      this.maxValid = Math.max(this.maxValid, valid.length);
      if (valid.length > 1) this.violations.push(`t=${this.now}: ${valid.join(',')}`);
    }
    this.now = until;
  }
}

export function scenario(
  seed: number,
  cfg: Omit<LeaderConfig, 'id'>,
  timersFirst: boolean,
  withPauses: boolean,
): Sim {
  const r = rng(seed * 7919 + 13);
  const sim = new Sim({ seed, cfg, timersFirst });
  const n = 2 + Math.floor(r() * 4);
  const ids = Array.from({ length: n }, (_, i) => `p${i}`);
  for (const id of ids) sim.join(id, Math.floor(r() * 4000));
  const crashed = new Set<string>();
  for (let k = 0; k < 4; k++) {
    const id = ids[Math.floor(r() * n)] as string;
    const at = 2000 + Math.floor(r() * 25_000);
    const x = r();
    if (x < 0.3 && crashed.size < n - 1) {
      crashed.add(id);
      sim.crash(id, at);
    } else if (x < 0.5) sim.release(id, at);
    else if (withPauses) {
      sim.note(`pause ${id} ${at}`);
      sim.pause(id, at, at + Math.floor(r() * 9000));
    }
  }
  sim.run(30_000 + 12_000 + 5_000);
  return sim;
}
