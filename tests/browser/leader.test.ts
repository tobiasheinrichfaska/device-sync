import { describe, expect, it } from 'vitest';
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
} from '../../src/browser/index.ts';
import { Sim, scenario } from './leader-sim.ts';

const BASE = { heartbeatMs: 1000, delayMs: 500, lateMs: 500, timeoutMs: 2500 } as const;
const cfg: LeaderConfig = { id: 'b', ...BASE };

describe('configuration', () => {
  it('the defaults are valid', () => {
    expect(leaderConfigProblem({ id: 'x', ...LEADER_DEFAULTS })).toBeUndefined();
  });
  it('the timeout must exceed heartbeat + delay + lateness, and twice the delay', () => {
    expect(leaderConfigProblem({ ...cfg, timeoutMs: 2000 })).toBe('bad-config'); // = 1000+500+500
    expect(leaderConfigProblem({ ...cfg, timeoutMs: 2001 })).toBeUndefined();
    // not above 2 * delay + lateness (the first beat of a new leader must arrive first)
    const c = { ...cfg, heartbeatMs: 10, lateMs: 500, delayMs: 500 };
    expect(leaderConfigProblem({ ...c, timeoutMs: 1500 })).toBe('bad-config');
    expect(leaderConfigProblem({ ...c, timeoutMs: 1501 })).toBeUndefined();
  });
  it('refuses bad ids and non-integers', () => {
    for (const c of [
      { ...cfg, id: '' },
      { ...cfg, id: 'a b' },
      { ...cfg, heartbeatMs: 0 },
      { ...cfg, delayMs: 1.5 },
      { ...cfg, lateMs: -1 },
      { ...cfg, timeoutMs: Number.NaN },
    ])
      expect(leaderConfigProblem(c)).toBe('bad-config');
  });
});

describe('messages', () => {
  it('round trip, and a strict reader', () => {
    for (const m of [
      { t: 'beat', id: 'a' },
      { t: 'bye', id: 'a' },
      { t: 'claim', id: 'a', at: 5 },
    ] as const)
      expect(readLeaderMessage(writeLeaderMessage(m))).toEqual(m);
    for (const bad of [
      null,
      'x',
      [],
      {},
      { v: 2, t: 'beat', id: 'a' },
      { v: 1, t: 'beat' },
      { v: 1, t: 'beat', id: 'a', extra: 1 },
      { v: 1, t: 'claim', id: 'a' },
      { v: 1, t: 'claim', id: 'a', at: -1 },
      { v: 1, t: 'claim', id: 'a', at: 1.5 },
      { v: 1, t: 'hello', id: 'a' },
      { v: 1, t: 'beat', id: 'a', at: 1 },
      { v: 1, t: 'other', id: 'a' },
      { v: 1, t: 'beat', id: 'a b' },
    ])
      expect(readLeaderMessage(bad)).toBeUndefined();
  });
});

describe('the machine, step by step', () => {
  // A peer started at 0 claims at 2500 (a full timeout of silence) and leads at 3000.
  const start = leaderStart(cfg, 0);
  const claimed = leaderTick(cfg, start.state, 2500);
  const led = leaderTick(cfg, claimed.state, 3000);

  it('a new peer is silent, claims after a full timeout of silence and leads one delay later', () => {
    expect(start.send).toEqual([]);
    expect(start.wake).toBe(cfg.timeoutMs);
    expect(claimed.send).toEqual([{ t: 'claim', id: 'b', at: 2500 }]);
    expect(claimed.gained).toBe(false);
    expect(claimed.wake).toBe(3000);
    expect(led.gained).toBe(true);
    expect(led.send).toEqual([{ t: 'beat', id: 'b' }]);
    expect(isLeaseValid(cfg, led.state, 3000)).toBe(true);
    expect(isLeaseValid(cfg, led.state, 3000 + cfg.timeoutMs - 1)).toBe(true);
    expect(isLeaseValid(cfg, led.state, 3000 + cfg.timeoutMs)).toBe(false);
    expect(isLeaseValid(cfg, led.state, 2999)).toBe(false);
  });

  it('a timer that fires early does nothing but ask again', () => {
    const early = leaderTick(cfg, start.state, 2499);
    expect(early.send).toEqual([]);
    expect(early.wake).toBe(2500);
    expect(early.state.role).toBe('follower');
  });

  it('a leader beats every heartbeat and not before', () => {
    expect(leaderTick(cfg, led.state, 3999).send).toEqual([]);
    const b = leaderTick(cfg, led.state, 4000);
    expect(b.send).toEqual([{ t: 'beat', id: 'b' }]);
    expect(b.state.leaseFrom).toBe(4000);
    expect(b.wake).toBe(5000);
  });

  it('a beat while waiting to claim, or while a candidate, makes a follower', () => {
    const heard = leaderMessage(cfg, start.state, { t: 'beat', id: 'a' }, 100);
    expect(heard.state.role).toBe('follower');
    expect(heard.wake).toBe(100 + cfg.timeoutMs);
    const back = leaderMessage(cfg, claimed.state, { t: 'beat', id: 'a' }, 2600);
    expect(back.state.role).toBe('follower');
  });

  it('claims are ordered by time then id; the better one wins, the worse one gives way', () => {
    const worse = leaderMessage(cfg, claimed.state, { t: 'claim', id: 'c', at: 2500 }, 2600);
    expect(worse.state.role).toBe('candidate');
    const later = leaderMessage(cfg, claimed.state, { t: 'claim', id: 'a', at: 2501 }, 2600);
    expect(later.state.role).toBe('candidate');
    const earlier = leaderMessage(cfg, claimed.state, { t: 'claim', id: 'z', at: 2499 }, 2600);
    expect(earlier.state.role).toBe('follower');
    const lowerId = leaderMessage(cfg, claimed.state, { t: 'claim', id: 'a', at: 2500 }, 2600);
    expect(lowerId.state.role).toBe('follower');
  });

  it('a leader answers a claim with a beat and ignores its own messages', () => {
    expect(leaderMessage(cfg, led.state, { t: 'claim', id: 'x', at: 1 }, 3100).send).toEqual([
      { t: 'beat', id: 'b' },
    ]);
    expect(leaderMessage(cfg, led.state, { t: 'beat', id: 'b' }, 3100).send).toEqual([]);
    expect(leaderMessage(cfg, led.state, { t: 'bye', id: 'x' }, 3100).state.role).toBe('leader');
  });

  it('two leaders (outside the assumptions): the lower id stays', () => {
    const low = leaderMessage(cfg, led.state, { t: 'beat', id: 'a' }, 3100);
    expect(low.state.role).toBe('follower');
    expect(low.lost).toBe(true);
    const high = leaderMessage(cfg, led.state, { t: 'beat', id: 'c' }, 3100);
    expect(high.state.role).toBe('leader');
  });

  it('a leader whose lease ran out steps down BEFORE it reads a beat (a paused tab does not renew)', () => {
    const late = 3000 + cfg.timeoutMs; // lease just over
    const r = leaderMessage(cfg, led.state, { t: 'beat', id: 'z' }, late); // z > b: would have been answered
    expect(r.state.role).toBe('follower');
    expect(r.lost).toBe(true);
    expect(isLeaseValid(cfg, r.state, late)).toBe(false);
    const inside = leaderMessage(cfg, led.state, { t: 'beat', id: 'z' }, late - 1);
    expect(inside.state.role).toBe('leader');
  });

  it('a leader whose timer ran late (lease over) steps down instead of beating', () => {
    const r = leaderTick(cfg, led.state, 3000 + cfg.timeoutMs + 7);
    expect(r.lost).toBe(true);
    expect(r.send).toEqual([]);
    expect(r.state.role).toBe('follower');
  });

  it('a candidate whose timer ran far too late drops the claim', () => {
    const ok = leaderTick(cfg, claimed.state, 2500 + cfg.delayMs + cfg.lateMs);
    expect(ok.gained).toBe(true);
    const tooLate = leaderTick(cfg, claimed.state, 2500 + cfg.delayMs + cfg.lateMs + 1);
    expect(tooLate.gained).toBe(false);
    expect(tooLate.state.role).toBe('follower');
  });

  it('bye from the known leader: claim at once; from anybody else: ignored', () => {
    const f = leaderMessage(cfg, start.state, { t: 'beat', id: 'a' }, 100);
    const other = leaderMessage(cfg, f.state, { t: 'bye', id: 'q' }, 200);
    expect(other.state.role).toBe('follower');
    const bye = leaderMessage(cfg, f.state, { t: 'bye', id: 'a' }, 200);
    expect(bye.state.role).toBe('candidate');
    expect(bye.send).toEqual([{ t: 'claim', id: 'b', at: 200 }]);
  });

  it('bye after a claim was heard: no second claim (it would ignore the first); the claim decides', () => {
    const f = leaderMessage(cfg, start.state, { t: 'beat', id: 'a' }, 100);
    const claimHeard = leaderMessage(cfg, f.state, { t: 'claim', id: 'c', at: 150 }, 160);
    expect(claimHeard.state.claimHeard).toBe(160);
    // an older beat of the leader arrives after the claim: it does not cancel the memory of the claim
    const beat = leaderMessage(cfg, claimHeard.state, { t: 'beat', id: 'a' }, 170);
    expect(beat.state.claimHeard).toBe(160);
    const bye = leaderMessage(cfg, beat.state, { t: 'bye', id: 'a' }, 200);
    expect(bye.state.role).toBe('follower');
    expect(bye.send).toEqual([]);
    // a claim long ago (a timeout) no longer counts
    const old = leaderMessage(cfg, beat.state, { t: 'bye', id: 'a' }, 160 + cfg.timeoutMs);
    expect(old.state.role).toBe('candidate');
  });

  it('release: a leader says bye and loses; a candidate or follower only stops', () => {
    expect(leaderRelease(cfg, claimed.state)).toMatchObject({ send: [], lost: false });
    const r = leaderRelease(cfg, led.state);
    expect(r.send).toEqual([{ t: 'bye', id: 'b' }]);
    expect(r.lost).toBe(true);
    expect(isLeaseValid(cfg, r.state, 3100)).toBe(false);
    expect(leaderTick(cfg, r.state, 9999).send).toEqual([]);
    expect(leaderMessage(cfg, r.state, { t: 'beat', id: 'a' }, 9999).state.role).toBe('released');
  });
});

describe('simulation: targeted', () => {
  it('the first tab becomes leader after timeout + delay (+ lateness) and the second one follows', () => {
    const sim = new Sim({ seed: 1, cfg: BASE });
    sim.join('a', 0);
    sim.join('b', 200);
    sim.run(20_000);
    expect(sim.violations).toEqual([]);
    expect(sim.validLeaders().length).toBe(1);
    const first = sim.gains[0] as { t: number; id: string };
    expect(first.t).toBeLessThanOrEqual(200 + BASE.timeoutMs + BASE.delayMs + 2 * BASE.lateMs);
    expect(sim.gains.length).toBe(1);
  });

  it('a crashed leader is replaced within timeout + 2 * delay + 2 * lateness, never two at once', () => {
    for (let seed = 1; seed <= 60; seed++) {
      const sim = new Sim({ seed, cfg: BASE });
      for (const id of ['a', 'b', 'c']) sim.join(id, 0);
      sim.run(10_000);
      const [leader] = sim.validLeaders();
      expect(leader, `seed ${seed}`).toBeDefined();
      const crashAt = 10_000;
      sim.crash(leader as string, crashAt);
      sim.run(crashAt + 20_000);
      expect(sim.violations, `seed ${seed}`).toEqual([]);
      const next = sim.gains.find((g) => g.t > crashAt);
      expect(next, `seed ${seed}`).toBeDefined();
      expect((next as { t: number }).t - crashAt).toBeLessThanOrEqual(
        BASE.timeoutMs + 2 * BASE.delayMs + 2 * BASE.lateMs,
      );
      expect(sim.validLeaders().length).toBe(1);
    }
  });

  it('a released leader is replaced within 2 * delay + lateness', () => {
    for (let seed = 1; seed <= 60; seed++) {
      const sim = new Sim({ seed, cfg: BASE });
      for (const id of ['a', 'b', 'c']) sim.join(id, 0);
      sim.run(10_000);
      const [leader] = sim.validLeaders();
      sim.release(leader as string, 10_000);
      sim.run(30_000);
      expect(sim.violations, `seed ${seed}`).toEqual([]);
      const next = sim.gains.find((g) => g.t > 10_000);
      expect(next, `seed ${seed}`).toBeDefined();
      expect((next as { t: number }).t - 10_000).toBeLessThanOrEqual(
        2 * BASE.delayMs + BASE.lateMs,
      );
    }
  });

  it('a paused leader loses its lease by the clock and does not get it back from a late beat', () => {
    for (const timersFirst of [false, true]) {
      for (let seed = 1; seed <= 60; seed++) {
        const sim = new Sim({ seed, cfg: BASE, timersFirst });
        for (const id of ['a', 'b']) sim.join(id, 0);
        sim.run(8_000);
        const [leader] = sim.validLeaders();
        sim.pause(leader as string, 8_000, 20_000);
        sim.run(40_000);
        expect(sim.violations, `seed ${seed} timersFirst=${timersFirst}`).toEqual([]);
        expect(sim.validLeaders().length).toBe(1);
      }
    }
  });
});

describe('simulation: seeded schedules', () => {
  const check = (name: string, timersFirst: boolean, withPauses: boolean): void => {
    it(name, () => {
      let withLeader = 0;
      for (let seed = 1; seed <= 400; seed++) {
        const sim = scenario(seed, BASE, timersFirst, withPauses);
        expect(sim.violations, `seed ${seed}`).toEqual([]);
        // callbacks alternate: gain, lose, gain, ...
        for (const id of sim.peers.keys()) {
          const events = [
            ...sim.gains.filter((g) => g.id === id).map((g) => ({ ...g, k: 1 })),
            ...sim.losses.filter((g) => g.id === id).map((g) => ({ ...g, k: -1 })),
          ].sort((a, b) => a.t - b.t || b.k - a.k * -1);
          let depth = 0;
          for (const e of events) {
            depth += e.k;
            expect(depth === 0 || depth === 1, `seed ${seed} ${id} alternation`).toBe(true);
          }
        }
        const eligible = [...sim.peers.values()].filter(
          (p) => p.alive && p.state && p.state.role !== 'released',
        );
        if (eligible.length > 0) {
          // everything is quiet for the last 5 s: somebody leads, and it is exactly one
          expect(sim.validLeaders().length, `seed ${seed} liveness`).toBe(1);
          withLeader++;
        }
      }
      expect(withLeader).toBeGreaterThan(300);
    });
  };

  check(
    'joins, crashes and releases: never two leaders at once, one in the end (400 schedules)',
    false,
    false,
  );
  check('with pauses, messages first on resume (400 schedules)', false, true);
  check('with pauses, timers first on resume (400 schedules)', true, true);

  it('the simulation is able to see a violation: a network slower than the configured bound gives two leaders', () => {
    // Valid configuration for a 50 ms network, run on one with 500 ms delays and timers 500 ms late.
    const small = { heartbeatMs: 1000, delayMs: 50, lateMs: 50, timeoutMs: 1200 };
    expect(leaderConfigProblem({ id: 'x', ...small })).toBeUndefined();
    let seen = 0;
    for (let seed = 1; seed <= 100; seed++) {
      const sim = new Sim({ seed, cfg: small, net: { delayMs: 500, lateMs: 500 } });
      for (const id of ['a', 'b', 'c']) sim.join(id, 0);
      sim.run(30_000);
      if (sim.violations.length > 0) seen++;
    }
    expect(seen).toBeGreaterThan(0);
  });
});
