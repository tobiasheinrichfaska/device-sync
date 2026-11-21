import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  emptyReplica,
  findRecord,
  fingerprint,
  insertSignatures,
  merge,
  outcome,
  pieces,
  receiveJudged,
  signOwnChanges,
  softDelete,
  startSession,
  undo,
  historyOf,
  restore,
  write,
  type Change,
  type JudgeOptions,
  type KeySource,
  type Limits,
  type Replica,
  type Session,
} from '../../src/log/index.ts';
import { int, pick, randomValue } from './fuzz.ts';
import { COL, prng, written, removed } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
const IDS = ['a', 'b', 'c'] as const;
type Id = (typeof IDS)[number];

const pairs: Record<string, CryptoKeyPair> = {};
const keySource: KeySource = { keyFor: (device) => pairs[device]?.publicKey };

beforeAll(async () => {
  for (const id of [...IDS, 'x']) pairs[id] = (await generateDeviceKeys()).signing;
});

const judgeFor = (me: string, extra: Partial<JudgeOptions> = {}): JudgeOptions => ({
  appId: APP,
  dataSet: SET,
  keys: keySource,
  ownDevice: me,
  allowFinalDelete: () => true,
  ...extra,
});

async function signed(replica: Replica): Promise<Replica> {
  const key = (pairs[replica.device] as CryptoKeyPair).privateKey;
  return insertSignatures(replica, await signOwnChanges(APP, key, replica, SET));
}

const json = (m: unknown): unknown => JSON.parse(JSON.stringify(m));
const must = <T>(v: T | undefined): T => {
  if (v === undefined) throw new Error('expected a value');
  return v;
};

interface Hooks {
  limits?: Partial<Limits>;
  /** Rewrites what one side sends (after JSON), e.g. to duplicate or forge. */
  tamper?: (from: 'x' | 'y', messages: unknown[]) => unknown[];
}

interface Side {
  session: Session;
  replica: Replica;
  out: unknown[];
}

/** The whole exchange of two devices: signed, cut into pieces, JSON, read strictly, judged, merged. */
async function exchange(x: Replica, y: Replica, hooks: Hooks = {}) {
  const open = async (replica: Replica, from: 'x' | 'y'): Promise<Side> => {
    const own = await signed(replica);
    const step = startSession(own);
    return {
      session: step.session,
      replica: step.replica,
      out: hooks.tamper ? hooks.tamper(from, step.send.map(json)) : step.send.map(json),
    };
  };
  const a = await open(x, 'x');
  const b = await open(y, 'y');
  const options = hooks.limits ? { limits: hooks.limits } : {};
  for (let round = 0; round < 50 && (a.out.length > 0 || b.out.length > 0); round += 1) {
    for (const [from, to, name] of [
      [a, b, 'x'],
      [b, a, 'y'],
    ] as const) {
      for (const message of from.out.splice(0)) {
        const step = await receiveJudged(
          to.session,
          to.replica,
          message,
          judgeFor(to.replica.device),
          options,
        );
        to.session = step.session;
        to.replica = step.replica;
        const send = step.send.map(json);
        const other = name === 'x' ? 'y' : 'x';
        to.out.push(...(hooks.tamper ? hooks.tamper(other, send) : send));
      }
    }
  }
  return { x: a.replica, y: b.replica, sx: a.session, sy: b.session };
}

/** Same as `exchange`, but the sender's answers to a `stand` are cut with these limits. */
const small: Partial<Limits> = { pieceBytes: 1500 };

describe('full stack: two replicas exchange through the protocol and converge', () => {
  it('signed, cut into pieces, JSON, strictly read, judged, merged: same data, same fingerprint', async () => {
    let a = emptyReplica('a');
    let b = emptyReplica('b');
    for (let i = 0; i < 40; i += 1) {
      a = written(a, `a${i}`, { title: `from a ${i}`, tags: ['x', i] });
      b = written(b, `b${i}`, { title: `from b ${i}`, pos: { x: i } });
    }
    const r = await exchange(a, b, { limits: small });
    expect(r.x.collections).toEqual(r.y.collections);
    expect(Object.keys(r.x.collections[COL] ?? {})).toHaveLength(80);
    expect(fingerprint(r.x)).toBe(fingerprint(r.y));
    expect(outcome(r.sx, r.x)).toMatchObject({ equal: true, taken: 40, sent: 40 });
    expect(outcome(r.sy, r.y)).toMatchObject({ equal: true, taken: 40, sent: 40 });
    expect(r.sx.refusal).toBeUndefined();
    expect(r.x.log.every((c) => c.sig && c.check)).toBe(true);
  });

  it('an erased write and its final deletion in different pieces still pass', async () => {
    let a = emptyReplica('a');
    for (let i = 0; i < 30; i += 1) a = written(a, `r${i}`, { title: 'x'.repeat(150) });
    a = removed(a, COL, 'r0');
    const parts = pieces((await signed(a)).log, { limits: small });
    const erased = parts.findIndex((p) => p.changes.some((c) => c.kind === 'redacted'));
    const deletion = parts.findIndex((p) => p.changes.some((c) => c.kind === 'delete'));
    expect(parts.length).toBeGreaterThan(2);
    expect(deletion).toBeGreaterThan(erased); // the deletion comes in a later piece than the erased write
    const r = await exchange(a, emptyReplica('b'), { limits: small });
    expect(findRecord(r.y, COL, 'r0')?.deleted).toBe(true);
    expect(fingerprint(r.y)).toBe(fingerprint(r.x));
    expect(r.sy.refusal).toBeUndefined();
  });

  it('a duplicated piece (every message sent twice) changes nothing', async () => {
    const a = written(written(emptyReplica('a'), 'r1', { title: 'x' }), 'r2', { title: 'y' });
    // a second stand or done would end the session (refusal unexpected): only pieces repeat
    const twice = (_: 'x' | 'y', msgs: unknown[]) =>
      msgs.flatMap((m) => ((m as { t: string }).t === 'changes' ? [m, m] : [m]));
    const r = await exchange(a, emptyReplica('b'), { tamper: twice });
    expect(r.y.log).toHaveLength(2);
    expect(r.sy.refusal).toBeUndefined();
    expect(fingerprint(r.y)).toBe(fingerprint(r.x));
    expect(r.sy.taken).toBe(2);
  });

  it('a second exchange after both converged sends and takes nothing', async () => {
    const a = written(emptyReplica('a'), 'r1', { title: 'x' });
    const first = await exchange(a, written(emptyReplica('b'), 'r2', { title: 'y' }));
    const second = await exchange(first.x, first.y);
    expect(second.sx).toMatchObject({ sent: 0, taken: 0 });
    expect(second.sy).toMatchObject({ sent: 0, taken: 0 });
    expect(outcome(second.sx, second.x)?.equal).toBe(true);
  });

  it('concurrent writes to one field converge and leave the same notice on both', async () => {
    const base = written(emptyReplica('a'), 'r1', { title: 'start' });
    const { x: a0, y: b0 } = await exchange(base, emptyReplica('b'));
    const a = written(a0, 'r1', { title: 'from a' });
    const b = written(b0, 'r1', { title: 'from b' });
    const r = await exchange(a, b);
    expect(fingerprint(r.x)).toBe(fingerprint(r.y));
    expect(r.x.notices).toEqual(r.y.notices);
    expect(r.x.notices).toHaveLength(1);
  });
});

describe('a forged change aborts the exchange and the receiver keeps its replica', () => {
  const setup = async () => {
    const a = written(written(emptyReplica('a'), 'r1', { title: 'real' }), 'r2', {
      title: 'real 2',
    });
    const b = written(emptyReplica('b'), 'mine', { title: 'b data' });
    return { a, b: await signed(b) };
  };

  /** Rewrites the changes inside the changes messages of one side. */
  const forge =
    (side: 'x' | 'y', edit: (c: Record<string, any>, i: number) => void) =>
    (from: 'x' | 'y', msgs: unknown[]): unknown[] =>
      from !== side
        ? msgs
        : msgs.map((m) => {
            const msg = m as { t: string; changes?: Record<string, any>[] };
            if (msg.t === 'changes') msg.changes?.forEach(edit);
            return msg;
          });

  it('altered content (does not match its check value)', async () => {
    const { a, b } = await setup();
    const r = await exchange(a, b, {
      tamper: forge('x', (c, i) => {
        if (i === 1) c.fields = { title: 'forged' };
      }),
    });
    expect(r.sy.refusal).toBe('forged');
    expect(r.y.log).toHaveLength(1); // only its own change: nothing of the exchange was taken
    expect(findRecord(r.y, COL, 'r1')).toBeUndefined();
    expect(findRecord(r.y, COL, 'r2')).toBeUndefined();
    expect(outcome(r.sy, r.y)).toBeUndefined();
    // the other side never received a `done` from the refusing one
    expect(outcome(r.sx, r.x)).toBeUndefined();
  });

  it('a wrong signature (signed by another device)', async () => {
    const { a, b } = await setup();
    const other = await signed(written(emptyReplica('b'), 'zzz', { title: 'x' }));
    const stolen = must(other.log[0]).sig;
    const r = await exchange(a, b, {
      tamper: forge('x', (c, i) => {
        if (i === 0) c.sig = stolen;
      }),
    });
    expect(r.sy.refusal).toBe('forged');
    expect(r.y.log).toHaveLength(1);
  });

  it("a change under the receiver's own id that it does not hold", async () => {
    const { a, b } = await setup();
    const r = await exchange(a, b, {
      tamper: forge('x', (c) => {
        c.device = 'b';
        c.seq = 99;
      }),
    });
    expect(r.sy.refusal).toBe('forged');
    expect(r.y.log).toHaveLength(1);
  });

  it('a forged change in the FIRST of several pieces: still nothing is taken', async () => {
    let a = emptyReplica('a');
    for (let i = 0; i < 30; i += 1) a = written(a, `r${i}`, { title: 'x'.repeat(150) });
    const b = await signed(written(emptyReplica('b'), 'mine', { title: 'b data' }));
    let first = true;
    const r = await exchange(a, b, {
      limits: small,
      tamper: (from, msgs) =>
        from !== 'x'
          ? msgs
          : msgs.map((m) => {
              const msg = m as { t: string; changes?: Record<string, any>[] };
              if (msg.t === 'changes' && first) {
                first = false;
                (msg.changes?.[0] as Record<string, any>).fields = { title: 'forged' };
              }
              return msg;
            }),
    });
    expect(r.sy.refusal).toBe('forged');
    expect(r.y.log).toHaveLength(1);
    expect(r.y.vector.a).toBeUndefined();
  });

  it('an unreadable change (extra member) refuses before any judgement', async () => {
    const { a, b } = await setup();
    const r = await exchange(a, b, {
      tamper: forge('x', (c, i) => {
        if (i === 0) c.extra = 1;
      }),
    });
    expect(r.sy.refusal).toBe('unreadable');
    expect(r.y.log).toHaveLength(1);
  });

  it('a change of an author nobody can check yet is not taken, not stored, and no abort', async () => {
    const stranger = await signed(written(emptyReplica('x'), 'sx', { title: 'from x' }));
    const mixed = merge(emptyReplica('a'), stranger.log).replica;
    const a = await signed(written(mixed, 'r1', { title: 'real' }));
    const known: KeySource = { keyFor: (d) => (d === 'x' ? undefined : pairs[d]?.publicKey) };
    const b0 = emptyReplica('b');
    const parts = pieces(a.log);
    let session = startSession(b0).session;
    let replica = b0;
    for (const part of parts) {
      const step = await receiveJudged(
        session,
        replica,
        json(part),
        judgeFor('b', { keys: known }),
      );
      session = step.session;
      replica = step.replica;
    }
    expect(session.refusal).toBeUndefined();
    expect(session.waiting).toBe(1);
    expect(replica.log.map((c) => c.device)).toEqual(['a']);
    expect(replica.vector.x).toBeUndefined();
  });

  it('the rights hook of the receiver can refuse a change: the exchange aborts', async () => {
    const { a, b } = await setup();
    const parts = pieces((await signed(a)).log);
    const step = await receiveJudged(
      startSession(b).session,
      b,
      json(must(parts[0])),
      judgeFor('b', { mayWrite: () => false }),
    );
    expect(step.session.refusal).toBe('forged');
    expect(step.replica).toBe(b);
  });

  it('more collected changes than maxSessionChanges ends the session as too large', async () => {
    const a = await signed(
      written(written(written(emptyReplica('a'), 'r1', { t: 1 }), 'r2', { t: 2 }), 'r3', { t: 3 }),
    );
    const parts = pieces(a.log, { limits: { maxChanges: 1 } });
    expect(parts).toHaveLength(3);
    const b = emptyReplica('b');
    let step = { session: startSession(b).session, replica: b };
    const options = { limits: { maxSessionChanges: 2 } };
    const outcomes: (string | undefined)[] = [];
    for (const part of parts) {
      step = (await receiveJudged(
        step.session,
        step.replica,
        json(part),
        judgeFor('b'),
        options,
      )) as never;
      outcomes.push(step.session.refusal);
    }
    expect(outcomes).toEqual([undefined, undefined, 'too-large']);
    expect(step.replica.log).toHaveLength(0);
    // exactly at the limit it goes through
    let ok = { session: startSession(b).session, replica: b };
    for (const part of parts) {
      ok = (await receiveJudged(ok.session, ok.replica, json(part), judgeFor('b'), {
        limits: { maxSessionChanges: 3 },
      })) as never;
    }
    expect(ok.session.refusal).toBeUndefined();
    expect(ok.replica.log).toHaveLength(3);
  });
});

describe('random multi-device schedules converge (seeded)', () => {
  const SCHEDULES = 120;
  const stats = { exchanges: 0, removes: 0, notices: 0, changes: 0 };

  async function schedule(seed: number): Promise<void> {
    const rng = prng(seed);
    const replicas: Record<Id, Replica> = {
      a: emptyReplica('a'),
      b: emptyReplica('b'),
      c: emptyReplica('c'),
    };
    const records = ['r1', 'r2', 'r3', 'r4'];
    const steps = 6 + int(rng, 14);
    for (let s = 0; s < steps; s += 1) {
      const id = pick(rng, IDS);
      const r = replicas[id];
      const record = pick(rng, records);
      const op = int(rng, 10);
      const origin = rng() < 0.5 ? { time: int(rng, 1e9), by: id } : {};
      let next: Replica = r;
      if (op < 5) {
        const fields = { [pick(rng, ['title', 'note', 'tags'])]: randomValue(rng) };
        const res = write(r, COL, record, fields, origin);
        if (res.ok) next = res.replica;
      } else if (op < 6) {
        const res = softDelete(r, COL, record, origin);
        if (res.ok) next = res.replica;
      } else if (op < 7) {
        const res = restore(r, COL, record, origin);
        if (res.ok) next = res.replica;
      } else if (op < 8) {
        const entry = historyOf(r, COL, record)[0];
        if (entry) {
          const res = undo(r, COL, record, entry, origin);
          if (res.ok) next = res.replica;
        }
      } else if (op < 9 && rng() < 0.35) {
        next = removed(r, COL, record, origin);
        stats.removes += 1;
      } else {
        const [from, to] = [pick(rng, IDS), pick(rng, IDS)];
        if (from !== to) {
          const result = await exchange(replicas[from], replicas[to], {
            limits: { pieceBytes: pick(rng, [700, 1500, 12000]) },
          });
          expect(result.sx.refusal, `seed ${seed}`).toBeUndefined();
          expect(result.sy.refusal, `seed ${seed}`).toBeUndefined();
          stats.exchanges += 1;
          replicas[from] = result.x;
          replicas[to] = result.y;
        }
        continue;
      }
      replicas[id] = await signed(next);
    }
    // settle: a full round through every pair, twice (a change can need two hops)
    for (let round = 0; round < 2; round += 1) {
      for (const [from, to] of [
        ['a', 'b'],
        ['b', 'c'],
        ['a', 'c'],
      ] as const) {
        const result = await exchange(replicas[from], replicas[to], {
          limits: { pieceBytes: pick(rng, [700, 12000]) },
        });
        expect(result.sx.refusal, `seed ${seed}`).toBeUndefined();
        expect(result.sy.refusal, `seed ${seed}`).toBeUndefined();
        replicas[from] = result.x;
        replicas[to] = result.y;
      }
    }
    stats.notices += replicas.a.notices.length;
    stats.changes += replicas.a.log.length;
    const prints = IDS.map((id) => fingerprint(replicas[id]));
    expect(new Set(prints).size, `seed ${seed}: ${prints.join(' ')}`).toBe(1);
    expect(replicas.b.collections, `seed ${seed}`).toEqual(replicas.a.collections);
    expect(replicas.c.collections, `seed ${seed}`).toEqual(replicas.a.collections);
    expect(replicas.b.notices, `seed ${seed}`).toEqual(replicas.a.notices);
    expect(replicas.b.vector, `seed ${seed}`).toEqual(replicas.a.vector);
    // the data of a converged exchange equals merging every change of every device directly
    const all: Change[] = IDS.flatMap((id) => replicas[id].log);
    const direct = merge(emptyReplica('a'), all).replica;
    expect(fingerprint(direct), `seed ${seed}`).toBe(prints[0]);
  }

  it(`${SCHEDULES} seeded schedules of three devices`, async () => {
    for (let seed = 1; seed <= SCHEDULES; seed += 1) await schedule(seed * 7919);
    // the schedules really did something
    expect(stats.exchanges).toBeGreaterThan(150);
    expect(stats.removes).toBeGreaterThan(10);
    expect(stats.notices).toBeGreaterThan(5);
    expect(stats.changes).toBeGreaterThan(800);
  }, 60_000);
});
