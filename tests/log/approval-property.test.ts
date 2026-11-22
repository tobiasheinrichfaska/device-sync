// Seeded schedules with random hook decisions: replicas that receive the same changes in any order and
// batching, and decide the same held changes the same way, end with the data of one reference merge
// of the decided list. Plus the invariants that must hold at every step, and the cost.
import { describe, expect, it } from 'vitest';
import { canonical } from '../../src/core/index.ts';
import {
  approve,
  decide,
  emptyReplica,
  fingerprint,
  merge,
  mergeApproved,
  missingFor,
  onSyncMessage,
  pendingApproval,
  remove,
  startSession,
  tipsOf,
  write,
  type ApprovalDecision,
  type Change,
  type Replica,
} from '../../src/log/index.ts';
import { redacted as redactedChange } from '../../src/log/merge.ts';
import { COL, prng } from './helpers.ts';

type Fate = 'apply' | 'reject' | 'approve' | 'rejectLater';

/** A pure function of the change alone, as the docs ask of a hook that is to converge. */
function fateOf(c: Change, seed: number): Fate {
  let h = seed;
  for (const ch of `${c.device}#${c.seq}${c.kind}`) h = (Math.imul(h, 31) + ch.charCodeAt(0)) >>> 0;
  h = Math.imul(h ^ (h >>> 15), 2246822507) >>> 0;
  const n = h % 8;
  // a final deletion cannot be rejected: it is held and approved, or applied
  if (c.kind === 'delete' && (n === 2 || n === 3)) return 'approve';
  return n < 2 ? 'approve' : n === 2 ? 'rejectLater' : n === 3 ? 'reject' : 'apply';
}

const hookFor =
  (seed: number) =>
  (c: Change): ApprovalDecision => {
    const f = fateOf(c, seed);
    return f === 'apply' ? 'apply' : f === 'reject' ? 'reject' : 'hold';
  };

const chooserFor = (seed: number) => (c: Change) =>
  fateOf(c, seed) === 'approve' ? ('approve' as const) : ('reject' as const);

/** Authors three devices with random writes, deletions and syncs; returns the union of every log. */
function schedule(seed: number): Replica {
  const rand = prng(seed);
  const int = (n: number): number => Math.floor(rand() * n);
  const ids = ['a', 'b', 'c'];
  const reps = new Map<string, Replica>(ids.map((d) => [d, emptyReplica(d)]));
  const records = ['r0', 'r1', 'r2', 'r3', 'r4'];
  const steps = 25 + int(40);
  for (let i = 0; i < steps; i += 1) {
    const device = ids[int(3)] as string;
    const r = reps.get(device) as Replica;
    const roll = rand();
    if (roll < 0.55) {
      const res = write(r, COL, records[int(5)] as string, { v: int(100), w: `x${int(9)}` });
      if (res.ok) reps.set(device, res.replica);
    } else if (roll < 0.65) {
      const res = remove(r, COL, records[int(5)] as string);
      if (res.ok) reps.set(device, res.replica);
    } else {
      const other = reps.get(ids[int(3)] as string) as Replica;
      reps.set(device, merge(r, missingFor(other, r.vector)).replica);
    }
  }
  let all = emptyReplica('z');
  for (const r of reps.values()) all = merge(all, missingFor(r, all.vector)).replica;
  for (const r of reps.values()) all = merge(all, missingFor(r, all.vector)).replica;
  return all;
}

const stable = (replica: Replica): string =>
  canonical({
    vector: replica.vector,
    clock: replica.clock,
    collections: replica.collections,
    notices: replica.notices,
    log: [...replica.log]
      .map((c) => ({ ...c }))
      .sort((x, y) => (x.device < y.device ? -1 : x.device > y.device ? 1 : x.seq - y.seq)),
  });

/** The data of the decided list in one plain merge: what every receiver must reach. */
function reference(union: readonly Change[], seed: number): Replica {
  const mapped = union.map((c) => {
    if (c.kind === 'redacted') return c;
    const f = fateOf(c, seed);
    return f === 'apply' || f === 'approve' ? c : redactedChange(c);
  });
  return merge(emptyReplica('o'), mapped).replica;
}

function checkInvariants(replica: Replica, union: readonly Change[], seed: number): void {
  // an erased change of a record that is not deleted exists only through a rejection
  const rejecting = (c: Change): boolean => {
    const f = fateOf(c, seed);
    return f === 'reject' || f === 'rejectLater';
  };
  for (const c of replica.log) {
    if (c.kind !== 'redacted' || replica.collections[c.collection]?.[c.id]?.deleted === true)
      continue;
    const original = union.find((u) => u.device === c.device && u.seq === c.seq) as Change;
    expect(
      original.kind !== 'redacted' && rejecting(original),
      `seed ${seed}: erased ${c.device}#${c.seq} of a live record without a rejection`,
    ).toBe(true);
  }
  const bySeq = new Map<string, number[]>();
  for (const c of replica.log) bySeq.set(c.device, [...(bySeq.get(c.device) ?? []), c.seq]);
  for (const [device, seqs] of bySeq) {
    expect([...seqs].sort((a, b) => a - b)).toEqual(seqs.map((_, i) => i + 1));
    expect(replica.vector[device]).toBe(seqs.length);
  }
  const tips = tipsOf(replica);
  for (const entry of replica.approval?.entries ?? []) {
    const have = replica.vector[entry.change.device] ?? 0;
    // held changes are never claimed: not in the log, above the vector
    expect(entry.change.seq).toBeGreaterThan(have);
    expect(
      replica.log.some((c) => c.device === entry.change.device && c.seq === entry.change.seq),
    ).toBe(false);
  }
  for (const device of Object.keys(tips)) expect(replica.vector[device]).toBeGreaterThan(0);
}

/** Everything that can still change: the data and what is held. */
const progress = (r: Replica): string => stable(r) + canonical(r.approval ?? null);

/**
 * One session as the protocol runs it: the full replica `z` answers the stand of `r`, cut at `cut`
 * changes (a prefix that keeps every group of erased changes whole), and `r` takes the pieces
 * through the hook. Nothing in a test chooses what a batch holds: the sender does.
 */
function session(r: Replica, z: Replica, cut: number, hook: (c: Change) => ApprovalDecision) {
  const answer = onSyncMessage(startSession(z).session, z, startSession(r).send[0] as never, {
    signedOnly: false,
    limits: { maxSessionChanges: cut },
  });
  if (answer.session.refusal) throw new Error(`sender refused: ${answer.session.refusalReason}`);
  let state = startSession(r).session;
  let current = r;
  let held = 0;
  let rejected = 0;
  for (const message of answer.send) {
    const step = onSyncMessage(state, current, message, { approval: { hook } });
    if (step.session.refusal) throw new Error(`receiver refused: ${step.session.refusalReason}`);
    state = step.session;
    current = step.replica;
    held = step.session.approvals?.held ?? 0;
    rejected = step.session.approvals?.rejected ?? 0;
  }
  return { replica: current, held, rejected, more: answer.session.sentMore === true };
}

describe('seeded schedules: random decisions, any cut, same result', () => {
  it('300 schedules x 2 receivers equal one plain merge of the decided list', () => {
    let held = 0;
    let rejected = 0;
    let withDeletion = 0;
    for (let seed = 1; seed <= 300; seed += 1) {
      const z = schedule(seed);
      const union = [...z.log];
      if (union.length === 0) continue;
      if (union.some((c) => c.kind === 'delete')) withDeletion += 1;
      const expected = stable(reference(union, seed));
      for (const name of ['r1', 'r2']) {
        const rand = prng(seed * 7 + name.charCodeAt(1));
        let r = emptyReplica(name);
        const hook = hookFor(seed);
        const choose = chooserFor(seed);
        for (let round = 0; round < 120; round += 1) {
          const done = session(r, z, 1 + Math.floor(rand() * 9), hook);
          held += done.held;
          rejected += done.rejected;
          r = done.replica;
          checkInvariants(r, union, seed);
          if (rand() < 0.3) {
            r = decide(r, (c) => (rand() < 0.5 ? choose(c) : undefined)).replica;
            checkInvariants(r, union, seed);
          }
          if (round % 3 === 2) r = decide(r, choose).replica;
          if (stable(r) === expected && (r.approval?.entries.length ?? 0) === 0) break;
        }
        expect(stable(r), `seed ${seed} ${name}`).toBe(expected);
        expect(r.approval?.entries ?? []).toEqual([]);
        expect(fingerprint(r)).toBe(fingerprint(reference(union, seed)));
      }
    }
    // the schedules really exercised holds, rejections and deletions
    expect(held).toBeGreaterThan(300);
    expect(rejected).toBeGreaterThan(100);
    expect(withDeletion).toBeGreaterThan(50);
    console.log(
      `approval schedules: 300 seeds, ${held} holds, ${rejected} rejections, ${withDeletion} with a deletion`,
    );
  });

  it('whole answers and the state through JSON at every step reach the same data', () => {
    for (let seed = 1000; seed < 1100; seed += 1) {
      const z = schedule(seed);
      if (z.log.length === 0) continue;
      let r = emptyReplica('r');
      for (let i = 0; i < 40; i += 1) {
        const before = progress(r);
        r = JSON.parse(JSON.stringify(r)) as Replica;
        r = decide(session(r, z, 100_000, hookFor(seed)).replica, chooserFor(seed)).replica;
        if (progress(r) === before) break;
      }
      expect(stable(r), `seed ${seed}`).toBe(stable(reference([...z.log], seed)));
    }
  });

  it('the decision timing does not matter: decide after every tiny session', () => {
    for (let seed = 2000; seed < 2060; seed += 1) {
      const z = schedule(seed);
      if (z.log.length < 3) continue;
      let eager = emptyReplica('e');
      for (let round = 0; round < 150; round += 1) {
        const before = progress(eager);
        eager = decide(session(eager, z, 2, hookFor(seed)).replica, chooserFor(seed)).replica;
        if (round > 3 && progress(eager) === before) break;
      }
      expect(stable(eager), `seed ${seed}`).toBe(stable(reference([...z.log], seed)));
    }
  });

  it('approving the held ones named by hand equals the chooser', () => {
    const union = [...schedule(77).log];
    let r = mergeApproved(emptyReplica('r'), union, { hook: hookFor(77) }).replica;
    for (let i = 0; i < 10; i += 1) {
      const names = pendingApproval(r)
        .filter((c) => chooserFor(77)(c) === 'approve' && c.kind !== 'redacted')
        .map((c) => ({ device: c.device, seq: c.seq }));
      r = approve(r, names).replica;
      r = decide(r, chooserFor(77)).replica;
      r = mergeApproved(r, union, { hook: hookFor(77) }).replica;
    }
    expect(stable(decide(r, chooserFor(77)).replica)).toBe(stable(reference(union, 77)));
  });
});

describe('cost', () => {
  function chain(n: number): Change[] {
    let a = emptyReplica('a');
    for (let i = 0; i < n; i += 1) {
      const res = write(a, COL, `r${i % 40}`, { v: i });
      if (res.ok) a = res.replica;
    }
    return [...a.log];
  }
  const big = { maxPending: 100_000, maxChars: 200_000_000 };

  function time(n: number): { hold: number; approveAll: number; again: number } {
    const log = chain(n);
    let t = performance.now();
    let asked = 0;
    const hook = (): ApprovalDecision => {
      asked += 1;
      return 'hold';
    };
    let r = mergeApproved(emptyReplica('b'), log, { hook, ...big }).replica;
    const hold = performance.now() - t;
    expect(pendingApproval(r)).toHaveLength(n);
    t = performance.now();
    // the same changes come again: nobody is asked again
    r = mergeApproved(r, log, { hook, ...big }).replica;
    const again = performance.now() - t;
    expect(asked).toBe(n);
    t = performance.now();
    r = approve(
      r,
      pendingApproval(r).map((c) => ({ device: c.device, seq: c.seq })),
      big,
    ).replica;
    const approveAll = performance.now() - t;
    expect(r.vector).toEqual({ a: n });
    return { hold, approveAll, again };
  }

  it('holding, repeating and approving n changes is linear, not quadratic', () => {
    time(500); // warm up
    const small = time(2000);
    const large = time(8000);
    console.log(
      `approval cost 2000 -> 8000: hold ${small.hold.toFixed(0)}->${large.hold.toFixed(0)} ms, ` +
        `repeat ${small.again.toFixed(0)}->${large.again.toFixed(0)} ms, approve ${small.approveAll.toFixed(0)}->${large.approveAll.toFixed(0)} ms`,
    );
    for (const key of ['hold', 'again', 'approveAll'] as const) {
      expect(large[key]).toBeLessThan(Math.max(small[key] * 12, 400));
    }
    expect(large.hold + large.again + large.approveAll).toBeLessThan(4000);
  });

  it('a call costs what is held (bounded by maxPending), not the whole history', () => {
    const log = chain(2000);
    const hook = (c: Change): ApprovalDecision => (c.seq <= 2000 ? 'hold' : 'apply');
    let r = mergeApproved(emptyReplica('b'), log, { hook }).replica;
    expect(pendingApproval(r)).toHaveLength(2000);
    const start = performance.now();
    // 200 sessions of 500 repeated changes against the full state
    for (let i = 0; i < 200; i += 1) {
      r = mergeApproved(r, log.slice((i * 500) % 1500, ((i * 500) % 1500) + 500), { hook }).replica;
    }
    const took = performance.now() - start;
    console.log(`approval: 200 batches of 500 against 2000 held: ${took.toFixed(0)} ms`);
    expect(took).toBeLessThan(3000);
  });
});
