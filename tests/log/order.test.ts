// Pieces of one session may arrive in any order. The protocol does not promise to take everything in
// such a session, but it must never corrupt a replica: no gap in a device's numbering, nothing taken
// twice, nothing that the sender does not hold, and the next ordinary session fills what is missing.
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  emptyReplica,
  fingerprint,
  insertSignatures,
  merge,
  missingFor,
  onSyncMessage,
  receive,
  receiveJudged,
  signOwnChanges,
  startSession,
  type JudgeOptions,
  type KeySource,
  type Replica,
  type Session,
  type SyncMessage,
} from '../../src/log/index.ts';
import { prng, written } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
// small pieces, so that one session needs several
const SMALL = { limits: { pieceBytes: 260 } };
const pairs: Record<string, CryptoKeyPair> = {};
const keys: KeySource = { keyFor: (device) => pairs[device]?.publicKey };

beforeAll(async () => {
  for (const id of ['a', 'b']) pairs[id] = (await generateDeviceKeys()).signing;
});

const json = (m: unknown): unknown => JSON.parse(JSON.stringify(m));

async function signed(replica: Replica): Promise<Replica> {
  const key = (pairs[replica.device] as CryptoKeyPair).privateKey;
  return insertSignatures(replica, await signOwnChanges(APP, key, replica, SET));
}

/** A replica of `device` with `count` writes to a few records. */
function filled(device: string, count: number, rnd: () => number): Replica {
  let r = emptyReplica(device);
  for (let i = 0; i < count; i += 1) {
    r = written(r, `r${Math.floor(rnd() * 4)}`, {
      title: `${device}${i}`,
      n: Math.floor(rnd() * 9),
    });
  }
  return r;
}

function shuffled<T>(items: readonly T[], rnd: () => number): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rnd() * (i + 1));
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
}

/** The invariants of a replica: gapless numbering per device, no change twice, data = its own log. */
function expectSound(replica: Replica): void {
  const seen = new Set<string>();
  for (const change of replica.log) {
    const id = `${change.device}#${change.seq}`;
    expect(seen.has(id), `${id} twice in the log`).toBe(false);
    seen.add(id);
  }
  for (const [device, top] of Object.entries(replica.vector)) {
    const seqs = replica.log
      .filter((c) => c.device === device)
      .map((c) => c.seq)
      .sort((x, y) => x - y);
    expect(seqs, `numbering of ${device} has a gap`).toEqual(
      Array.from({ length: top }, (_, i) => i + 1),
    );
  }
  const rebuilt = merge(emptyReplica('rebuild'), replica.log).replica;
  expect(fingerprint(rebuilt)).toBe(fingerprint(replica));
}

/** a asks b for what it lacks; b's pieces reach a in the given order, through `deliver`. */
function piecesFor(a: Replica, b: Replica): SyncMessage[] {
  const open = startSession(a);
  const asked = onSyncMessage(startSession(b).session, b, open.send[0] as SyncMessage, SMALL);
  return asked.send.filter((m) => m.t === 'changes');
}

/** An ordinary in-order session in both directions (nothing judged), as the next session would run. */
function plainSession(x: Replica, y: Replica): [Replica, Replica] {
  return [merge(x, missingFor(y, x.vector)).replica, merge(y, missingFor(x, y.vector)).replica];
}

describe('pieces in any order never corrupt a replica (plain session)', () => {
  it('120 random permutations of the pieces: sound, nothing foreign, the next session converges', () => {
    let multi = 0;
    for (let seed = 1; seed <= 120; seed += 1) {
      const rnd = prng(seed);
      const a = filled('a', 2 + Math.floor(rnd() * 5), rnd);
      const b = filled('b', 6 + Math.floor(rnd() * 12), rnd);
      const parts = piecesFor(a, b);
      if (parts.length > 1) multi += 1;
      let step = { session: startSession(a).session, replica: a };
      for (const part of shuffled(parts, rnd)) {
        step = receive(step.session, step.replica, json(part), SMALL);
      }
      expectSound(step.replica);
      // a holds nothing that b does not hold
      for (const change of step.replica.log.filter((c) => c.device === 'b')) {
        expect(b.log.some((c) => c.seq === change.seq && c.device === 'b')).toBe(true);
      }
      const [x, y] = plainSession(step.replica, b);
      expect(fingerprint(x)).toBe(fingerprint(y));
    }
    expect(multi).toBeGreaterThan(60); // the test really split into several pieces
  });

  it('delivered in order, the pieces are all taken in one session', () => {
    const rnd = prng(7);
    const a = filled('a', 2, rnd);
    const b = filled('b', 14, rnd);
    const parts = piecesFor(a, b);
    expect(parts.length).toBeGreaterThan(2);
    let step = { session: startSession(a).session, replica: a };
    for (const part of parts) step = receive(step.session, step.replica, json(part), SMALL);
    expect(step.session.taken).toBe(14);
    expect(step.session.waiting).toBe(0);
  });

  it('every piece twice (duplicates) is harmless', () => {
    const rnd = prng(9);
    const a = filled('a', 1, rnd);
    const b = filled('b', 12, rnd);
    let step = { session: startSession(a).session, replica: a };
    for (const part of piecesFor(a, b).flatMap((p) => [p, p])) {
      step = receive(step.session, step.replica, json(part), SMALL);
    }
    expectSound(step.replica);
    expect(step.session.taken).toBe(12);
  });
});

describe('pieces in any order never corrupt a replica (judged session)', () => {
  const judge: JudgeOptions = { appId: APP, dataSet: SET, keys, ownDevice: 'a' };

  it('60 random permutations: sound, nothing forged taken, the next session converges', async () => {
    for (let seed = 1; seed <= 60; seed += 1) {
      const rnd = prng(1000 + seed);
      const a = await signed(filled('a', 2 + Math.floor(rnd() * 4), rnd));
      const b = await signed(filled('b', 6 + Math.floor(rnd() * 10), rnd));
      const parts = piecesFor(a, b);
      let step = { session: startSession(a).session as Session, replica: a };
      for (const part of shuffled(parts, rnd)) {
        step = await receiveJudged(step.session, step.replica, json(part), judge, SMALL);
      }
      expect(step.session.refusal).toBeUndefined();
      expectSound(step.replica);
      const [x, y] = plainSession(step.replica, b);
      expect(fingerprint(x)).toBe(fingerprint(y));
    }
  });

  it('pieces collected before the last one may come in any order: all are taken', async () => {
    const rnd = prng(31);
    const a = await signed(filled('a', 1, rnd));
    const b = await signed(filled('b', 14, rnd));
    const parts = piecesFor(a, b);
    expect(parts.length).toBeGreaterThan(2);
    const last = parts[parts.length - 1] as SyncMessage;
    const rest = shuffled(parts.slice(0, -1), rnd);
    let step = { session: startSession(a).session as Session, replica: a };
    for (const part of [...rest, last]) {
      step = await receiveJudged(step.session, step.replica, json(part), judge, SMALL);
    }
    expect(step.session.taken).toBe(14);
    expect(step.session.refusal).toBeUndefined();
  });
});
