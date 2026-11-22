// Three devices, real keys and signatures, the real trust layer, the real relay client against the
// repository's reference server: data written on one device reaches the others through the relay
// alone; limits hold; a removed device gets nothing and is heard no more; a misbehaving relay does
// not corrupt anything.
import { describe, expect, it } from 'vitest';
import { RELAY_LIMITS, readFileHeader, type SyncRelay } from '../../src/index.ts';
import { write } from '../../src/log/index.ts';
import { acceptGrant, emptyGroupState, rotateGroup } from '../../src/group/index.ts';
import {
  groupTrustOf,
  queueFile,
  rotateAfterRemoval,
  rotationStatus,
  totals,
} from '../../src/sync/index.ts';
import {
  APP,
  SET,
  TRUST,
  chaotic,
  freshRandom,
  note,
  notesOf,
  prng,
  removeFrom,
  rounds,
  step,
  text,
  world,
  type Member,
} from './helpers.ts';

const vk = (m: Member): string => JSON.stringify(Object.entries(m.replica.vector).sort());
const three = async (opts: Parameters<typeof world>[1] = {}) => {
  const w = await world(['A', 'B', 'C'], opts);
  return { w, a: w.members[0] as Member, b: w.members[1] as Member, c: w.members[2] as Member };
};

describe('data reaches the other devices through the relay alone', () => {
  it('A writes, B and C take it; every device ends with the same data and vector', async () => {
    const { w, a, b, c } = await three();
    note(a, 'n1', 'hello');
    await rounds(w, 6);
    expect(text(b, 'n1')).toBe('hello');
    expect(text(c, 'n1')).toBe('hello');
    note(c, 'n2', 'from c');
    note(b, 'n3', 'from b');
    await rounds(w, 8);
    for (const m of [a, b, c]) expect(notesOf(m)).toBe(notesOf(a));
    expect(vk(b)).toBe(vk(a));
    // a converged group is quiet: nothing is dropped, nothing refused
    const last = a.reports[a.reports.length - 1]!;
    expect(last.dropped).toEqual({});
  });

  it('a step reports the cadence: fast while frames move, slow when idle, backing off on a failing relay', async () => {
    const { w, a } = await three();
    note(a, 'n1', 'x');
    await rounds(w, 1);
    const first = await step(w, a);
    expect(first.nextMs).toBe(1000);
    await rounds(w, 3);
    w.advance(120_000);
    const quiet = await step(w, a);
    expect(quiet.nextMs).toBe(10_000);
    const failing: SyncRelay = {
      deviceId: () => a.client.deviceId(),
      drop: (r, o) => a.client.drop(r, o),
      collectAll: () =>
        Promise.resolve({
          ok: false as const,
          kind: 'network',
          token: null,
          status: null,
          class: 'retry' as const,
          retryAfterMs: null,
          attempts: 1,
        }),
    };
    const cfg = { ...a.config, relay: failing };
    const { syncOnce } = await import('../../src/sync/index.ts');
    const delays: number[] = [];
    for (let i = 0; i < 5; i += 1) {
      const r = await syncOnce(cfg, a.state, a.replica, w.now());
      if (r.ok) delays.push(r.report.nextMs);
    }
    expect(delays).toEqual([2000, 4000, 8000, 16000, 32000]);
  });
});

describe('limits: nothing over the relay limit, a large log is cut and continues', () => {
  it('every message dropped is within maxContentBytes; a big log arrives over several rounds', async () => {
    const sizes: number[] = [];
    const watch = (inner: SyncRelay): SyncRelay => ({
      deviceId: () => inner.deviceId(),
      collectAll: (o) => inner.collectAll(o),
      drop: (r, o) => {
        for (const x of r) sizes.push(x.content.length);
        return inner.drop(r, o);
      },
    });
    const { w, a, b } = await three({ relayWrap: (m) => watch(m) });
    // about 900 kB of changes: well over the 240 kB budget of one answer
    for (let i = 0; i < 300; i += 1) note(a, `n${i}`, 'x'.repeat(1900) + i);
    // and one change of about 70 kB (40 fields) that needs more than one frame
    const big = write(
      a.replica,
      'blobs',
      'big',
      Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`f${i}`, 'y'.repeat(1900)])),
      { time: 1, by: 'A' },
    );
    if (!big.ok) throw new Error(big.reason);
    a.replica = big.replica;
    await rounds(w, 40);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(RELAY_LIMITS.maxContentBytes);
    expect(notesOf(b)).toBe(notesOf(a));
    expect(b.replica.collections.blobs?.big?.fields.f39?.value).toBe('y'.repeat(1900));
    // it did take more than one round: no single step of B applied everything
    const applied = b.reports.map((r) => r.applied).filter((n) => n > 0);
    expect(applied.length).toBeGreaterThan(1);
    expect(applied.reduce((x, y) => x + y, 0)).toBeGreaterThanOrEqual(301);
  });
});

describe('removal', () => {
  it('C is removed: it gets nothing afterwards, A and B drop what it sends, the key must be rotated', async () => {
    const { w, a, b, c } = await three();
    note(a, 'n1', 'before');
    await rounds(w, 8);
    expect(text(c, 'n1')).toBe('before');

    // a group key held by everybody, given to A, B and C while C was trusted
    const own = { device: a.id, agreement: a.keys.agreement, signing: a.keys.signing };
    const trust0 = (await step(w, a)).trust;
    const random = freshRandom(99);
    const made = await rotateGroup({
      appId: APP,
      own,
      trust: groupTrustOf(trust0),
      state: emptyGroupState(SET),
      random,
    });
    if (!made.ok) throw new Error(made.reason);
    let groupA = made.state;

    removeFrom(a, c);
    const afterRemoval = await step(w, a);
    expect(afterRemoval.newlyRemoved).toEqual([c.id]);
    expect(afterRemoval.peers).toEqual([b.id]);
    expect(afterRemoval.trust.removed).toEqual([c.id]);

    // package-level: the key needs rotating, the adapter says so and does it for the trusted only
    const status = rotationStatus(groupA, afterRemoval.trust, a.id);
    expect(status).toMatchObject({ needed: true, removedHolders: [c.id], lead: true });
    const rotated = await rotateAfterRemoval({
      appId: APP,
      own,
      trust: afterRemoval.trust,
      state: groupA,
      random,
    });
    if (!rotated.ok) throw new Error(rotated.reason);
    groupA = rotated.state;
    expect(rotated.grants.map((g) => g.to)).toEqual([b.id]);
    for (const g of rotated.grants)
      expect(queueFile(a.config, a.state, g.to, g.file, w.now()).ok).toBe(true);
    // a grant for the removed device cannot be queued into the relay path: it is dropped at the step
    const stray = rotated.grants[0]!;
    queueFile(a.config, a.state, c.id, stray.file, w.now());

    const collectedByC: number[] = [];
    note(a, 'n2', 'after removal');
    for (let i = 0; i < 12; i += 1) {
      await step(w, a);
      await step(w, b);
      const r = await step(w, c);
      collectedByC.push(r.collected);
      w.advance(1000);
    }
    expect(text(b, 'n2')).toBe('after removal');
    expect(text(c, 'n2')).toBeUndefined();
    expect(collectedByC.every((n) => n === 0)).toBe(true);
    expect(totals(a.state)['recipient-not-trusted']).toBeGreaterThan(0);
    // B learned the removal through A, with no help from the relay
    expect(b.reports.some((r) => r.newlyRemoved.includes(c.id))).toBe(true);
    // B received the new key as a file that is not a sync packet, from the trusted device A
    const passed = b.reports.flatMap((r) => r.passed);
    expect(passed).toHaveLength(1);
    expect(passed[0]!.from).toBe(a.id);
    const bTrust = b.reports[b.reports.length - 1]!.trust;
    const got = await acceptGrant({
      appId: APP,
      own: { device: b.id, agreement: b.keys.agreement, signing: b.keys.signing },
      trust: groupTrustOf(bTrust),
      state: emptyGroupState(SET),
      file: passed[0]!.file,
    });
    expect(got.ok).toBe(true);
    expect(readFileHeader(APP, passed[0]!.file)?.to).toBe(b.id);

    // C, which does not know it is removed, writes and asks: A and B drop it and merge nothing of it
    note(c, 'n3', 'from the removed');
    for (let i = 0; i < 10; i += 1) {
      await rounds(w, 1);
    }
    expect(text(a, 'n3')).toBeUndefined();
    expect(text(b, 'n3')).toBeUndefined();
    expect(totals(a.state)['removed-sender']).toBeGreaterThan(0);
    expect(totals(b.state)['removed-sender']).toBeGreaterThan(0);
  });

  it('a device that finds itself removed does not even collect', async () => {
    const { w, a, c } = await three();
    note(a, 'n1', 'x');
    await rounds(w, 6);
    removeFrom(a, c);
    await step(w, a);
    // C is handed the removal (by hand, as a file would): from then on it does nothing
    const { merge } = await import('../../src/log/index.ts');
    c.replica = merge(c.replica, a.replica.log).replica;
    let collects = 0;
    c.config = {
      ...c.config,
      relay: {
        deviceId: () => c.client.deviceId(),
        drop: (r, o) => c.client.drop(r, o),
        collectAll: (o) => {
          collects += 1;
          return c.client.collectAll(o);
        },
      },
    };
    const report = await step(w, c);
    expect(report.selfRemoved).toBe(true);
    expect(report.framesSent).toBe(0);
    expect(collects).toBe(0);
    expect(report.dropped['self-removed']).toBe(1);
  });
});

describe('the relay is not believed', () => {
  it('a forged `from` is dropped (unknown sender, or the file names another sender); nothing is merged', async () => {
    const forged: string[] = [];
    const { w, a, b, c } = await three({
      relayWrap: (m, i) =>
        i === 1
          ? {
              deviceId: () => m.deviceId(),
              drop: (r, o) => m.drop(r, o),
              collectAll: async (o) => {
                const got = await m.collectAll(o);
                if (!got.ok) return got;
                // every message of A is said to come from C, and one from somebody the relay made up
                const messages = got.value.messages.map((x, k) => {
                  const from =
                    k % 3 === 2
                      ? `geraet-${'0'.repeat(32)}`
                      : x.from === a.relayId
                        ? c.relayId
                        : a.relayId;
                  forged.push(from);
                  return { ...x, from };
                });
                return { ok: true, value: { ...got.value, messages } };
              },
            }
          : m,
    });
    note(a, 'n1', 'secret');
    await rounds(w, 8);
    expect(forged.length).toBeGreaterThan(0);
    // B is lied to about every sender: it learns nothing through the relay's `from`
    expect(text(b, 'n1')).toBeUndefined();
    const t = totals(b.state);
    expect((t['sender-mismatch'] ?? 0) + (t['unknown-sender'] ?? 0)).toBeGreaterThan(0);
    // C is not disturbed by B's blindness
    expect(text(c, 'n1')).toBe('secret');
  });

  it('a lost collect answer, duplicates and reordering lose nothing: the next round repairs it', async () => {
    const rnd = prng(5);
    const { w, a, b, c } = await three({
      relayWrap: (m) =>
        chaotic(
          m,
          rnd,
          { loseDrop: 0, duplicate: 0.4, reorder: 0.5, loseCollect: 0.3, forgeFrom: 0 },
          () => [],
        ),
    });
    note(a, 'n1', 'one');
    note(b, 'n2', 'two');
    note(c, 'n3', 'three');
    await rounds(w, 40);
    for (const m of [a, b, c]) expect(notesOf(m)).toBe(notesOf(a));
    expect(text(a, 'n3')).toBe('three');
  });
});

describe('seeded schedules converge', () => {
  const SEEDS = 120;
  const batch = async (from: number, to: number): Promise<void> => {
    for (let seed = from; seed < to; seed += 1) {
      const r = prng(seed * 7919 + 1);
      const chaos = {
        loseDrop: r() * 0.25,
        duplicate: r() * 0.3,
        reorder: r() * 0.5,
        loseCollect: r() * 0.25,
        forgeFrom: r() * 0.1,
      };
      const rnd = prng(seed + 1000);
      let ids: string[] = [];
      const { w, a, b, c } = await three({
        seed,
        relayWrap: (m) => chaotic(m, rnd, chaos, () => ids),
      });
      ids = w.members.map((m) => m.relayId);
      const all = [a, b, c];
      // a chaotic phase: random writers, random steps, a clock that sometimes jumps past the relay's 30 s
      for (let i = 0; i < 24; i += 1) {
        const m = all[Math.floor(r() * 3)] as Member;
        if (r() < 0.45) note(m, `n${seed}-${i}`, `v${i}`.repeat(1 + Math.floor(r() * 40)));
        const who = all.filter(() => r() < 0.7);
        for (const x of who) await step(w, x);
        w.advance(r() < 0.1 ? 40_000 : 1000);
      }
      // a calm phase: an honest relay, everybody steps
      const honest = w.members.map((m) => m.client);
      all.forEach((m, i) => {
        m.config = { ...m.config, relay: honest[i] as SyncRelay };
      });
      for (let i = 0; i < 60; i += 1) {
        await rounds(w, 1);
        if (
          notesOf(a) === notesOf(b) &&
          notesOf(a) === notesOf(c) &&
          vk(a) === vk(b) &&
          vk(a) === vk(c)
        )
          break;
      }
      for (const m of [b, c]) expect(notesOf(m), `seed ${seed}`).toBe(notesOf(a));
      expect(vk(b), `seed ${seed}`).toBe(vk(a));
      expect(vk(c), `seed ${seed}`).toBe(vk(a));
      // nobody was ever refused or blamed: a hostile relay is not a forged change
      for (const m of all) expect(totals(m.state)['round-refused'] ?? 0, `seed ${seed}`).toBe(0);
    }
  };
  for (let k = 0; k < SEEDS; k += 30) {
    it(`seeds ${k} to ${k + 29}`, () => batch(k, k + 30), 120_000);
  }
});

void TRUST;
