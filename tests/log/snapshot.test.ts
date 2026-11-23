import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  catchUp,
  condense,
  emptyReplica,
  findRecord,
  fingerprint,
  insertSignatures,
  merge,
  missingFor,
  needsSnapshot,
  parseSnapshot,
  parseSnapshotText,
  receiveJudged,
  remove,
  restore,
  signOwnChanges,
  snapshot,
  softDelete,
  startSession,
  valuesOf,
  write,
  type CatchUpOptions,
  type JudgeOptions,
  type KeySource,
  type Replica,
  type Session,
  type Snapshot,
} from '../../src/log/index.ts';
import { COL, prng } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
const NAMES = ['a', 'b', 'c', 'd', 'x'];
const pairs: Record<string, CryptoKeyPair> = {};
const keySource: KeySource = { keyFor: (device) => pairs[device]?.publicKey };

beforeAll(async () => {
  for (const id of NAMES) pairs[id] = (await generateDeviceKeys()).signing;
});

const judgeFor = (me: string, extra: Partial<JudgeOptions> = {}): JudgeOptions => ({
  appId: APP,
  dataSet: SET,
  keys: keySource,
  ownDevice: me,
  allowFinalDelete: () => true,
  ...extra,
});

const catchOptions = (me: string, extra: Partial<CatchUpOptions> = {}): CatchUpOptions => ({
  judge: judgeFor(me),
  trustProducer: () => true,
  ...extra,
});

async function signed(replica: Replica): Promise<Replica> {
  const key = (pairs[replica.device] as CryptoKeyPair).privateKey;
  return insertSignatures(replica, await signOwnChanges(APP, key, replica, SET));
}

async function snap(replica: Replica): Promise<Snapshot> {
  const own = await signed(replica);
  const made = await snapshot(own, {
    appId: APP,
    dataSet: SET,
    signingKey: (pairs[replica.device] as CryptoKeyPair).privateKey,
  });
  if (!made.ok) throw new Error(`snapshot: ${made.reason}`);
  return JSON.parse(JSON.stringify(made.snapshot)) as Snapshot;
}

const json = (m: unknown): unknown => JSON.parse(JSON.stringify(m));
const okw = (r: ReturnType<typeof write>): Replica => {
  if (!r.ok) throw new Error(`refused ${r.reason}`);
  return r.replica;
};
const w = (r: Replica, id: string, fields: Record<string, unknown>): Replica =>
  okw(write(r, COL, id, fields));

/** One full session between two replicas through the protocol (signed, JSON, judged). */
async function exchange(x: Replica, y: Replica): Promise<[Replica, Replica]> {
  const sides = [
    { replica: await signed(x), session: undefined as Session | undefined, out: [] as unknown[] },
    { replica: await signed(y), session: undefined as Session | undefined, out: [] as unknown[] },
  ];
  for (const side of sides) {
    const step = startSession(side.replica);
    side.session = step.session;
    side.out = step.send.map(json);
  }
  for (let round = 0; round < 50 && sides.some((s) => s.out.length > 0); round += 1) {
    for (const [from, to] of [
      [sides[0]!, sides[1]!],
      [sides[1]!, sides[0]!],
    ] as const) {
      for (const message of from.out.splice(0)) {
        const step = await receiveJudged(
          to.session as Session,
          to.replica,
          message,
          judgeFor(to.replica.device),
        );
        to.session = step.session;
        to.replica = step.replica;
        to.out.push(...step.send.map(json));
      }
    }
  }
  return [sides[0]!.replica, sides[1]!.replica];
}

/** A busy history of two devices: conflicts, equal values, soft and final deletions. */
async function history(): Promise<{ a: Replica; b: Replica }> {
  let a = emptyReplica('a');
  let b = emptyReplica('b');
  for (let i = 0; i < 30; i += 1) {
    a = w(a, `r${i}`, { title: `t${i}`, n: i, tags: ['x', i] });
    b = w(b, `s${i}`, { title: `s${i}`, pos: { x: i } });
  }
  [a, b] = await exchange(a, b);
  // concurrent writes to one field: a conflict (and one with equal values: none)
  a = w(a, 'r1', { title: 'from a' });
  b = w(b, 'r1', { title: 'from b' });
  a = w(a, 'r2', { title: 'same' });
  b = w(b, 'r2', { title: 'same' });
  [a, b] = await exchange(a, b);
  a = w(a, 'r1', { title: 'a again', n: 5 });
  a = okw(softDelete(a, COL, 'r3'));
  b = okw(remove(b, COL, 'r4'));
  b = w(b, 's1', { title: 'b2' });
  a = w(a, 'r4', { late: 'write to a record b deletes' });
  [a, b] = await exchange(a, b);
  b = okw(restore(b, COL, 'r3'));
  b = w(b, 'r5', { title: 'b over a' });
  a = w(a, 'r5', { title: 'a over b' });
  return { a, b };
}

const notices = (r: Replica): unknown[] => JSON.parse(JSON.stringify(r.notices));
const data = (r: Replica): unknown =>
  JSON.parse(JSON.stringify(r.collections, (_k, v: unknown) => v));

describe('snapshot: a late device starts from a condensed state', () => {
  it('gives the same data, notices and stand as the whole log, from a much shorter log', async () => {
    const { a, b } = await history();
    const [full] = await exchange(a, b);
    const made = await snap(full);
    const result = await catchUp(emptyReplica('c'), made, catchOptions('c'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const c = result.replica;
    expect(result.fingerprintChecked).toBe(true);
    expect(fingerprint(c)).toBe(fingerprint(full));
    expect(c.vector).toEqual(full.vector);
    expect(notices(c)).toEqual(notices(full));
    expect(notices(c).length).toBeGreaterThan(0);
    expect(data(c)).toEqual(data(full));

    expect(c.log.length).toBeLessThan(full.log.length);
    expect(c.clock).toBeGreaterThanOrEqual(full.clock);
    expect(findRecord(c, COL, 'r4')?.deleted).toBe(true);
    expect(valuesOf(findRecord(c, COL, 'r2')!).title).toBe('same');
    // the same snapshot as text
    const text = await catchUp(emptyReplica('c'), JSON.stringify(made), catchOptions('c'));
    expect(text.ok).toBe(true);
  });

  it('a device caught up continues: writes, settles old conflicts, deletes, converges', async () => {
    const { a, b } = await history();
    let [fa, fb] = await exchange(a, b);
    const made = await snap(fa);
    const got = await catchUp(emptyReplica('c'), made, catchOptions('c'));
    if (!got.ok) throw new Error(got.reason);
    let c = got.replica;
    // c settles a conflict that predates the snapshot, edits and deletes old records
    const before = notices(c) as { id: string; field: string }[];
    const first = before[0]!;
    c = w(c, first.id, { [first.field]: 'settled by c' });
    c = w(c, 'r7', { title: 'c edit' });
    c = okw(remove(c, COL, 's9'));
    c = w(c, 'new', { title: 'c new' });
    fa = w(fa, 'r7', { title: 'a edit' });
    fb = w(fb, 's8', { title: 'b edit' });
    for (let i = 0; i < 3; i += 1) {
      [fa, c] = await exchange(fa, c);
      [fb, c] = await exchange(fb, c);
      [fa, fb] = await exchange(fa, fb);
    }
    expect(fingerprint(fa)).toBe(fingerprint(fb));
    expect(fingerprint(c)).toBe(fingerprint(fa));
    expect(notices(c)).toEqual(notices(fa));
    expect(notices(fb)).toEqual(notices(fa));
    expect(c.vector).toEqual(fa.vector);
    expect(findRecord(c, COL, 's9')?.deleted).toBe(true);
    expect(findRecord(fa, COL, 's9')?.deleted).toBe(true);
    // the conflict c settled is gone everywhere
    expect(
      (notices(fa) as { id: string; field: string }[]).some(
        (n) => n.id === first.id && n.field === first.field,
      ),
    ).toBe(false);
  });

  it('seeded schedules: a device that starts from a snapshot converges with full-log devices', async () => {
    for (let seed = 1; seed <= 14; seed += 1) {
      const rnd = prng(seed * 7919);
      const pick = <T>(list: readonly T[]): T => list[Math.floor(rnd() * list.length)] as T;
      const reps: Record<string, Replica> = { a: emptyReplica('a'), b: emptyReplica('b') };
      const start = 4 + Math.floor(rnd() * 12);
      const ids = ['p', 'q', 'r', 's', 't', 'u'];
      let step = 0;
      const act = async (): Promise<void> => {
        const who = pick(Object.keys(reps));
        const r = reps[who] as Replica;
        const roll = rnd();
        const id = pick(ids);
        if (roll < 0.5) {
          const res = write(r, COL, id, {
            [pick(['f', 'g', 'h'])]: pick(['u', 'v', 'w']),
            n: Math.floor(rnd() * 3),
          });
          if (res.ok) reps[who] = res.replica;
        } else if (roll < 0.58) {
          const res = softDelete(r, COL, id);
          if (res.ok) reps[who] = res.replica;
        } else if (roll < 0.64) {
          const res = restore(r, COL, id);
          if (res.ok) reps[who] = res.replica;
        } else if (roll < 0.68) {
          const res = remove(r, COL, id);
          if (res.ok) reps[who] = res.replica;
        } else {
          const other = pick(Object.keys(reps).filter((k) => k !== who));
          const [x, y] = await exchange(r, reps[other] as Replica);
          reps[who] = x;
          reps[other] = y;
        }
      };
      for (; step < 40; step += 1) {
        if (step === start) {
          const producer = pick(['a', 'b']);
          const made = await snap(reps[producer] as Replica);
          reps[producer] = await signed(reps[producer] as Replica);
          const got = await catchUp(emptyReplica('c'), made, catchOptions('c'));
          expect(got.ok, `seed ${seed}`).toBe(true);
          if (!got.ok) return;
          reps['c'] = got.replica;
        }
        await act();
      }
      const names = Object.keys(reps);
      for (let round = 0; round < 3; round += 1) {
        for (const x of names) {
          for (const y of names) {
            if (x >= y) continue;
            const [p, q] = await exchange(reps[x] as Replica, reps[y] as Replica);
            reps[x] = p;
            reps[y] = q;
          }
        }
      }
      const fa = fingerprint(reps['a'] as Replica);
      for (const n of names) {
        expect(fingerprint(reps[n] as Replica), `seed ${seed} ${n}`).toBe(fa);
        expect(notices(reps[n] as Replica), `seed ${seed} ${n}`).toEqual(
          notices(reps['a'] as Replica),
        );
        expect((reps[n] as Replica).vector, `seed ${seed} ${n}`).toEqual(
          (reps['a'] as Replica).vector,
        );
      }
    }
  }, 120_000);

  it('moves a replica that is behind forward and keeps what it holds', async () => {
    const { a, b } = await history();
    // d holds the first part, then catches up from a later snapshot
    let d = emptyReplica('d');
    d = (await exchange(d, a))[0];
    const [fa, fb] = await exchange(a, b);
    const more = w(fa, 'r9', { title: 'late' });
    const made = await snap(more);
    const got = await catchUp(d, made, catchOptions('d'));
    if (!got.ok) throw new Error(got.reason);
    expect(got.fingerprintChecked).toBe(false);
    expect(fingerprint(got.replica)).toBe(fingerprint(more));
    expect(notices(got.replica)).toEqual(notices(more));
    expect(fb.vector).toBeDefined();
  });

  it('a snapshot of a caught-up replica is a snapshot again (chain of producers)', async () => {
    const { a, b } = await history();
    const [full] = await exchange(a, b);
    const c = await catchUp(emptyReplica('c'), await snap(full), catchOptions('c'));
    if (!c.ok) throw new Error(c.reason);
    const cw = w(c.replica, 'fresh', { title: 'c wrote' });
    const d = await catchUp(emptyReplica('d'), await snap(cw), catchOptions('d'));
    if (!d.ok) throw new Error(d.reason);
    expect(fingerprint(d.replica)).toBe(fingerprint(cw));
    expect(notices(d.replica)).toEqual(notices(cw));
    expect(d.replica.base).toBeDefined();
  });
});

describe('snapshot: what a caught-up replica can hand out', () => {
  it('serves peers at or above its base, withholds from peers below it', async () => {
    const { a, b } = await history();
    const [full] = await exchange(a, b);
    const got = await catchUp(emptyReplica('c'), await snap(full), catchOptions('c'));
    if (!got.ok) throw new Error(got.reason);
    const c = w(got.replica, 'cw', { title: 'x' });
    // an empty peer lacks everything below the base: it needs a snapshot, it is handed nothing of it
    expect(needsSnapshot(c, {})).toEqual(['a', 'b']);
    expect(missingFor(c, {}).every((ch) => ch.device === 'c')).toBe(true);
    const step = startSession(await signed(c));
    expect(step.send[0]).toBeDefined();
    // a peer at the base is served what is above it
    expect(needsSnapshot(c, full.vector)).toEqual([]);
    expect(missingFor(c, full.vector).map((ch) => ch.device)).toEqual(['c']);
  });
});

describe('snapshot: tampering and hostile snapshots', () => {
  const mutate = (s: Snapshot, edit: (raw: Record<string, unknown>) => void): unknown => {
    const raw = JSON.parse(JSON.stringify(s)) as Record<string, unknown>;
    edit(raw);
    return raw;
  };

  it('every changed member of the head and of every retained change is refused', async () => {
    const { a, b } = await history();
    const [full] = await exchange(a, b);
    const made = await snap(full);
    const refused = async (raw: unknown): Promise<boolean> =>
      !(await catchUp(emptyReplica('c'), raw, catchOptions('c'))).ok;
    expect(await refused(mutate(made, (r) => (r.clock = (r.clock as number) + 1)))).toBe(true);
    expect(await refused(mutate(made, (r) => (r.fingerprint = 'f'.repeat(32))))).toBe(true);
    expect(await refused(mutate(made, (r) => (r.producer = 'b')))).toBe(true);
    expect(await refused(mutate(made, (r) => (r.set = 'other')))).toBe(true);
    expect(await refused(mutate(made, (r) => (r.v = 2)))).toBe(true);
    expect(await refused(mutate(made, (r) => (r.extra = 1)))).toBe(true);
    expect(await refused(mutate(made, (r) => delete r.sig))).toBe(true);
    expect(
      await refused(mutate(made, (r) => ((r.vector as Record<string, number>)['a'] = 1))),
    ).toBe(true);
    expect(
      await refused(mutate(made, (r) => ((r.vector as Record<string, number>)['a'] = 10_000))),
    ).toBe(true);
    expect(
      await refused(mutate(made, (r) => ((r.vector as Record<string, number>)['zz'] = 3))),
    ).toBe(true);
    const list = (r: Record<string, unknown>): Record<string, unknown>[] =>
      r.changes as Record<string, unknown>[];
    let checked = 0;
    for (let i = 0; i < made.changes.length; i += 1) {
      const c = made.changes[i] as Snapshot['changes'][number];
      // dropped, duplicated, swapped with the next one
      expect(await refused(mutate(made, (r) => list(r).splice(i, 1))), `drop ${i}`).toBe(true);
      expect(
        await refused(mutate(made, (r) => list(r).splice(i, 0, list(r)[i]!))),
        `dup ${i}`,
      ).toBe(true);
      if (i + 1 < made.changes.length) {
        expect(
          await refused(
            mutate(made, (r) => {
              const l = list(r);
              [l[i], l[i + 1]] = [l[i + 1]!, l[i]!];
            }),
          ),
          `swap ${i}`,
        ).toBe(true);
      }
      // every member of the change changed
      for (const member of Object.keys(c)) {
        const edited = mutate(made, (r) => {
          const ch = list(r)[i]!;
          const v = ch[member];
          ch[member] =
            typeof v === 'number'
              ? v + 1
              : typeof v === 'string'
                ? v + 'x'
                : v === 'set'
                  ? 'delete'
                  : { zz: 1 };
        });
        expect(await refused(edited), `change ${i} member ${member}`).toBe(true);
        checked += 1;
      }
      expect(await refused(mutate(made, (r) => delete list(r)[i]!.sig)), `unsigned ${i}`).toBe(
        true,
      );
    }
    expect(checked).toBeGreaterThan(50);
  }, 120_000);

  it('refuses a wrong app, a wrong data set, an unknown or untrusted producer', async () => {
    const { a, b } = await history();
    const [full] = await exchange(a, b);
    const made = await snap(full);
    const run = (opts: CatchUpOptions) => catchUp(emptyReplica('c'), made, opts);
    expect((await run(catchOptions('c', { judge: judgeFor('c', { appId: 'otherapp' }) }))).ok).toBe(
      false,
    );
    expect((await run(catchOptions('c', { judge: judgeFor('c', { dataSet: 'other' }) }))).ok).toBe(
      false,
    );
    const untrusted = await run(catchOptions('c', { trustProducer: () => false }));
    expect(untrusted).toEqual({ ok: false, reason: 'untrusted-producer' });
    const thrower = await run(
      catchOptions('c', {
        trustProducer: () => {
          throw new Error('x');
        },
      }),
    );
    expect(thrower).toEqual({ ok: false, reason: 'untrusted-producer' });
    const seenArgs: unknown[] = [];
    await run(
      catchOptions('c', {
        trustProducer: (...args) => (seenArgs.push(args[0], args[1].changes), true),
      }),
    );
    expect(seenArgs[0]).toBe('b' === full.device ? 'b' : 'a');
    const noKey = await run(
      catchOptions('c', { judge: judgeFor('c', { keys: { keyFor: () => undefined } }) }),
    );
    expect(noKey).toEqual({ ok: false, reason: 'unknown-producer' });
    // a key source that knows the producer but not the authors of the retained changes
    const onlyProducer: KeySource = {
      keyFor: (d) => (d === made.producer ? pairs[d]?.publicKey : undefined),
    };
    const partial = await run(catchOptions('c', { judge: judgeFor('c', { keys: onlyProducer }) }));
    expect(partial.ok).toBe(false);
    // one wrong key for another author: that author's changes do not verify
    const swapped: KeySource = {
      keyFor: (d) => (d === 'b' ? pairs['x']?.publicKey : pairs[d]?.publicKey),
    };
    expect((await run(catchOptions('c', { judge: judgeFor('c', { keys: swapped }) }))).ok).toBe(
      false,
    );
  });

  it('the receiver rules (mayWrite, allowFinalDelete, fieldRules) judge the retained changes', async () => {
    const { a, b } = await history();
    const [full] = await exchange(a, b);
    const made = await snap(full);
    const run = (judge: Partial<JudgeOptions>, extra: Partial<CatchUpOptions> = {}) =>
      catchUp(
        emptyReplica('c'),
        made,
        catchOptions('c', { judge: judgeFor('c', judge), ...extra }),
      );
    const noWrite = await run({ mayWrite: (author) => author !== 'b' });
    expect(noWrite).toMatchObject({
      ok: false,
      reason: 'forged',
      rejection: { reason: 'not-allowed' },
    });
    const noDelete = await run({ allowFinalDelete: () => false });
    expect(noDelete).toMatchObject({
      ok: false,
      reason: 'forged',
      rejection: { reason: 'delete-not-allowed' },
    });
    const rules = await run({
      fieldRules: (c) => (c.fields && 'pos' in c.fields ? 'no-late' : undefined),
    });
    expect(rules).toMatchObject({
      ok: false,
      reason: 'forged',
      rejection: { reason: 'field-rules', detail: 'no-late' },
    });
    const viaOptions = await run(
      {},
      { fieldRules: (c) => (c.fields && 'n' in c.fields ? 'no-n' : undefined) },
    );
    expect(viaOptions).toMatchObject({ ok: false, rejection: { detail: 'no-n' } });
  });

  it("a change under the receiver's own id that it does not hold is refused (a restored backup)", async () => {
    const { a, b } = await history();
    const [full] = await exchange(a, b);
    const made = await snap(full);
    const result = await catchUp(emptyReplica('a'), made, catchOptions('a'));
    expect(result).toMatchObject({
      ok: false,
      reason: 'forged',
      rejection: { reason: 'own-history' },
    });
  });

  it('what no check can show: a producer that signs a condensed state with a write left out', async () => {
    // The retained changes are all real and signed, but a producer that leaves one out (and signs
    // the fingerprint of the data it actually shows) is believed: that is why the producer is trusted.
    const { a, b } = await history();
    const [full] = await exchange(a, b);
    const made = await snap(full);
    const keyOf = (pairs[made.producer] as CryptoKeyPair).privateKey;
    const { signText } = await import('../../src/core/index.ts');
    const { snapshotSigningText } = await import('../../src/log/index.ts');
    // leave out the last write of one field of a record (the record keeps an older value)
    const victim = made.changes.findIndex(
      (c) =>
        c.kind === 'set' &&
        c.collection === COL &&
        c.fields &&
        'title' in c.fields &&
        c.device === 'a' &&
        c.id === 'r1',
    );
    expect(victim).toBeGreaterThanOrEqual(0);
    const tails = new Set(Object.entries(made.vector).map(([d, s]) => `${d}#${s}`));
    const droppable = made.changes.findIndex(
      (c, i) => i >= 0 && c.kind === 'set' && !tails.has(`${c.device}#${c.seq}`) && c.id === 'r5',
    );
    const index = droppable >= 0 ? droppable : victim;
    const changes = made.changes.filter((_, i) => i !== index);
    const body = { ...made, changes };
    // carelessly left out, signed with the true fingerprint: a device that starts empty notices
    const careless = { ...body, sig: await signText(keyOf, snapshotSigningText(APP, body, SET)) };
    const caught = await catchUp(emptyReplica('c'), json(careless), catchOptions('c'));
    expect(caught).toEqual({ ok: false, reason: 'inconsistent' });
  });
});

describe('snapshot: strict reader and limits', () => {
  it('reads only what it can verify the shape of; never throws', async () => {
    const { a, b } = await history();
    const [full] = await exchange(a, b);
    const made = await snap(full);
    expect(parseSnapshot(made)).toBeDefined();
    expect(parseSnapshotText(JSON.stringify(made))).toBeDefined();
    for (const junk of [
      null,
      1,
      'x',
      [],
      {},
      { ...made, changes: 'no' },
      { ...made, vector: [] },
    ]) {
      expect(parseSnapshot(junk)).toBeUndefined();
    }
    expect(parseSnapshotText(42)).toBeUndefined();
    expect(parseSnapshotText('{')).toBeUndefined();
    // a key twice
    const text = JSON.stringify(made).replace('"v":1', '"v":1,"v":1');
    expect(parseSnapshotText(text)).toBeUndefined();
    // limits
    expect(parseSnapshot(made, { limits: { maxSnapshotChanges: 3 } })).toBeUndefined();
    expect(parseSnapshot(made, { limits: { maxSnapshotChars: 500 } })).toBeUndefined();
    expect(
      parseSnapshotText('x'.repeat(2000), { limits: { maxSnapshotChars: 500 } }),
    ).toBeUndefined();
    const own = await signed(full);
    const tooBig = await snapshot(own, {
      appId: APP,
      dataSet: SET,
      signingKey: (pairs['a'] as CryptoKeyPair).privateKey,
      limits: { maxSnapshotChanges: 3 },
    });
    expect(tooBig).toEqual({ ok: false, reason: 'too-large' });
    // a getter that throws
    const hostile = { ...made } as Record<string, unknown>;
    Object.defineProperty(hostile, 'changes', {
      get() {
        throw new Error('boom');
      },
      enumerable: true,
    });
    expect(parseSnapshot(hostile)).toBeUndefined();
  });

  it('refuses to make a snapshot of a log with an unsigned change', async () => {
    const r = w(emptyReplica('a'), 'one', { t: 1 });
    expect(condense(r)).toBe('unsigned');
    const made = await snapshot(r, {
      appId: APP,
      dataSet: SET,
      signingKey: (pairs['a'] as CryptoKeyPair).privateKey,
    });
    expect(made).toEqual({ ok: false, reason: 'unsigned' });
  });
});

describe('snapshot: size and speed', () => {
  it('3000 records with 4 writes each condense to the current state; catching up stays fast', async () => {
    let a = emptyReplica('a');
    for (let round = 0; round < 4; round += 1) {
      for (let i = 0; i < 3000; i += 1) a = w(a, `k${i}`, { title: `v${round}-${i}`, n: round });
    }
    a = await signed(a);
    const t0 = performance.now();
    const made = await snap(a);
    const t1 = performance.now();
    const got = await catchUp(emptyReplica('c'), made, catchOptions('c'));
    const t2 = performance.now();
    if (!got.ok) throw new Error(got.reason);
    expect(a.log.length).toBe(12000);
    expect(made.changes.length).toBeLessThan(3010);
    expect(fingerprint(got.replica)).toBe(fingerprint(a));
    expect(t1 - t0).toBeLessThan(15_000);
    expect(t2 - t1).toBeLessThan(30_000);
    expect(merge(got.replica, []).applied).toBe(0);
  }, 120_000);
});
