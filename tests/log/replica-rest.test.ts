// A replica at rest (`readReplica`, `storeReplica`) and moving a data set to a new device id
// (`rehome`). The stored-state cases of the earlier app's tests, re-expressed: kept as JSON and read
// back strictly, own numbers 1..n with the vector naming n, a store that is too big or full, a new
// device id that goes on from the old clock.
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  catchUp,
  emptyReplica,
  insertSignatures,
  merge,
  mergeApproved,
  readReplica,
  readReplicaText,
  rehome,
  remove,
  replicaToStored,
  signOwnChanges,
  snapshot,
  storeReplica,
  write,
  type ApprovalHook,
  type Replica,
} from '../../src/log/index.ts';
import { COL, prng } from './helpers.ts';

const APP = 'restdemo';
const SET = 'main';
const pairs: Record<string, CryptoKeyPair> = {};

beforeAll(async () => {
  for (const id of ['a', 'b', 'c']) pairs[id] = (await generateDeviceKeys()).signing;
});

const okw = (r: ReturnType<typeof write>): Replica => {
  if (!r.ok) throw new Error(r.reason);
  return r.replica;
};
const signed = async (r: Replica): Promise<Replica> =>
  insertSignatures(
    r,
    await signOwnChanges(APP, (pairs[r.device] as CryptoKeyPair).privateKey, r, SET),
  );
const json = (r: Replica): Record<string, unknown> =>
  JSON.parse(JSON.stringify(replicaToStored(r))) as Record<string, unknown>;

/** Two devices with conflicts and a final deletion. */
function busy(): { a: Replica; b: Replica } {
  let a = emptyReplica('a');
  let b = emptyReplica('b');
  for (let i = 0; i < 12; i += 1) {
    a = okw(write(a, COL, `r${i}`, { v: i, tags: ['x', i] }, { time: 1 }));
    b = okw(write(b, COL, `s${i}`, { v: -i - 1 }, { time: 2 }));
  }
  a = merge(a, b.log).replica;
  b = merge(b, a.log).replica;
  a = okw(write(a, COL, 'shared', { v: 'a' }));
  b = okw(write(b, COL, 'shared', { v: 'b' }));
  a = merge(a, b.log).replica;
  const gone = remove(a, COL, 's3');
  if (!gone.ok) throw new Error(gone.reason);
  return { a: gone.replica, b };
}

const same = (x: Replica, y: Replica): void => {
  expect(y.vector).toEqual(x.vector);
  expect(y.clock).toBe(x.clock);
  expect(y.collections).toEqual(x.collections);
  expect(y.notices).toEqual(x.notices);
  expect(y.log.length).toBe(x.log.length);
};

describe('readReplica', () => {
  it('reads back what it wrote: values, vector, clock and notices are rebuilt from the log', async () => {
    const { a } = busy();
    const stored = json(await signed(a));
    const read = readReplica(stored, { device: 'a' });
    if (!read.ok) throw new Error(read.reason);
    same(await signed(a), read.replica);
    // and the text form
    const text = readReplicaText(JSON.stringify(stored), { device: 'a' });
    expect(text.ok).toBe(true);
  });

  it('an empty replica and one that is only somebody else’s data', () => {
    const empty = readReplica(json(emptyReplica('a')), { device: 'a' });
    expect(empty.ok).toBe(true);
    const { b } = busy();
    const foreign = readReplica(json(b), { device: 'a' });
    expect(foreign).toEqual({ ok: false, reason: 'wrong-device' });
  });

  it('refuses a replica of another device, a wrong version and a member too many', () => {
    const { a } = busy();
    const stored = json(a);
    const cases: [unknown, string][] = [
      [{ ...stored, device: 'b' }, 'wrong-device'],
      [{ ...stored, v: 2 }, 'bad-version'],
      [{ ...stored, collections: {} }, 'unknown-member'],
      [{ ...stored, x: 1 }, 'unknown-member'],
      [null, 'not-an-object'],
      ['x', 'not-an-object'],
      [[], 'not-an-object'],
      [{}, 'unknown-member'],
      [{ ...stored, clock: -1 }, 'bad-clock'],
      [{ ...stored, clock: 1.5 }, 'bad-clock'],
      [{ ...stored, clock: 0 }, 'bad-clock'],
      [{ ...stored, log: 'x' }, 'bad-log'],
      [{ ...stored, log: [{ device: 'a' }] }, 'bad-change'],
      [{ ...stored, vector: [] }, 'bad-vector'],
    ];
    for (const [raw, reason] of cases) {
      expect(readReplica(raw, { device: 'a' }), JSON.stringify(reason)).toEqual({
        ok: false,
        reason,
      });
    }
  });

  it('the own numbers must run 1 to n and the vector must name n (a half restored store)', () => {
    const { a } = busy();
    const stored = json(a) as {
      vector: Record<string, number>;
      log: { device: string; seq: number }[];
    };
    const n = stored.vector.a as number;
    // the vector says one more than the log holds
    expect(
      readReplica({ ...stored, vector: { ...stored.vector, a: n + 1 } }, { device: 'a' }),
    ).toEqual({ ok: false, reason: 'own-numbers' });
    // a number of its own missing in the middle
    const hole = stored.log.filter((c) => !(c.device === 'a' && c.seq === 2));
    expect(readReplica({ ...stored, log: hole }, { device: 'a' })).toEqual({
      ok: false,
      reason: 'own-numbers',
    });
    // the vector lower than the log
    expect(
      readReplica({ ...stored, vector: { ...stored.vector, a: n - 1 } }, { device: 'a' }),
    ).toEqual({ ok: false, reason: 'own-numbers' });
    // a number of another device missing, or a vector entry of one that wrote nothing
    const hole2 = stored.log.filter((c) => !(c.device === 'b' && c.seq === 3));
    expect(readReplica({ ...stored, log: hole2 }, { device: 'a' }).ok).toBe(false);
    expect(readReplica({ ...stored, vector: { ...stored.vector, z: 1 } }, { device: 'a' })).toEqual(
      { ok: false, reason: 'vector-mismatch' },
    );
    // a negative or fractional number, a prototype key
    for (const bad of [-1, 1.5]) {
      expect(
        readReplica({ ...stored, vector: { ...stored.vector, b: bad } }, { device: 'a' }).ok,
      ).toBe(false);
    }
    expect(
      readReplica(JSON.parse(`{"v":1,"device":"a","clock":1,"vector":{"__proto__":1},"log":[]}`), {
        device: 'a',
      }).ok,
    ).toBe(false);
  });

  it('a change twice, an unknown member in a change and a clock below a change are refused', () => {
    const { a } = busy();
    const stored = json(a) as { log: Record<string, unknown>[]; clock: number };
    const first = stored.log[0] as Record<string, unknown>;
    expect(readReplica({ ...stored, log: [...stored.log, first] }, { device: 'a' })).toEqual({
      ok: false,
      reason: 'duplicate-change',
    });
    expect(
      readReplica(
        { ...stored, log: [{ ...first, extra: 1 }, ...stored.log.slice(1)] },
        { device: 'a' },
      ),
    ).toEqual({ ok: false, reason: 'bad-change' });
    expect(readReplica({ ...stored, clock: 1 }, { device: 'a' })).toEqual({
      ok: false,
      reason: 'bad-clock',
    });
  });

  it('is bounded: too many changes, too long a text', () => {
    const { a } = busy();
    const stored = json(a);
    expect(readReplica(stored, { device: 'a', maxChanges: 3 })).toEqual({
      ok: false,
      reason: 'too-many-changes',
    });
    expect(readReplicaText(JSON.stringify(stored), { device: 'a', maxChars: 100 })).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect(readReplicaText('{"v":1,"v":1}', { device: 'a' }).ok).toBe(false);
    expect(readReplicaText('not json', { device: 'a' }).ok).toBe(false);
    expect(readReplicaText(5, { device: 'a' }).ok).toBe(false);
  });

  it('a replica that started from a snapshot is read back with its base', async () => {
    let x = emptyReplica('a');
    let y = emptyReplica('b');
    for (let i = 0; i < 8; i += 1) {
      x = okw(write(x, COL, `r${i}`, { v: i }, { time: 1 }));
      y = okw(write(y, COL, `s${i}`, { v: -i - 1 }, { time: 2 }));
    }
    y = await signed(y);
    x = await signed(merge(x, y.log).replica);
    const made = await snapshot(x, {
      appId: APP,
      dataSet: SET,
      signingKey: (pairs.a as CryptoKeyPair).privateKey,
    });
    if (!made.ok) throw new Error(made.reason);
    const caught = await catchUp(emptyReplica('c'), JSON.parse(JSON.stringify(made.snapshot)), {
      judge: {
        appId: APP,
        dataSet: SET,
        keys: { keyFor: (d) => pairs[d]?.publicKey },
        ownDevice: 'c',
        allowFinalDelete: () => true,
      },
      trustProducer: () => true,
    });
    if (!caught.ok) throw new Error(caught.reason);
    const mine = okw(write(caught.replica, COL, 'c1', { v: 'c' }));
    const stored = json(mine);
    expect(stored.base).toBeDefined();
    const read = readReplica(stored, { device: 'c' });
    if (!read.ok) throw new Error(read.reason);
    same(mine, read.replica);
    expect(read.replica.base).toEqual(mine.base);
    // a base that names a device the vector does not, or a number above the vector
    expect(readReplica({ ...stored, base: { zz: 1 } }, { device: 'c' }).ok).toBe(false);
    const high = { ...(stored.base as object), a: 99999 };
    expect(readReplica({ ...stored, base: high }, { device: 'c' }).ok).toBe(false);
    expect(readReplica({ ...stored, base: {} }, { device: 'c' })).toEqual({
      ok: false,
      reason: 'bad-base',
    });
    expect(readReplica({ ...stored, base: [] }, { device: 'c' }).ok).toBe(false);
  });

  it('the approval state is read strictly and may not overlap the log', () => {
    const hold: ApprovalHook = () => 'hold';
    let r = emptyReplica('a');
    const other = okw(write(emptyReplica('b'), COL, 'x', { v: 1 }));
    r = mergeApproved(r, other.log, { hook: hold }).replica;
    expect(r.approval?.entries.length).toBe(1);
    const stored = json(r);
    const read = readReplica(stored, { device: 'a' });
    if (!read.ok) throw new Error(read.reason);
    expect(read.replica.approval?.entries.length).toBe(1);
    expect(readReplica({ ...stored, approval: { entries: 5 } }, { device: 'a' })).toEqual({
      ok: false,
      reason: 'bad-approval',
    });
    expect(readReplica({ ...stored, approval: [] }, { device: 'a' }).ok).toBe(false);
    // the same change both held and in the log
    const logged = { ...stored, log: other.log, clock: 5, vector: { b: 1 } };
    expect(readReplica(logged, { device: 'a' })).toEqual({ ok: false, reason: 'approval-overlap' });
  });

  it('never throws and never returns an inconsistent replica for 3000 seeded damages', () => {
    const { a } = busy();
    const stored = json(a);
    const text = JSON.stringify(stored);
    const r = prng(21);
    let accepted = 0;
    for (let i = 0; i < 3000; i += 1) {
      let value: unknown;
      const kind = Math.floor(r() * 4);
      if (kind === 0) {
        // a damaged character in the text
        const at = Math.floor(r() * text.length);
        const bad =
          text.slice(0, at) + String.fromCharCode(32 + Math.floor(r() * 90)) + text.slice(at + 1);
        try {
          value = JSON.parse(bad);
        } catch {
          continue;
        }
      } else {
        // a structural damage
        const copy = JSON.parse(text) as {
          log: Record<string, unknown>[];
          vector: Record<string, unknown>;
          clock: unknown;
        };
        const pick = Math.floor(r() * copy.log.length);
        if (kind === 1) copy.log.splice(pick, 1);
        else if (kind === 2) copy.log[pick] = { ...copy.log[pick], seq: Math.floor(r() * 40) - 3 };
        else copy.vector[r() < 0.5 ? 'a' : 'b'] = Math.floor(r() * 60) - 5;
        value = copy;
      }
      const out = readReplica(value, { device: 'a' });
      if (!out.ok) continue;
      accepted += 1;
      // whatever it accepts: own numbers 1..n gapless and the vector names n
      const own = out.replica.log
        .filter((c) => c.device === 'a')
        .map((c) => c.seq)
        .sort((x, y) => x - y);
      expect(own.every((seq, k) => seq === k + 1)).toBe(true);
      expect(out.replica.vector.a ?? 0).toBe(own.length);
      for (const [d, n] of Object.entries(out.replica.vector)) {
        const seqs = new Set(out.replica.log.filter((c) => c.device === d).map((c) => c.seq));
        for (let k = 1; k <= n; k += 1) expect(seqs.has(k)).toBe(true);
      }
    }
    expect(accepted).toBeLessThan(3000);
  });
});

describe('storeReplica', () => {
  it('writes the text; a text over the bound is not written; a failing write keeps the old state', async () => {
    const { a } = busy();
    let stored: string | undefined = 'old';
    const ok = await storeReplica((t) => void (stored = t), a);
    expect(ok.ok).toBe(true);
    expect(JSON.parse(stored as string).log.length).toBe(a.log.length);
    stored = 'old';
    const big = await storeReplica((t) => void (stored = t), a, { maxChars: 100 });
    expect(big).toMatchObject({ ok: false, reason: 'too-large' });
    expect(stored).toBe('old');
    const full = await storeReplica(() => {
      throw new Error('quota');
    }, a);
    expect(full).toMatchObject({ ok: false, reason: 'write-failed' });
    const asyncFull = await storeReplica(() => Promise.reject(new Error('quota')), a);
    expect(asyncFull).toMatchObject({ ok: false, reason: 'write-failed' });
    // the replica is never halved: what was written is the whole log
    const text = JSON.stringify(replicaToStored(a));
    expect(text.length).toBe((ok as { chars: number }).chars);
  });
});

describe('rehome', () => {
  it('goes on as another device from the same clock and the same data; the old id stays an author', async () => {
    const { a } = busy();
    const sa = await signed(a);
    const out = rehome(sa, 'device-new');
    if (!out.ok) throw new Error(out.reason);
    expect(out.replica.device).toBe('device-new');
    expect(out.replica.clock).toBe(sa.clock);
    expect(out.replica.log).toBe(sa.log);
    const next = okw(write(out.replica, COL, 'n1', { v: 1 }));
    const last = next.log[next.log.length - 1];
    expect([last?.device, last?.seq]).toEqual(['device-new', 1]);
    expect(last?.clock).toBeGreaterThan(sa.clock);
    // what the old id wrote is intact and the old vector entry stays
    expect(next.vector.a).toBe(sa.vector.a);
  });

  it('refuses a new id that already wrote, a bad id and unsigned own changes', async () => {
    const { a, b } = busy();
    const sa = await signed(a);
    expect(rehome(sa, 'b')).toEqual({ ok: false, reason: 'already-wrote' });
    expect(rehome(a, 'b')).toEqual({ ok: false, reason: 'already-wrote' });
    expect(rehome(sa, '')).toEqual({ ok: false, reason: 'bad-device' });
    expect(rehome(sa, 'has space')).toEqual({ ok: false, reason: 'bad-device' });
    expect(rehome(sa, 'a')).toEqual({ ok: true, replica: sa });
    expect(rehome(a, 'fresh')).toEqual({ ok: false, reason: 'unsigned-changes' });
    expect(rehome(sa, 'fresh', { deviceId: (id) => id.startsWith('dev') })).toEqual({
      ok: false,
      reason: 'bad-device',
    });
    // a vector entry without a log entry counts too (a condensed device)
    const ghost = { ...sa, vector: { ...sa.vector, ghost: 4 } };
    expect(rehome(ghost, 'ghost')).toEqual({ ok: false, reason: 'already-wrote' });
    void b;
  });
});
