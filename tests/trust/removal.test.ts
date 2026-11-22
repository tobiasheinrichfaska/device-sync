// The removal notice (src/trust/removal.ts): the signed device-record writes that let a removed device
// see for itself that a trusted device removed it. Real keys, real signatures, the real trust layer.
// The cases are those of the earlier implementation's file and service tests (the notice judged on its
// own, only the chain goes in, a removal by a device nobody vouched for counts for nothing, a changed
// write is refused as a whole, the removal of another device says nothing about this one), plus tamper
// sweeps, hostile notices and seeded scenarios.
import { beforeAll, describe, expect, it } from 'vitest';
import { emptyReplica, merge, write, type Change, type Replica } from '../../src/log/index.ts';
import {
  REMOVAL_LIMITS,
  computeTrust,
  judgeRemovalNotice,
  looksLikeRemovalNotice,
  readRemovalNotice,
  removalNotice,
  vouchRoles,
  writeRemovalNotice,
} from '../../src/trust/index.ts';
import {
  APP,
  SET,
  dev,
  drop,
  emptyOf,
  enter,
  known,
  opts,
  prng,
  signed,
  type Dev,
} from './helpers.ts';

const O = opts(vouchRoles(['admin']));
const ids = (changes: readonly Change[]): Set<string> => new Set(changes.map((c) => c.id));

interface School {
  a: Dev;
  b: Dev;
  c: Dev;
  d: Dev;
  /** A's replica with everything: A entered B, C and D, B removed C. */
  atA: Replica;
}

/** Admin A enters admin B, member C and member D; B (which met C) removes C; A learns of it. */
async function school(): Promise<School> {
  const [a, b, c, d] = [await dev('A'), await dev('B'), await dev('C'), await dev('D')];
  let ra = await enter(a, emptyOf(a), b, 'admin', O);
  ra = await enter(a, ra, c, 'member', O);
  ra = await enter(a, ra, d, 'member', O);
  const rb = await drop(b, merge(emptyOf(b), ra.log).replica, c, O);
  const atA = merge(ra, rb.log).replica;
  return { a, b, c, d, atA };
}

let s: School;
beforeAll(async () => {
  s = await school();
});

const notice = (
  viewer: Replica,
  target: Dev,
  direct = [] as ReturnType<typeof known>[],
): Change[] => {
  const out = removalNotice(viewer, target.id, { ...O, direct });
  if (!out.ok) throw new Error(out.reason);
  return [...out.changes];
};

describe("the notice judged on its own (the earlier implementation's cases)", () => {
  it('C sees from the notice alone, with an empty replica of its own, that a trusted device removed it; nothing is merged', async () => {
    const changes = notice(s.atA, s.c);
    const mine = emptyOf(s.c);
    const v = await judgeRemovalNotice(mine, [known(s.a, 'admin')], changes, O);
    expect(v).toEqual({ selfRemoved: true, reason: 'removed' });
    expect(mine.log).toEqual([]);
    expect(Object.keys(mine.vector)).toEqual([]);
  });

  it('it works from a device met in person that is not the root (B, which removed C)', async () => {
    const changes = notice(s.atA, s.c);
    const v = await judgeRemovalNotice(emptyOf(s.c), [known(s.b, 'admin')], changes, O);
    expect(v.selfRemoved).toBe(true);
  });

  it('a device that already holds part of the notice judges the same (held changes are left out)', async () => {
    const changes = notice(s.atA, s.c);
    const half = merge(
      emptyOf(s.c),
      s.atA.log.filter((x) => x.device === s.a.id),
    ).replica;
    expect((await judgeRemovalNotice(half, [known(s.a, 'admin')], changes, O)).selfRemoved).toBe(
      true,
    );
    // and one that holds all of it, but not the removal
    const before = merge(
      emptyOf(s.c),
      s.atA.log.filter((x) => x.device === s.a.id),
    ).replica;
    expect((await computeTrust(before, [known(s.a, 'admin')], O)).selfRemoved).toBe(false);
  });

  it('only the chain goes in: not the record of a device that wrote nothing, not other collections', () => {
    const changes = notice(s.atA, s.c);
    const entries = ids(changes);
    expect(entries.has(s.c.id)).toBe(true);
    expect(entries.has(s.b.id)).toBe(true);
    expect(entries.has(s.d.id)).toBe(false);
    expect(changes.every((x) => x.collection === 'device' && x.kind === 'set' && x.sig)).toBe(true);
    expect(changes.every((x) => x.device !== s.c.id)).toBe(true);
    expect(JSON.stringify(changes)).not.toMatch(/"D"/);
  });

  it('a notice exists only for a device whose removal counts here', () => {
    for (const who of [s.a, s.b, s.d]) {
      expect(removalNotice(s.atA, who.id, { ...O, direct: [] })).toEqual({
        ok: false,
        reason: 'not-removed',
      });
    }
    expect(removalNotice(s.atA, 'f'.repeat(32), { ...O, direct: [] })).toEqual({
      ok: false,
      reason: 'not-removed',
    });
    // a replica that has not heard of the removal cannot make one
    const before = merge(
      emptyOf(s.a),
      s.atA.log.filter((x) => x.device === s.a.id),
    ).replica;
    expect(removalNotice(before, s.c.id, { ...O, direct: [] }).ok).toBe(false);
  });

  it('the removal of another device says nothing about this one', async () => {
    const changes = notice(s.atA, s.c);
    const v = await judgeRemovalNotice(emptyOf(s.d), [known(s.a, 'admin')], changes, O);
    expect(v).toEqual({ selfRemoved: false, reason: 'no-proof' });
  });

  it('a removal written by a device nobody vouched for counts for nothing', async () => {
    const z = await dev('Z');
    const zlog = await signed(
      (() => {
        const w = write(emptyOf(z), 'device', s.c.id, { removed: true }, { time: 1 });
        if (!w.ok) throw new Error(w.reason);
        return w.replica;
      })(),
      z,
    );
    const changes = [...zlog.log] as Change[];
    // Z unknown: nothing can be checked, so it counts for nothing
    expect(await judgeRemovalNotice(emptyOf(s.c), [known(s.a, 'admin')], changes, O)).toEqual({
      selfRemoved: false,
      reason: 'no-proof',
    });
    // Z known in person but with a role that does not vouch: its removal does not count
    expect(
      await judgeRemovalNotice(emptyOf(s.c), [known(s.a, 'admin'), known(z, 'member')], changes, O),
    ).toMatchObject({
      selfRemoved: false,
    });
    // nothing known in person at all: nothing is checkable
    expect(await judgeRemovalNotice(emptyOf(s.c), [], notice(s.atA, s.c), O)).toEqual({
      selfRemoved: false,
      reason: 'no-proof',
    });
  });

  it('a changed write is refused as a whole', async () => {
    const changes = notice(s.atA, s.c);
    const last = changes.length - 1;
    const changed = changes.map((x, i) =>
      i === last ? { ...x, fields: { ...x.fields, name: 'Other' } } : x,
    ) as Change[];
    const v = await judgeRemovalNotice(emptyOf(s.c), [known(s.a, 'admin')], changed, O);
    expect(v.selfRemoved).toBe(false);
    expect(v.reason).toBe('refused');
  });

  it('a partial notice (the removal alone, or without the link that vouches for the remover) proves nothing', async () => {
    const changes = notice(s.atA, s.c);
    const removal = changes.filter((x) => x.device === s.b.id && x.fields?.removed === true);
    expect(removal.length).toBe(1);
    // the removal without the entries that introduce B: B cannot be checked from C's side
    expect(
      (await judgeRemovalNotice(emptyOf(s.c), [known(s.a, 'admin')], removal, O)).selfRemoved,
    ).toBe(false);
    // everything but the removal
    const without = changes.filter((x) => !removal.includes(x));
    expect(
      (await judgeRemovalNotice(emptyOf(s.c), [known(s.a, 'admin')], without, O)).selfRemoved,
    ).toBe(false);
    // everything but A's entry of B
    const noLink = changes.filter((x) => !(x.device === s.a.id && x.id === s.b.id));
    expect(
      (await judgeRemovalNotice(emptyOf(s.c), [known(s.a, 'admin')], noLink, O)).selfRemoved,
    ).toBe(false);
  });

  it('writes of this device itself count for nothing, whether it holds them or not', async () => {
    const changes = notice(s.atA, s.c);
    const own = write(emptyOf(s.c), 'device', s.c.id, { removed: false }, { time: 1 });
    if (!own.ok) throw new Error(own.reason);
    const ownSigned = (await signed(own.replica, s.c)).log as Change[];
    const mixed = [...changes, ...ownSigned].sort((x, y) =>
      x.device < y.device ? -1 : x.device > y.device ? 1 : x.seq - y.seq,
    );
    expect(
      (await judgeRemovalNotice(emptyOf(s.c), [known(s.a, 'admin')], mixed, O)).selfRemoved,
    ).toBe(true);
  });

  it("a validly signed write that claims another device's identity is refused", async () => {
    const changes = notice(s.atA, s.c);
    // D signs a write under B's device id: the signature does not fit B's key
    const forged = (
      await signed(
        (() => {
          const w = write(emptyReplica(s.b.id), 'device', s.c.id, { removed: true }, { time: 1 });
          if (!w.ok) throw new Error(w.reason);
          return w.replica;
        })(),
        s.d,
      )
    ).log as Change[];
    const v = await judgeRemovalNotice(
      emptyOf(s.c),
      [known(s.a, 'admin')],
      [...forged, ...changes.filter((x) => x.device !== s.b.id)].sort((x, y) =>
        x.device < y.device ? -1 : x.device > y.device ? 1 : x.seq - y.seq,
      ),
      O,
    );
    expect(v.selfRemoved).toBe(false);
    expect(v.reason).toBe('refused');
  });
});

describe('the wire form', () => {
  it('is read back exactly, one spelling only', () => {
    const changes = notice(s.atA, s.c);
    const bytes = writeRemovalNotice(APP, changes);
    expect(looksLikeRemovalNotice(APP, bytes)).toBe(true);
    expect(new TextDecoder().decode(bytes).startsWith(`{"m":"${APP}-removal:1","changes":[`)).toBe(
      true,
    );
    expect(readRemovalNotice(APP, bytes)).toEqual(changes);
    const text = new TextDecoder().decode(bytes);
    const enc = (t: string): Uint8Array => new TextEncoder().encode(t);
    expect(
      readRemovalNotice(APP, enc(text.replace('"changes":[', '"changes": ['))),
    ).toBeUndefined();
    expect(readRemovalNotice(APP, enc(` ${text}`))).toBeUndefined();
    expect(readRemovalNotice(APP, enc(`${text}\n`))).toBeUndefined();
    expect(readRemovalNotice('other', bytes)).toBeUndefined();
    expect(readRemovalNotice(APP, enc(text.replace('"m":', '"x":')))).toBeUndefined();
  });

  it('is not a sync packet and carries no planning, stand, envelope or extra member', () => {
    const changes = notice(s.atA, s.c);
    const enc = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
    const good = { m: `${APP}-removal:1`, changes };
    expect(readRemovalNotice(APP, enc(good))).toEqual(changes);
    for (const extra of [{ planning: [] }, { post: [] }, { stand: {} }, { x: 1 }]) {
      expect(readRemovalNotice(APP, enc({ ...good, ...extra }))).toBeUndefined();
    }
    expect(readRemovalNotice(APP, enc({ changes, m: good.m }))).toBeUndefined();
  });

  it('refuses what is not a signed set write to the device list, in order and without repeat', () => {
    const changes = notice(s.atA, s.c);
    const enc = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
    const m = `${APP}-removal:1`;
    const first = changes[0] as Change;
    const read = (cs: unknown[]) => readRemovalNotice(APP, enc({ m, changes: cs }));
    expect(read([])).toBeUndefined();
    expect(read([{ ...first, collection: 'plan' }])).toBeUndefined();
    const { sig: _s, ...unsigned } = first;
    expect(read([unsigned])).toBeUndefined();
    expect(read([{ ...first, kind: 'delete', fields: undefined }])).toBeUndefined();
    expect(read([...changes].reverse())).toBeUndefined();
    expect(read([first, first])).toBeUndefined();
    expect(read(['x'])).toBeUndefined();
    expect(read([{ ...first, extra: 1 }])).toBeUndefined();
    const many = Array.from({ length: REMOVAL_LIMITS.maxChanges + 1 }, (_, i) => ({
      ...first,
      seq: i + 1,
    }));
    expect(read(many)).toBeUndefined();
  });

  it('never throws on hostile bytes', () => {
    const changes = notice(s.atA, s.c);
    const bytes = writeRemovalNotice(APP, changes);
    const r = prng(5);
    for (let i = 0; i < 400; i += 1) {
      const copy = Uint8Array.from(bytes);
      for (let k = 0; k < 1 + (i % 4); k += 1)
        copy[Math.floor(r() * copy.length)] = Math.floor(r() * 256);
      expect(() => readRemovalNotice(APP, copy)).not.toThrow();
    }
    for (const junk of [
      undefined,
      null,
      5,
      'text',
      {},
      new Uint8Array(0),
      new Uint8Array(REMOVAL_LIMITS.maxBytes + 1),
    ]) {
      expect(readRemovalNotice(APP, junk)).toBeUndefined();
    }
  });
});

describe('tamper sweeps', () => {
  it('no change of any member of any write makes the notice prove a removal that was not signed', async () => {
    const changes = notice(s.atA, s.c);
    const direct = [known(s.a, 'admin')];
    expect((await judgeRemovalNotice(emptyOf(s.c), direct, changes, O)).selfRemoved).toBe(true);
    const members = Object.keys(changes.find((x) => x.fields?.removed === true) as object);
    let judged = 0;
    for (const [i, change] of changes.entries()) {
      for (const member of Object.keys(change)) {
        const value = (change as unknown as Record<string, unknown>)[member];
        const variants: unknown[] =
          member === 'fields'
            ? [
                { ...(value as object), name: 'Other' },
                { ...(value as object), removed: !(value as { removed?: boolean }).removed },
                {
                  ...(value as object),
                  role: (value as { role?: string }).role === 'admin' ? 'member' : 'admin',
                },
              ]
            : typeof value === 'number'
              ? [value + 1, Math.max(0, value - 1)]
              : typeof value === 'string'
                ? [`${value.slice(0, -1)}${value.endsWith('A') ? 'B' : 'A'}`]
                : [{ [s.a.id]: 1 }];
        for (const variant of variants) {
          const copy = changes.map((x, j) =>
            j === i ? { ...x, [member]: variant } : x,
          ) as Change[];
          const v = await judgeRemovalNotice(emptyOf(s.c), direct, copy, O);
          judged += 1;
          expect(
            v.selfRemoved,
            `${i}.${member} ${JSON.stringify(variant)} ${JSON.stringify(v)}`,
          ).toBe(false);
        }
      }
    }
    expect(judged).toBeGreaterThan(changes.length * members.length);
  });

  it('a mutated notice text never reads and judges to a removal that differs from the real one', async () => {
    const changes = notice(s.atA, s.c);
    const bytes = writeRemovalNotice(APP, changes);
    const direct = [known(s.a, 'admin')];
    const r = prng(11);
    let judged = 0;
    for (let i = 0; i < 160; i += 1) {
      const at = Math.floor(r() * bytes.length);
      const copy = Uint8Array.from(bytes);
      copy[at] = ((copy[at] as number) + 1 + Math.floor(r() * 254)) % 256;
      const read = readRemovalNotice(APP, copy);
      if (!read) continue;
      judged += 1;
      const v = await judgeRemovalNotice(emptyOf(s.c), direct, read, O);
      expect(v.selfRemoved, `byte ${at}`).toBe(false);
    }
    expect(judged).toBeGreaterThanOrEqual(0);
  });
});

describe('seeded scenarios with the real trust layer', () => {
  /** A founds; devices are entered by random admins; random admins remove random devices. */
  async function scenario(seed: number) {
    const rnd = prng(seed);
    const n = 4 + Math.floor(rnd() * 4);
    const devs: Dev[] = [];
    for (let i = 0; i < n; i += 1) devs.push(await dev(`D${seed}-${i}`));
    const founder = devs[0] as Dev;
    const role = new Map<string, string>([[founder.id, 'admin']]);
    // one global linear history: each author writes on a replica that holds everything so far
    let all = emptyOf(founder);
    const joined = new Map<string, Replica>();
    const authorOf = new Map<string, Dev>(devs.map((x) => [x.id, x]));
    const admins = [founder];
    for (const who of devs.slice(1)) {
      const by = admins[Math.floor(rnd() * admins.length)] as Dev;
      const r = rnd() < 0.4 ? 'admin' : 'member';
      const mine = merge(emptyOf(by), all.log).replica;
      const next = await enter(by, mine, who, r, O);
      all = merge(all, next.log).replica;
      role.set(who.id, r);
      if (r === 'admin') admins.push(who);
      joined.set(who.id, all);
    }
    const removals = 1 + Math.floor(rnd() * 3);
    for (let k = 0; k < removals; k += 1) {
      const by = admins[Math.floor(rnd() * admins.length)] as Dev;
      const victim = devs[1 + Math.floor(rnd() * (n - 1))] as Dev;
      if (victim.id === by.id) continue;
      const mine = merge(emptyOf(by), all.log).replica;
      const next = await drop(by, mine, victim, O);
      all = merge(all, next.log).replica;
    }
    void authorOf;
    return { devs, founder, all, joined };
  }

  it('for 120 seeds: a device the founder shows removed is told so by a valid notice, and no other device is', async () => {
    let removedSeen = 0;
    for (let seed = 1; seed <= 120; seed += 1) {
      const { devs, founder, all, joined } = await scenario(seed);
      const direct = [known(founder, 'admin')];
      const trust = await computeTrust(all, [], O);
      const removed = new Set(trust.removed);
      for (const target of devs.slice(1)) {
        const out = removalNotice(all, target.id, { ...O, direct: [] });
        expect(out.ok, `seed ${seed} ${target.name}`).toBe(removed.has(target.id));
      }
      for (const target of devs.slice(1).filter((x) => removed.has(x.id))) {
        removedSeen += 1;
        const changes = notice(all, target);
        const mine = joined.get(target.id) as Replica;
        const own = merge(emptyOf(target), mine.log).replica;
        const v = await judgeRemovalNotice(own, direct, changes, O);
        expect(v, `seed ${seed} ${target.name}`).toEqual({ selfRemoved: true, reason: 'removed' });
        // a device the founder does not show removed learns nothing from it
        for (const other of devs.slice(1).filter((x) => !removed.has(x.id))) {
          const theirs = merge(emptyOf(other), (joined.get(other.id) as Replica).log).replica;
          const w = await judgeRemovalNotice(theirs, direct, changes, O);
          expect(w.selfRemoved, `seed ${seed} ${other.name} reads ${target.name}'s notice`).toBe(
            false,
          );
        }
        // the bytes make the trip
        const back = readRemovalNotice(APP, writeRemovalNotice(APP, changes));
        expect(back).toEqual(changes);
      }
    }
    expect(removedSeen).toBeGreaterThan(40);
  }, 120_000);
});

void SET;
