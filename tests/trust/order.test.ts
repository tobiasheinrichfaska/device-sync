// The derived trust is a function of the set of changes and of the devices met in person: the order
// the log arrived in, the order records were created in and the order of the met list change nothing.
// Random scenarios: entries by random writers (also non-vouchers, also self-writes), key and relay
// conflicts, removals incl. mutual and cyclic ones, devices met in person.
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys, publicKeys } from '../../src/core/index.ts';
import { merge, type Change, type Replica } from '../../src/log/index.ts';
import {
  DEVICE_COLLECTION,
  computeTrust,
  newDeviceId,
  vouchAnyRole,
  vouchRoles,
  type KnownDevice,
  type Trust,
  type TrustOptions,
} from '../../src/trust/index.ts';
import { emptyOf, known, opts, prng, signed, writeRaw, type Dev } from './helpers.ts';
import { deriveSync } from '../../src/trust/derive.ts';

const POOL = 8;
const SCENARIOS = 400;
const ROLES = ['admin', 'member', 'guest'] as const;
const VIEWER = 'device-' + 'f'.repeat(32);

let pool: Dev[];
beforeAll(async () => {
  pool = [];
  for (let i = 0; i < POOL; i += 1) {
    const id = newDeviceId(new Uint8Array(16).fill(0x40 + i));
    const keys = await generateDeviceKeys();
    pool.push({
      id,
      name: `P${i}`,
      keys,
      intro: { device: id, name: `P${i}`, ...(await publicKeys(keys)) },
    });
  }
});

/** What two runs must agree on, as text (keys sorted, so equal values give equal text). */
function shape(t: Trust): string {
  const entry = (d: Trust['trusted'][number]) =>
    [d.device, d.name, d.sig, d.dh, d.role, d.roleVouched, d.relayId, d.private, d.removed].join(
      '/',
    );
  return JSON.stringify({
    trusted: t.trusted.map(entry),
    checkable: t.checkable.map(entry),
    removed: t.removed,
    selfRemoved: t.selfRemoved,
    cutoffs: [...(t.cutoffs ?? [])].sort(),
    reasons: [...(t.reasons ?? [])].sort(),
  });
}

interface Scenario {
  readonly changes: readonly Change[];
  readonly direct: readonly KnownDevice[];
  readonly options: TrustOptions;
}

async function scenario(seed: number): Promise<Scenario> {
  const rnd = prng(seed);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(rnd() * list.length)] as T;
  const writers = new Map<string, Replica>(pool.map((d) => [d.id, emptyOf(d)]));
  const met = pool.filter(() => rnd() < 0.25);
  if (met.length === 0) met.push(pick(pool));
  const steps = 6 + Math.floor(rnd() * 15);
  for (let i = 0; i < steps; i += 1) {
    const w = rnd() < 0.6 ? pick(met) : pick(pool);
    let mine = writers.get(w.id) as Replica;
    if (rnd() < 0.5) mine = merge(mine, (writers.get(pick(pool).id) as Replica).log).replica;
    const t = rnd() < 0.08 ? w : pick(pool);
    const what = rnd();
    const role = pick(ROLES);
    let fields: Record<string, unknown>;
    if (what < 0.45) fields = { name: t.name, sig: t.intro.sig, dh: t.intro.dh, role };
    else if (what < 0.51) fields = { sig: pick(pool).intro.sig };
    else if (what < 0.55) fields = { dh: pick(pool).intro.dh };
    else if (what < 0.61) fields = { relayId: pick(['relay-1', 'relay-2']) };
    else if (what < 0.66) fields = { role };
    else if (what < 0.95) fields = { removed: true, lastSeq: Math.floor(rnd() * 4) };
    else fields = { removed: false };
    writers.set(w.id, writeRaw(mine, DEVICE_COLLECTION, t.id, fields));
  }
  const changes: Change[] = [];
  for (const d of pool) {
    const r = writers.get(d.id) as Replica;
    if (!r.log.some((c) => c.device === d.id)) continue;
    changes.push(...(await signed(r, d)).log.filter((c) => c.device === d.id));
  }
  const direct = met.map((d) => known(d, rnd() < 0.7 ? 'admin' : pick(ROLES)));
  const strategy = rnd() < 0.8 ? vouchRoles(['admin']) : vouchAnyRole();
  return { changes, direct, options: opts(strategy) };
}

const shuffled = <T>(list: readonly T[], rnd: () => number): T[] => {
  const out = [...list];
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rnd() * (i + 1));
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
};

/** The same replica as if its records had been created in another order (key order of the collection, order of the log). */
function created(replica: Replica, rnd: () => number): Replica {
  const col = replica.collections[DEVICE_COLLECTION] ?? {};
  return {
    ...replica,
    log: shuffled(replica.log, rnd),
    collections: {
      ...replica.collections,
      [DEVICE_COLLECTION]: Object.fromEntries(shuffled(Object.entries(col), rnd)),
    },
  };
}

describe('order independence of the derived trust', () => {
  it(`${SCENARIOS} random scenarios give the same result for every delivery order`, async () => {
    let withRemovals = 0;
    let withConflicts = 0;
    let withDepth = 0;
    let bothRemoved = 0;
    for (let n = 0; n < SCENARIOS; n += 1) {
      const sc = await scenario(1000 + n);
      const rnd = prng(77 + n);
      const orders: Change[][] = [
        [...sc.changes],
        [...sc.changes].reverse(),
        shuffled(sc.changes, rnd),
        shuffled(sc.changes, rnd),
      ];
      const results: string[] = [];
      for (const [i, order] of orders.entries()) {
        let view = emptyOf(VIEWER);
        if (i === 3) view = merge(view, shuffled(sc.changes, rnd).slice(0, 3)).replica;
        view = merge(view, order).replica;
        if (i >= 2) view = created(view, rnd);
        const direct = i % 2 === 1 ? shuffled(sc.direct, rnd) : sc.direct;
        results.push(shape(await computeTrust(view, direct, sc.options)));
      }
      for (const [i, r] of results.entries())
        expect(r, `seed ${1000 + n}, order ${i}`).toBe(results[0]);
      const t = JSON.parse(results[0] as string) as {
        trusted: string[];
        removed: string[];
        reasons: unknown[];
      };
      if (t.removed.length > 0) withRemovals += 1;
      if (t.removed.length > 1) bothRemoved += 1;
      if (t.reasons.some((r) => JSON.stringify(r).includes('conflict'))) withConflicts += 1;
      if (t.trusted.length > sc.direct.length) withDepth += 1;
    }
    // the scenarios are not vacuous
    expect(withRemovals).toBeGreaterThan(60);
    expect(bothRemoved).toBeGreaterThan(10);
    expect(withConflicts).toBeGreaterThan(20);
    expect(withDepth).toBeGreaterThan(100);
    process.stderr.write(
      `\norder test: ${SCENARIOS} scenarios x 4 orders; ${withRemovals} with removals, ${bothRemoved} with several removed, ${withConflicts} with conflicts, ${withDepth} trusting beyond the met devices\n`,
    );
  }, 120_000);

  it('the synchronous run used for local decisions agrees with the checked run', async () => {
    for (let n = 0; n < 60; n += 1) {
      const sc = await scenario(5000 + n);
      const view = merge(emptyOf(VIEWER), sc.changes).replica;
      const checked = shape(await computeTrust(view, sc.direct, sc.options));
      expect(shape(deriveSync(view, sc.direct, sc.options).trust), `seed ${5000 + n}`).toBe(
        checked,
      );
    }
  }, 60_000);
});
