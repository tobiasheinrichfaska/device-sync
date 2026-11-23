import { randomFillSync } from 'node:crypto';
import { computeTrust } from '../../src/trust/index.ts';
import type { Replica } from '../../src/log/index.ts';
import {
  acceptGrant,
  emptyGroupState,
  type GroupOwn,
  type GroupState,
  type GroupTrust,
  type IssuedGrant,
} from '../../src/group/index.ts';
import {
  dev,
  drop,
  emptyOf,
  enter,
  holding,
  known,
  opts,
  prng,
  APP,
  type Dev,
} from '../trust/helpers.ts';

export { APP, SET, prng } from '../trust/helpers.ts';
export const DATA_SET = 'main';

/** Seeded random bytes: tests are repeatable. */
export function seeded(seed: number): (n: number) => Uint8Array {
  const next = prng(seed);
  return (n) => Uint8Array.from({ length: n }, () => Math.floor(next() * 256));
}

export const realRandom = (n: number): Uint8Array => randomFillSync(new Uint8Array(n));

export const text = (s: string): Uint8Array => new TextEncoder().encode(s);
export const show = (b: Uint8Array): string => new TextDecoder().decode(b);

export interface World {
  readonly devs: readonly Dev[];
  readonly admin: Dev;
  /** The admin's signed replica holding every entry and removal so far. */
  replica: Replica;
  own(d: Dev): GroupOwn;
  /** Trust as `viewer` derives it from the shared replica (the admin was met in person). */
  trustOf(viewer: Dev, version?: number): Promise<GroupTrust>;
  /** Replica versions: 0 is the start, one more after every removal. */
  readonly versions: Replica[];
  remove(d: Dev): Promise<void>;
}

/** The first name is the admin; every other device is entered by it. */
export async function world(names: readonly string[]): Promise<World> {
  const devs: Dev[] = [];
  for (const n of names) devs.push(await dev(n));
  const admin = devs[0] as Dev;
  const o = opts();
  let replica = emptyOf(admin);
  for (const d of devs) {
    replica = await enter(admin, replica, d, d === admin ? 'admin' : 'member', o);
  }
  const versions: Replica[] = [replica];
  const cache = new Map<string, GroupTrust>();
  const w: World = {
    devs,
    admin,
    get replica() {
      return replica;
    },
    set replica(r: Replica) {
      replica = r;
      versions.push(r);
    },
    own: (d) => ({ device: d.id, agreement: d.keys.agreement, signing: d.keys.signing }),
    versions,
    async trustOf(viewer, version = versions.length - 1) {
      const cacheKey = `${viewer.id}/${version}`;
      const hit = cache.get(cacheKey);
      if (hit) return hit;
      const direct = viewer === admin ? [] : [known(admin, 'admin')];
      const t = await computeTrust(holding(viewer, versions[version] as Replica), direct, o);
      const result = { trusted: t.trusted, removed: t.removed, selfRemoved: t.selfRemoved };
      cache.set(cacheKey, result);
      return result;
    },
    async remove(d) {
      replica = await drop(admin, replica, d, o);
      versions.push(replica);
    },
  } as World;
  return w;
}

export const fresh = (): GroupState => emptyGroupState(DATA_SET);

/** Delivers every grant addressed to a device in `devs`; returns the new states by device id. */
export async function deliver(
  w: World,
  states: Map<string, GroupState>,
  grants: readonly IssuedGrant[],
  sender?: undefined,
): Promise<Map<string, string>> {
  void sender;
  const outcome = new Map<string, string>();
  for (const g of grants) {
    const d = w.devs.find((x) => x.id === g.to);
    if (!d) continue;
    const state = states.get(d.id) ?? fresh();
    const r = await acceptGrant({
      appId: APP,
      own: w.own(d),
      trust: await w.trustOf(d),
      state,
      file: g.file,
    });
    outcome.set(d.id, r.ok ? 'ok' : r.reason);
    if (r.ok) states.set(d.id, r.state);
  }
  return outcome;
}
