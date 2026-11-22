// A small world for the sync tests: devices with real keys and real signatures, a real relay
// client on the repository's reference server, the real trust layer. Nothing here is a mock of the
// code under test; only the relay can be made to misbehave (`chaotic`).
import { generateDeviceKeys, publicKeys, type DeviceKeys } from '../../src/core/index.ts';
import {
  emptyReplica,
  insertSignatures,
  merge,
  signOwnChanges,
  write,
  type Replica,
} from '../../src/log/index.ts';
import { RelayClient, type CredentialStore, type FetchLike } from '../../src/relay/index.ts';
import {
  newSyncState,
  syncOnce,
  type SyncConfig,
  type SyncRelay,
  type SyncReport,
  type SyncState,
} from '../../src/sync/index.ts';
import {
  addDevice,
  newDeviceId,
  removeDevice,
  vouchRoles,
  type Introduction,
  type KnownDevice,
  type TrustOptions,
} from '../../src/trust/index.ts';
import { mintProof, serverFor } from '../relay/helpers.ts';

export const APP = 'alpha';
export const SET = 'main';
export const ORIGIN = 'https://alpha.example';
export const BASE = 'https://relay.test';

export const TRUST: TrustOptions = { appId: APP, dataSet: SET, voucher: vouchRoles(['admin']) };

export function prng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const seededRandom =
  (seed: number) =>
  (n: number): Uint8Array => {
    const r = prng(seed);
    return Uint8Array.from({ length: n }, () => Math.floor(r() * 256));
  };

/** A random source that never repeats (a counter mixed into a seeded generator). */
export function freshRandom(seed: number): (n: number) => Uint8Array {
  const r = prng(seed);
  return (n) => Uint8Array.from({ length: n }, () => Math.floor(r() * 256));
}

export interface Member {
  readonly name: string;
  readonly id: string;
  readonly keys: DeviceKeys;
  readonly intro: Introduction;
  relayId: string;
  client: RelayClient;
  relay: SyncRelay;
  replica: Replica;
  state: SyncState;
  config: SyncConfig;
  /** Reports of every step, newest last. */
  reports: SyncReport[];
}

const memoryStore = (): CredentialStore => {
  let v: string | undefined;
  return {
    get: () => v,
    set: (t) => {
      v = t;
    },
    remove: () => {
      v = undefined;
    },
  };
};

export interface World {
  readonly server: ReturnType<typeof serverFor>;
  readonly members: Member[];
  now(): number;
  advance(ms: number): void;
}

let counter = 0;
/** Devices A (admin), then members; every one enrolled at the relay, with the device list in place. */
export async function world(
  names: readonly string[],
  opts: {
    relayWrap?: (m: SyncRelay, i: number) => SyncRelay;
    seed?: number;
    /** The last n devices enrol at the relay but are not entered into the device list. */
    outsiders?: number;
  } = {},
): Promise<World> {
  let clock = 1_800_000_000_000;
  const server = serverFor({ now: () => clock });
  const members: Member[] = [];
  const rnd = freshRandom(opts.seed ?? 7);
  for (const [i, name] of names.entries()) {
    const id = newDeviceId(new Uint8Array(16).fill((++counter % 250) + 1));
    const keys = await generateDeviceKeys();
    const intro = { device: id, name, ...(await publicKeys(keys)) };
    const fetchFn: FetchLike = (url, init) => server.fetch(url, init);
    const client = new RelayClient({
      baseUrl: BASE,
      appId: APP,
      origin: ORIGIN,
      fetch: fetchFn,
      store: memoryStore(),
      clock: () => clock,
      random: () => 0.5,
      sleep: () => Promise.resolve(),
    });
    const enrolled = await client.enrol({ proof: await mintProof(APP, clock) });
    if (!enrolled.ok) throw new Error(`enrol ${enrolled.kind}`);
    const relayId = enrolled.value.device;
    const m = {
      name,
      id,
      keys,
      intro,
      relayId,
      client,
      relay: client,
      replica: emptyReplica(id),
      reports: [],
    } as unknown as Member;
    members.push(m);
    void i;
  }
  // The admin (first) enters everybody else with their relay ids; the others start from its log.
  const admin = members[0] as Member;
  let r = admin.replica;
  const inside = members.length - (opts.outsiders ?? 0);
  for (const m of members.slice(1, inside)) {
    const added = addDevice(
      r,
      TRUST,
      m.intro,
      'member',
      { time: 1, by: admin.name },
      { relayId: m.relayId },
    );
    if (!added.ok) throw new Error(added.reason);
    r = added.replica;
  }
  r = insertSignatures(r, await signOwnChanges(APP, admin.keys.signing.privateKey, r, SET));
  admin.replica = r;
  for (const m of members.slice(1)) m.replica = merge(emptyReplica(m.id), r.log).replica;
  const direct: KnownDevice = {
    ...admin.intro,
    role: 'admin',
    relayId: admin.relayId,
    since: '2026-11-10',
    checkCode: '1111 2222 3333 4444 5555',
  };
  for (const [i, m] of members.entries()) {
    m.relay = opts.relayWrap ? opts.relayWrap(m.client, i) : m.client;
    m.state = newSyncState(APP);
    m.config = {
      trust: TRUST,
      own: { device: m.id, keys: m.keys },
      relay: m.relay,
      direct: i === 0 ? [] : [direct],
      random: rnd,
    };
  }
  return {
    server,
    members,
    now: () => clock,
    advance: (ms) => {
      clock += ms;
    },
  };
}

/** One step of a member at the world's clock; the report is kept. */
export async function step(w: World, m: Member): Promise<SyncReport> {
  const res = await syncOnce(m.config, m.state, m.replica, w.now());
  if (!res.ok) throw new Error(`step refused: ${res.reason}`);
  m.replica = res.replica;
  m.reports.push(res.report);
  return res.report;
}

/** Everybody steps in order, the clock moves one second; `n` times. */
export async function rounds(
  w: World,
  n: number,
  who: readonly Member[] = w.members,
): Promise<void> {
  for (let i = 0; i < n; i += 1) {
    for (const m of who) await step(w, m);
    w.advance(1000);
  }
}

/** The device writes a record and signs nothing (the step signs). */
export function note(m: Member, id: string, text: string): void {
  const out = write(m.replica, 'notes', id, { text }, { time: 1, by: m.name });
  if (!out.ok) throw new Error(out.reason);
  m.replica = out.replica;
}

export const text = (m: Member, id: string): unknown =>
  m.replica.collections.notes?.[id]?.fields.text?.value;

/** The admin removes a device (signed at the next step). */
export function removeFrom(m: Member, who: Member): void {
  const out = removeDevice(m.replica, TRUST, who.id, { time: 2 });
  if (!out.ok) throw new Error(out.reason);
  m.replica = out.replica;
}

export const logKey = (m: Member): string =>
  JSON.stringify(Object.entries(m.replica.vector).sort());

/** Visible data of the notes collection, for equality checks between devices. */
export const notesOf = (m: Member): string =>
  JSON.stringify(
    Object.entries(m.replica.collections.notes ?? {})
      .sort()
      .map(([id, rec]) => [id, rec.fields.text?.value ?? null, rec.deleted ?? false]),
  );

/** A relay that misbehaves: loses, duplicates, reorders, forges `from`, loses collect answers. */
export interface Chaos {
  loseDrop: number;
  duplicate: number;
  reorder: number;
  loseCollect: number;
  forgeFrom: number;
}
export function chaotic(
  inner: SyncRelay,
  rnd: () => number,
  c: Chaos,
  others: () => string[],
): SyncRelay {
  return {
    deviceId: () => inner.deviceId(),
    drop: async (recipients, opts) => {
      const kept = recipients.filter(() => rnd() >= c.loseDrop);
      const lost = recipients.filter((r) => !kept.includes(r));
      const real = kept.length > 0 ? await inner.drop(kept, opts) : undefined;
      if (real && !real.ok) return real;
      return {
        ok: true,
        value: (() => {
          const results = recipients.map((r) =>
            lost.includes(r)
              ? { device: r.device, ok: true as const, present: true }
              : (real as unknown as { value: { byDevice: Record<string, never> } }).value.byDevice[
                  r.device
                ]!,
          );
          const byDevice = Object.fromEntries(results.map((x) => [x.device, x]));
          return { results, byDevice } as never;
        })(),
      };
    },
    collectAll: async (opts) => {
      const got = await inner.collectAll(opts);
      if (!got.ok) return got;
      if (rnd() < c.loseCollect) {
        return {
          ok: false,
          kind: 'network',
          token: null,
          status: null,
          class: 'retry',
          retryAfterMs: null,
          attempts: 1,
        };
      }
      let messages = [...got.value.messages];
      messages = messages.flatMap((m) => (rnd() < c.duplicate ? [m, m] : [m]));
      if (rnd() < c.reorder) messages.reverse();
      const ids = others();
      messages = messages.map((m) =>
        rnd() < c.forgeFrom && ids.length > 0
          ? { ...m, from: ids[Math.floor(rnd() * ids.length)] as string }
          : m,
      );
      return { ok: true, value: { ...got.value, messages } };
    },
  };
}
