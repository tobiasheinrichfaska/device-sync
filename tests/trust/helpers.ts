import { generateDeviceKeys, publicKeys, type DeviceKeys } from '../../src/core/index.ts';
import {
  emptyReplica,
  insertSignatures,
  merge,
  signOwnChanges,
  write,
  type Replica,
} from '../../src/log/index.ts';
import {
  addDevice,
  newDeviceId,
  removeDevice,
  vouchRoles,
  type DeviceResult,
  type Introduction,
  type KnownDevice,
  type TrustOptions,
  type Voucher,
} from '../../src/trust/index.ts';

export const APP = 'syncdemo';
export const SET = 'main';

export interface Dev {
  readonly id: string;
  readonly name: string;
  readonly keys: DeviceKeys;
  readonly intro: Introduction;
}

let counter = 0;
/** A device with an id made from a counter (never random: tests are repeatable) and real keys. */
export async function dev(name: string): Promise<Dev> {
  const id = newDeviceId(new Uint8Array(16).fill(++counter % 256));
  const keys = await generateDeviceKeys();
  const pub = await publicKeys(keys);
  return { id, name, keys, intro: { device: id, name, ...pub } };
}

export const opts = (voucher: Voucher = vouchRoles(['admin']), extra: Partial<TrustOptions> = {}) =>
  ({ appId: APP, dataSet: SET, voucher, ...extra }) satisfies TrustOptions;

export function ok(result: DeviceResult): Replica {
  if (!result.ok) throw new Error(`refused: ${result.reason}`);
  return result.replica;
}

/** The device's own changes without signature, signed. */
export async function signed(replica: Replica, d: Dev): Promise<Replica> {
  const list = await signOwnChanges(APP, d.keys.signing.privateKey, replica, SET);
  return insertSignatures(replica, list);
}

export const emptyOf = (d: Dev | string): Replica => emptyReplica(typeof d === 'string' ? d : d.id);

/** `author` enters `who` in its own replica and signs it, as a session would before sending. */
export async function enter(
  author: Dev,
  replica: Replica,
  who: Dev,
  role: string | undefined,
  o: TrustOptions = opts(),
  extra: { private?: boolean; relayId?: string } = {},
): Promise<Replica> {
  return signed(
    ok(addDevice(replica, o, who.intro, role, { time: 1, by: author.name }, extra)),
    author,
  );
}

export async function drop(author: Dev, replica: Replica, who: Dev, o: TrustOptions = opts()) {
  return signed(ok(removeDevice(replica, o, who.id, { time: 2 })), author);
}

/** Replica of `viewer` holding all the given logs. */
export const holding = (viewer: Dev | string, ...logs: Replica[]): Replica =>
  logs.reduce((r, x) => merge(r, x.log).replica, emptyOf(viewer));

export const known = (d: Dev, role?: string): KnownDevice => ({
  ...d.intro,
  ...(role !== undefined ? { role } : {}),
  since: '2026-11-10',
  checkCode: '1111 2222 3333 4444 5555',
});

export const names = (list: readonly { name: string; role?: string }[]) => list.map((b) => b.name);

export const writeRaw = (
  r: Replica,
  collection: string,
  id: string,
  fields: Record<string, unknown>,
): Replica => {
  const out = write(r, collection, id, fields, {});
  if (!out.ok) throw new Error(out.reason);
  return out.replica;
};

/** Tiny seeded PRNG (mulberry32). */
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
