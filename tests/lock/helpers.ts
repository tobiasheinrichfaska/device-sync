import { generateDeviceKeys, type DeviceKeys } from '../../src/core/index.ts';
import { DAY_MS, lockStart, type LockConfig, type LockState } from '../../src/lock/index.ts';

export { DAY_MS };
export const APP = 'lockdemo';
export const OP = `device-${'a'.repeat(32)}`;
export const SELF = `device-${'b'.repeat(32)}`;
export const OTHER = `device-${'c'.repeat(32)}`;

export const PEER: LockConfig = { source: 'peer', kind: 'device', maxDays: 10, warnDays: 7 };
export const SERVER: LockConfig = {
  source: 'server',
  kind: 'remote',
  maxDays: 10,
  warnDays: 7,
  wipeOn: 'contact',
};

export function start(config: LockConfig, at = 0, local = at): LockState {
  const r = lockStart(config, at, local);
  if (!r.ok) throw new Error(r.reason);
  return r.state;
}

let cached: DeviceKeys | undefined;
export async function operatorKeys(): Promise<DeviceKeys> {
  cached ??= await generateDeviceKeys();
  return cached;
}

export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
