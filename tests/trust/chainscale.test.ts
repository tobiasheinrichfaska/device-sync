// N5: reading a chain of devices that each introduce the next is not quadratic in the work per round:
// a fresh device that is handed the whole chain at once takes seconds, and doubling the chain costs
// about as much again, not four times as much.
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys, publicKeys } from '../../src/core/index.ts';
import { emptyReplica, readChanges, type Change, type JudgeOptions } from '../../src/log/index.ts';
import {
  deviceKeySource,
  deviceNeverErase,
  newDeviceId,
  vouchRoles,
} from '../../src/trust/index.ts';
import { APP, SET, emptyOf, enter, known, opts, type Dev } from './helpers.ts';

const N = 1600;
const VIEWER = 'device-' + '1'.repeat(32);
const VOUCH = opts(vouchRoles(['admin']));

let chain: Dev[];
let log: Change[];

beforeAll(async () => {
  chain = [];
  for (let i = 0; i < N; i += 1) {
    const id = newDeviceId(
      new Uint8Array(16).map((_, k) => (k === 15 ? i & 255 : k === 14 ? i >> 8 : 7)),
    );
    const keys = await generateDeviceKeys();
    chain.push({
      id,
      name: `D${i}`,
      keys,
      intro: { device: id, name: `D${i}`, ...(await publicKeys(keys)) },
    });
  }
  // device i enters device i+1
  log = [];
  for (let i = 0; i < N - 1; i += 1) {
    const d = chain[i] as Dev;
    log.push(...(await enter(d, emptyOf(d), chain[i + 1] as Dev, 'admin', VOUCH)).log);
  }
}, 180_000);

async function read(count: number): Promise<{ ms: number; accepted: number; rejected: number }> {
  const judge: JudgeOptions = {
    appId: APP,
    dataSet: SET,
    ownDevice: VIEWER,
    neverErase: deviceNeverErase(),
    keys: deviceKeySource({ ...VOUCH, direct: [known(chain[0] as Dev, 'admin')] }),
  };
  const started = performance.now();
  // delivered back to front: the worst order, one device becomes checkable per round
  const res = await readChanges(emptyReplica(VIEWER), log.slice(0, count - 1).reverse(), judge);
  return { ms: performance.now() - started, accepted: res.accepted.length, rejected: res.rejected };
}

describe('N5: readChanges of a long voucher chain', () => {
  it(`a chain of ${N} devices is read by a fresh device in seconds, and 800 to ${N} grows less than quadratically`, async () => {
    const half = await read(N / 2);
    const full = await read(N);
    process.stderr.write(
      `\nreadChanges chain: ${N / 2 - 1} changes ${half.ms.toFixed(0)} ms, ${N - 1} changes ${full.ms.toFixed(0)} ms, ratio ${(full.ms / half.ms).toFixed(2)}\n`,
    );
    expect(half).toMatchObject({ accepted: N / 2 - 1, rejected: 0 });
    expect(full).toMatchObject({ accepted: N - 1, rejected: 0 });
    // generous bounds: the old code needed about 25 s here, and a ratio near 4
    expect(full.ms).toBeLessThan(8000);
    expect(full.ms / half.ms).toBeLessThan(3.5);
  }, 120_000);
});
