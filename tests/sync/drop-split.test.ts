// A step splits what it sends for the relay: at most 50 recipients per drop, one frame per recipient
// and call, never the own id, nobody twice, every frame within the relay's content limit, a large
// file cut into frames. (The driver did this from the start; these tests pin it.)
import { describe, expect, it } from 'vitest';
import { RELAY_LIMITS, type SyncRelay } from '../../src/index.ts';
import { generateDeviceKeys, publicKeys } from '../../src/core/index.ts';
import { addDevice, newDeviceId } from '../../src/trust/index.ts';
import { queueFile, syncOnce } from '../../src/sync/index.ts';
import { TRUST, rounds, world, type Member } from './helpers.ts';

type DropArgs = Parameters<SyncRelay['drop']>;

describe('what a step drops', () => {
  it('55 peers: calls of at most 50 recipients, none twice in a call, never the own id, every frame within the limit', async () => {
    // a fake relay (the real one takes 50 devices per app, so 55 peers cannot enrol there)
    const calls: DropArgs[0][] = [];
    const w = await world(['A']);
    const a = w.members[0] as Member;
    let r = a.replica;
    for (let i = 0; i < 55; i += 1) {
      const keys = await generateDeviceKeys();
      const intro = {
        device: newDeviceId(new Uint8Array(16).fill(100 + i)),
        name: `P${i}`,
        ...(await publicKeys(keys)),
      };
      const added = addDevice(
        r,
        TRUST,
        intro,
        'member',
        { time: 1 },
        { relayId: `geraet-${(i + 1).toString(16).padStart(32, '0')}` },
      );
      if (!added.ok) throw new Error(added.reason);
      r = added.replica;
    }
    const own = 'geraet-' + 'f'.repeat(32);
    const fake: SyncRelay = {
      deviceId: () => Promise.resolve(own),
      collectAll: (opts) =>
        Promise.resolve({
          ok: true,
          value: { messages: [], present: opts?.ask ?? [], interrupted: undefined },
        } as never),
      drop: (recipients) => {
        calls.push(recipients);
        const results = recipients.map((x) => ({
          device: x.device,
          ok: true as const,
          present: true,
        }));
        return Promise.resolve({
          ok: true,
          value: { results, byDevice: Object.fromEntries(results.map((x) => [x.device, x])) },
        } as never);
      },
    };
    const res = await syncOnce({ ...a.config, relay: fake }, a.state, r, w.now());
    if (!res.ok) throw new Error(res.reason);
    expect(res.report.peers.length).toBe(55);
    expect(calls.length).toBe(2);
    const all = calls.flat();
    expect(new Set(all.map((x) => x.device)).size).toBe(55);
    for (const call of calls) {
      expect(call.length).toBeLessThanOrEqual(50);
      expect(new Set(call.map((x) => x.device)).size).toBe(call.length);
    }
    expect(all.some((x) => x.device === own)).toBe(false);
    for (const x of all) expect(x.content.length).toBeLessThanOrEqual(RELAY_LIMITS.maxContentBytes);
  }, 60_000);

  it('a file of more than a megabyte is cut into frames that each fit the relay', async () => {
    const sizes: number[] = [];
    const w = await world(['A', 'B'], {
      relayWrap: (m, i) =>
        i !== 0
          ? m
          : {
              deviceId: () => m.deviceId(),
              collectAll: async (opts) => {
                const got = await m.collectAll(opts);
                return got.ok
                  ? { ok: true, value: { ...got.value, present: opts?.ask ?? [] } }
                  : got;
              },
              drop: (recipients, opts) => {
                for (const r of recipients) sizes.push(r.content.length);
                return m.drop(recipients, opts);
              },
            },
    });
    const [a, b] = w.members as [Member, Member];
    const big = new Uint8Array(1_200_000).fill(7);
    expect(queueFile(a.config, a.state, b.id, big, w.now())).toEqual({ ok: true });
    await rounds(w, 12, [a]);
    expect(sizes.length).toBeGreaterThan(25);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(RELAY_LIMITS.maxContentBytes);
  }, 60_000);
});
