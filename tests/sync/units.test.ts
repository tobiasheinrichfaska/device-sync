import { describe, expect, it } from 'vitest';
import { RelayClient } from '../../src/relay/index.ts';
import {
  buildRoster,
  looksLikePacket,
  newSyncState,
  readPacket,
  syncOnce,
  totals,
  writePacket,
  writePostPacket,
  isSetName,
} from '../../src/sync/index.ts';
import type { Trust, TrustedDevice } from '../../src/trust/index.ts';
import { APP, TRUST, freshRandom, note, prng, rounds, step, text, world } from './helpers.ts';

const rid = (n: number): string => `geraet-${n.toString(16).padStart(32, '0')}`;
const dev = (n: number, relayId?: string): TrustedDevice => ({
  device: `device-${n.toString(16).padStart(32, '0')}`,
  name: `D${n}`,
  sig: 's'.repeat(87),
  dh: 'd'.repeat(87),
  removed: false,
  private: false,
  ...(relayId === undefined ? {} : { relayId }),
});
const trustOf = (trusted: TrustedDevice[], removed: TrustedDevice[] = []): Trust => ({
  trusted,
  checkable: [...trusted, ...removed],
  removed: removed.map((d) => d.device).sort(),
  selfRemoved: false,
  checkableById: new Map([...trusted, ...removed].map((d) => [d.device, d])),
  reasons: new Map(),
});

describe('roster: who gets content comes from the trust derivation', () => {
  it('trusted devices with a distinct relay id are peers; no relay id, a clash and the own id are left out', () => {
    const own = dev(1, rid(1));
    const t = trustOf([
      own,
      dev(2, rid(2)),
      dev(3),
      dev(4, rid(4)),
      dev(5, rid(4)),
      dev(6, rid(1)),
    ]);
    const r = buildRoster(t, own.device, rid(1));
    expect([...r.peers.keys()]).toEqual([dev(2).device]);
    expect(r.excluded.map((x) => [x.device, x.reason]).sort()).toEqual(
      [
        [dev(3).device, 'no-relay-id'],
        [dev(4).device, 'relay-id-clash'],
        [dev(5).device, 'relay-id-clash'],
        [dev(6).device, 'no-relay-id'],
      ].sort(),
    );
  });

  it('a removed device is no peer, and its relay id is remembered as removed', () => {
    const own = dev(1, rid(1));
    const gone = dev(7, rid(7));
    const r = buildRoster(trustOf([own, dev(2, rid(2))], [gone]), own.device, rid(1));
    expect(r.peers.has(gone.device)).toBe(false);
    expect(r.byRelay.has(rid(7))).toBe(false);
    expect(r.removedRelay.has(rid(7))).toBe(true);
  });
});

describe('packet reader', () => {
  const stand = { t: 'stand' as const, vector: { 'device-a': 2 }, tips: {} };
  const bytes = writePacket(APP, '0123456789abcdef', 'main', stand);
  it('reads what it writes', () => {
    expect(looksLikePacket(APP, bytes)).toBe(true);
    expect(readPacket(APP, bytes)).toMatchObject({
      kind: 'log',
      round: '0123456789abcdef',
      set: 'main',
      message: { t: 'stand' },
    });
  });
  it('refuses another app, a bad round, a member too many, a duplicate key, other bytes', () => {
    const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
    const text = new TextDecoder().decode(bytes);
    expect(readPacket('other', bytes)).toBeUndefined();
    expect(
      readPacket(APP, enc(text.replace('0123456789abcdef', '0123456789ABCDEF'))),
    ).toBeUndefined();
    expect(readPacket(APP, enc(text.slice(0, -1) + ',"x":1}'))).toBeUndefined();
    expect(
      readPacket(APP, enc(text.replace('"r":', '"r":"0123456789abcdef","r":'))),
    ).toBeUndefined();
    expect(readPacket(APP, enc('{}'))).toBeUndefined();
    expect(readPacket(APP, new Uint8Array(0))).toBeUndefined();
    expect(readPacket(APP, 'text')).toBeUndefined();
  });
  it('never throws on 3000 damaged packets', () => {
    const r = prng(3);
    for (let i = 0; i < 3000; i += 1) {
      const copy = Uint8Array.from(bytes);
      for (let k = 0; k < 1 + Math.floor(r() * 3); k += 1)
        copy[Math.floor(r() * copy.length)] = Math.floor(r() * 256);
      const cut = r() < 0.3 ? copy.subarray(0, Math.floor(r() * copy.length)) : copy;
      expect(() => readPacket(APP, cut)).not.toThrow();
    }
  });
});

describe('the step refuses what it cannot do', () => {
  it('not enrolled, a replica of another device, a second call while one runs', async () => {
    const w = await world(['A', 'B']);
    const a = w.members[0]!;
    const bare = new RelayClient({
      baseUrl: 'https://relay.test',
      appId: APP,
      fetch: (u, i) => w.server.fetch(u, i),
      store: { get: () => undefined, set: () => undefined, remove: () => undefined },
      clock: w.now,
    });
    expect(await syncOnce({ ...a.config, relay: bare }, a.state, a.replica, w.now())).toEqual({
      ok: false,
      reason: 'not-enrolled',
    });
    expect(await syncOnce(a.config, a.state, w.members[1]!.replica, w.now())).toEqual({
      ok: false,
      reason: 'bad-input',
    });
    const first = syncOnce(a.config, a.state, a.replica, w.now());
    expect(await syncOnce(a.config, a.state, a.replica, w.now())).toEqual({
      ok: false,
      reason: 'busy',
    });
    expect((await first).ok).toBe(true);
    expect(newSyncState(APP).busy).toBe(false);
  });
});

describe('a device that is not on the device list', () => {
  it('gets nothing, and what it sends is dropped before any merge', async () => {
    const w = await world(['A', 'B', 'Z'], { outsiders: 1 });
    const [a, b, z] = w.members as [any, any, any];
    note(a, 'n1', 'private');
    note(z, 'nz', 'spam');
    let collected = 0;
    for (let i = 0; i < 12; i += 1) {
      await step(w, a);
      await step(w, b);
      collected += (await step(w, z)).collected;
      w.advance(1000);
    }
    expect(text(b, 'n1')).toBe('private');
    expect(text(z, 'n1')).toBeUndefined();
    expect(collected).toBe(0);
    expect(text(a, 'nz')).toBeUndefined();
    expect(text(b, 'nz')).toBeUndefined();
    expect(totals(a.state)['unknown-sender']).toBeGreaterThan(0);
    expect(a.reports.every((r: { peers: readonly string[] }) => !r.peers.includes(z.id))).toBe(
      true,
    );
  });
});

void TRUST;
void freshRandom;
void rounds;

describe('packet reader: sets and the mailbox shape', () => {
  const post = writePostPacket(
    APP,
    '0123456789abcdef',
    `{"m":"${APP}-post:2","t":"days","days":{"2026-11-10":"AAAAAAAAAAAAAAAAAAAAAA"}}`,
  );
  it('reads a mailbox packet and a set name of one spelling', () => {
    expect(readPacket(APP, post)).toMatchObject({ kind: 'post', round: '0123456789abcdef' });
    for (const ok of ['main', 'times:p-1', 'a.b_c', 'A1']) expect(isSetName(ok), ok).toBe(true);
    for (const bad of ['', ' x', 'x y', ':x', '-x', 'x'.repeat(81), 'é', 1, undefined]) {
      expect(isSetName(bad), String(bad)).toBe(false);
    }
  });
  it('refuses a mailbox text that is not a mailbox message, and both member lists mixed', () => {
    const text = new TextDecoder().decode(post);
    const enc = (t: string): Uint8Array => new TextEncoder().encode(t);
    expect(readPacket(APP, enc(text.replaceAll('days', 'dayz')))).toBeUndefined();
    expect(readPacket(APP, enc(text.replace('"post":', '"s":"main","post":')))).toBeUndefined();
    expect(readPacket(APP, enc(text.replace('"post":"', '"post":5,"x":"')))).toBeUndefined();
  });
  it('never throws on 3000 damaged mailbox packets', () => {
    const r = prng(9);
    for (let i = 0; i < 3000; i += 1) {
      const copy = Uint8Array.from(post);
      for (let k = 0; k < 1 + Math.floor(r() * 3); k += 1)
        copy[Math.floor(r() * copy.length)] = Math.floor(r() * 256);
      const cut = r() < 0.3 ? copy.subarray(0, Math.floor(r() * copy.length)) : copy;
      expect(() => readPacket(APP, cut)).not.toThrow();
    }
  });
});
