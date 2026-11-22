// Round 3, part B: the trust derivation is order independent (T1), a voucher cannot replace another
// device's keys (T2), local writing decides against the derived state (T3), the derivation is
// linear (T4). The write cut-off of the removal (L5) was taken out again in round 3, third pass.
import { beforeAll, describe, expect, it } from 'vitest';
import { base64url, generateDeviceKeys, publicKeys, checkCode } from '../../src/core/index.ts';
import {
  emptyReplica,
  insertSignatures,
  merge,
  readChanges,
  write,
  signOwnChanges,
  type Change,
  type JudgeOptions,
} from '../../src/log/index.ts';
import { deriveSync } from '../../src/trust/derive.ts';
import {
  DEVICE_COLLECTION,
  addDevice,
  computeTrust,
  deviceKeySource,
  deviceNeverErase,
  deviceStatus,
  listDevices,
  newDeviceId,
  removeDevice,
  vouchRoles,
  type TrustOptions,
} from '../../src/trust/index.ts';
import {
  APP,
  SET,
  dev,
  drop,
  emptyOf,
  enter,
  holding,
  known,
  names,
  ok,
  opts,
  signed,
  writeRaw,
  type Dev,
} from './helpers.ts';

const O: TrustOptions = opts(vouchRoles(['admin']));
const VOUCH_ADMIN = O;
const VIEWER = 'device-' + '1'.repeat(32);

describe('T1: removal is order independent (equal rank: mutual removal removes both, no id tie-break)', () => {
  let a: Dev, b: Dev, r: Dev;
  beforeAll(async () => {
    [a, b, r] = [await dev('A'), await dev('B'), await dev('R')];
  });

  for (const order of ['R then A', 'A then R'] as const) {
    it(`B enters ${order}; A removes R, R marks A removed: both of equal rank are removed, whatever their ids, B stays trusted`, async () => {
      let rb = emptyOf(b);
      const first = order === 'R then A' ? r : a;
      const second = order === 'R then A' ? a : r;
      rb = await enter(b, rb, first, 'admin');
      rb = await enter(b, rb, second, 'admin');
      const ra = await drop(a, merge(emptyOf(a), rb.log).replica, r);
      let rr = merge(emptyOf(r), rb.log).replica;
      rr = await signed(writeRaw(rr, DEVICE_COLLECTION, a.id, { removed: true }), r);
      const t = await computeTrust(holding(VIEWER, rb, ra, rr), [known(b, 'admin')], O);
      expect(names(t.trusted)).toEqual(['B']);
      expect(t.removed).toEqual([a.id, r.id].sort());
    });
  }

  it('both met in person and removing each other: both are removed, deterministically (no id decides)', async () => {
    const ra = await drop(a, await enter(a, emptyOf(a), r, 'admin'), r);
    const rr = await drop(r, await enter(r, emptyOf(r), a, 'admin'), a);
    const t = await computeTrust(
      holding(VIEWER, ra, rr),
      [known(a, 'admin'), known(r, 'admin')],
      O,
    );
    expect(names(t.trusted)).toEqual([]);
    expect(t.removed).toEqual([a.id, r.id].sort());
  });
});

describe('T2: a voucher cannot replace another device key', () => {
  let b: Dev, m: Dev, v: Dev;
  beforeAll(async () => {
    [b, m, v] = [await dev('B'), await dev('M'), await dev('V')];
  });

  for (const field of ['sig', 'dh'] as const) {
    for (const order of ['M then V', 'V then M'] as const) {
      it(`M writes its own ${field} into the entry of V (${order}): V is not trusted through the chain`, async () => {
        let rb = emptyOf(b);
        const [x, y] = order === 'M then V' ? [m, v] : [v, m];
        rb = await enter(b, rb, x, x === m ? 'admin' : 'member');
        rb = await enter(b, rb, y, y === m ? 'admin' : 'member');
        let rm = merge(emptyOf(m), rb.log).replica;
        rm = await signed(writeRaw(rm, DEVICE_COLLECTION, v.id, { [field]: m.intro[field] }), m);
        const view = holding(VIEWER, rb, rm);
        const t = await computeTrust(view, [known(b, 'admin')], O);
        expect(names(t.trusted)).toEqual(['B', 'M']);
        expect(names(t.checkable)).toEqual(['B', 'M']);
      });
    }
  }

  it('a change signed by M as V is not accepted; V own change waits (neither is taken)', async () => {
    let rb = await enter(b, emptyOf(b), m, 'admin');
    rb = await enter(b, rb, v, 'member');
    let rm = merge(emptyOf(m), rb.log).replica;
    rm = await signed(writeRaw(rm, DEVICE_COLLECTION, v.id, { sig: m.intro.sig }), m);
    const viewer = holding(VIEWER, rb, rm);
    const judge: JudgeOptions = {
      appId: APP,
      dataSet: SET,
      ownDevice: VIEWER,
      keys: deviceKeySource({ ...O, direct: [known(b, 'admin')] }),
    };
    const rv = writeRaw(emptyReplica(v.id), 'notes', 'n1', { text: 'x' });
    const real = await signed(rv, v);
    const forged = insertSignatures(
      rv,
      await signOwnChanges(APP, m.keys.signing.privateKey, rv, SET),
    );
    const f = await readChanges(viewer, forged.log, judge);
    expect(f.accepted).toEqual([]);
    const g = await readChanges(viewer, real.log, judge);
    expect(g.accepted).toEqual([]);
    expect(g.rejected).toBe(0);
  });

  it('a device met in person keeps the keys learned in person; a conflicting vouch is reported', async () => {
    const rb = await enter(b, emptyOf(b), v, 'member');
    let rm = merge(emptyOf(m), rb.log).replica;
    rm = await signed(writeRaw(rm, DEVICE_COLLECTION, v.id, { sig: m.intro.sig }), m);
    const view = holding(VIEWER, rb, rm);
    const direct = [known(b, 'admin'), known(m, 'admin'), known(v)];
    const t = await computeTrust(view, direct, O);
    expect(t.trusted.find((d) => d.name === 'V')?.sig).toBe(v.intro.sig);
    const s = await deviceStatus(view, v.id, { ...O, direct });
    expect(s.trusted).toBe(true);
    expect(s.reasons).toContain('key-mismatch');
  });

  it('conflicting relay ids of two vouchers drop the relay id; the device stays trusted', async () => {
    const rb = await enter(b, emptyOf(b), v, 'member', O, { relayId: 'relay-b' });
    let rm = merge(emptyOf(m), rb.log).replica;
    rm = await signed(writeRaw(rm, DEVICE_COLLECTION, v.id, { relayId: 'relay-m' }), m);
    const direct = [known(b, 'admin'), known(m, 'admin')];
    const view = holding(VIEWER, rb, rm);
    const t = await computeTrust(view, direct, O);
    const entry = t.trusted.find((d) => d.name === 'V');
    expect(entry).toBeDefined();
    expect(entry?.relayId).toBeUndefined();
    expect((await deviceStatus(view, v.id, { ...O, direct })).reasons).toContain('relay-conflict');
    // one voucher alone: the relay id counts
    const alone = await computeTrust(holding(VIEWER, rb), direct, O);
    expect(alone.trusted.find((d) => d.name === 'V')?.relayId).toBe('relay-b');
  });
});

describe('T3: local writing decides against the derived state', () => {
  let a: Dev, x: Dev, y: Dev;
  beforeAll(async () => {
    [a, x, y] = [await dev('A'), await dev('X'), await dev('Y')];
  });

  it('removeDevice writes although the device wrote "removed" into its own entry (that counts for nothing)', async () => {
    const ra = await enter(a, emptyOf(a), x, 'member');
    let rx = merge(emptyOf(x), ra.log).replica;
    rx = await signed(writeRaw(rx, DEVICE_COLLECTION, x.id, { removed: true }), x);
    const mine = merge(ra, rx.log).replica;
    expect(listDevices(mine, O).find((e) => e.device === x.id)?.removed).toBe(true); // raw display
    const before = await computeTrust(mine, [], O);
    expect(names(before.trusted)).toEqual(['X']);
    const out = ok(removeDevice(mine, O, x.id, {}));
    expect(out.log.length).toBeGreaterThan(mine.log.length);
    const after = await computeTrust(out, [], O);
    expect(after.trusted).toEqual([]);
    expect(after.removed).toEqual([x.id]);
    expect(ok(removeDevice(out, O, x.id, {}))).toBe(out); // now it stands: nothing more to write
  });

  it('addDevice writes although a non-voucher pre-wrote the entry verbatim', async () => {
    let ry = emptyOf(y);
    ry = writeRaw(ry, DEVICE_COLLECTION, x.id, {
      name: x.intro.name,
      sig: x.intro.sig,
      dh: x.intro.dh,
      role: 'member',
    });
    ry = await signed(ry, y);
    const mine = merge(emptyOf(a), ry.log).replica;
    expect((await computeTrust(mine, [], O)).trusted).toEqual([]);
    const out = ok(addDevice(mine, O, x.intro, 'member', {}));
    expect(out.log.length).toBeGreaterThan(mine.log.length);
    expect(names((await computeTrust(out, [], O)).trusted)).toEqual(['X']);
    expect(ok(addDevice(out, O, x.intro, 'member', {}))).toBe(out);
  });

  it('addDevice is not blocked by other keys that a non-voucher wrote into the entry', async () => {
    let ry = emptyOf(y);
    ry = writeRaw(ry, DEVICE_COLLECTION, x.id, { sig: y.intro.sig, dh: y.intro.dh });
    ry = await signed(ry, y);
    const mine = merge(emptyOf(a), ry.log).replica;
    const out = ok(addDevice(mine, O, x.intro, 'member', {}));
    expect(names((await computeTrust(out, [], O)).trusted)).toEqual(['X']);
  });

  it('a removed device stays removed: entering it again is refused, an entry rewritten after the removal does not undo it', async () => {
    const ra = await drop(a, await enter(a, emptyOf(a), x, 'member'), x);
    expect(addDevice(ra, O, x.intro, 'member', {})).toEqual({ ok: false, reason: 'removed' });
    // neither the removed device nor another voucher can take the removal back
    const b = await dev('B');
    const rb = await enter(a, ra, b, 'admin');
    let rx = merge(emptyOf(x), rb.log).replica;
    rx = await signed(writeRaw(rx, DEVICE_COLLECTION, x.id, { removed: false }), x);
    let rb2 = merge(emptyOf(b), rb.log).replica;
    rb2 = await signed(writeRaw(rb2, DEVICE_COLLECTION, x.id, { removed: false }), b);
    const view = holding(VIEWER, rb, rx, rb2);
    expect((await computeTrust(view, [known(a, 'admin')], O)).trusted.map((d) => d.name)).toEqual([
      'A',
      'B',
    ]);
    const s = await deviceStatus(ra, x.id, { ...O, direct: [] });
    expect(s).toMatchObject({ trusted: false, checkable: true, removed: true });
  });

  it('deviceStatus reports the derived state of an id', async () => {
    const ra = await enter(a, emptyOf(a), x, 'member');
    expect(await deviceStatus(ra, x.id, { ...O, direct: [] })).toMatchObject({
      trusted: true,
      checkable: true,
      removed: false,
    });
    const unknown = await deviceStatus(ra, y.id, { ...O, direct: [] });
    expect(unknown).toMatchObject({ trusted: false, checkable: false, removed: false });
  });
});

describe('T4: the derivation is linear', () => {
  const N = 400;
  let chain: Dev[];
  let log: Change[];
  const VOUCH = opts(vouchRoles(['admin']));

  beforeAll(async () => {
    chain = [];
    for (let i = 0; i < N; i += 1) {
      const id = newDeviceId(
        new Uint8Array(16).fill(0).map((_, k) => (k === 15 ? i & 255 : k === 14 ? i >> 8 : 7)),
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
      const r = await enter(d, emptyOf(d), chain[i + 1] as Dev, 'admin', VOUCH);
      log.push(...r.log);
    }
  }, 60_000);

  it(`computeTrust over a chain of ${N} devices takes well under a second`, async () => {
    const view = merge(emptyOf(VIEWER), log).replica;
    const direct = [known(chain[0] as Dev, 'admin')];
    const cold = performance.now();
    const t = await computeTrust(view, direct, VOUCH);
    const coldMs = performance.now() - cold;
    expect(t.trusted).toHaveLength(N);
    const warmStart = performance.now();
    await computeTrust(view, direct, VOUCH);
    const warmMs = performance.now() - warmStart;
    process.stderr.write(`
computeTrust(${N} chain): cold ${coldMs.toFixed(0)} ms, warm ${warmMs.toFixed(0)} ms
`);
    expect(warmMs).toBeLessThan(600);
    expect(coldMs).toBeLessThan(8000);
  });

  it(`readChanges of the ${N - 1} chain changes by a fresh device takes seconds, not minutes`, async () => {
    const judge: JudgeOptions = {
      appId: APP,
      dataSet: SET,
      ownDevice: VIEWER,
      neverErase: deviceNeverErase(),
      keys: deviceKeySource({ ...VOUCH, direct: [known(chain[0] as Dev, 'admin')] }),
    };
    const start = performance.now();
    const res = await readChanges(emptyReplica(VIEWER), [...log].reverse(), judge);
    const ms = performance.now() - start;
    process.stderr.write(`
readChanges(${log.length} chain changes): ${ms.toFixed(0)} ms
`);
    expect(res.rejected).toBe(0);
    expect(res.accepted).toHaveLength(log.length);
    // about 1.6 s alone, about 6 s while the whole suite runs on all cores; the old code needed 30 s and more
    expect(ms).toBeLessThan(12_000);
  }, 60_000);
});

describe('T4: scale without signature work', () => {
  it('a chain of 6000 entries derives in linear time (no rescan per entry)', () => {
    const N = 6000;
    const id = (i: number) =>
      newDeviceId(new Uint8Array(16).map((_, k) => (k === 15 ? i & 255 : k === 14 ? i >> 8 : 9)));
    const point = (i: number, tag: number) =>
      base64url(
        new Uint8Array(65).map((_, k) =>
          k === 0 ? 4 : k === 1 ? tag : k === 2 ? i & 255 : k === 3 ? i >> 8 : 5,
        ),
      );
    const changes: Change[] = [];
    for (let i = 0; i < N - 1; i += 1) {
      const w = write(
        emptyReplica(id(i)),
        DEVICE_COLLECTION,
        id(i + 1),
        { name: `D${i + 1}`, sig: point(i + 1, 1), dh: point(i + 1, 2), role: 'admin' },
        {},
      );
      if (!w.ok) throw new Error(w.reason);
      changes.push(...w.replica.log);
    }
    const view = merge(emptyReplica(VIEWER), changes).replica;
    const first = { device: id(0), name: 'D0', sig: point(0, 1), dh: point(0, 2), role: 'admin' };
    const direct = [{ ...first, since: '2026-11-10', checkCode: '1111 2222 3333 4444 5555' }];
    const start = performance.now();
    const t = deriveSync(view, direct, VOUCH_ADMIN).trust;
    const ms = performance.now() - start;
    process.stderr.write(`
deriveSync(${N} chain, no signatures): ${ms.toFixed(0)} ms
`);
    expect(t.trusted).toHaveLength(N);
    expect(ms).toBeLessThan(6000);
  });
});

describe('hardening: checkCode groups', () => {
  it('five groups stay the default; 5 to 10 groups are allowed; others are a TypeError', async () => {
    const d = await dev('Z');
    const keys = await publicKeys(d.keys);
    const five = await checkCode(APP, d.id, keys);
    expect(five.split(' ')).toHaveLength(5);
    expect(await checkCode(APP, d.id, keys, 5)).toBe(five);
    for (let g = 5; g <= 10; g += 1) {
      const code = await checkCode(APP, d.id, keys, g);
      expect(code.split(' ')).toHaveLength(g);
      expect(code.startsWith(five)).toBe(true);
    }
    for (const bad of [4, 11, 5.5, NaN, '8', -1, 0]) {
      await expect(checkCode(APP, d.id, keys, bad as never)).rejects.toThrow(TypeError);
    }
  });
});
