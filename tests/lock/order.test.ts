import { describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  MAX_ORDER_CHARS,
  applyLockOrder,
  lockStatus,
  readLockOrder,
  signLockOrder,
  type ApplyOrderParams,
  type LockOp,
} from '../../src/lock/index.ts';
import { APP, OP, OTHER, PEER, SELF, operatorKeys, prng, start } from './helpers.ts';

async function params(over: Partial<ApplyOrderParams> = {}): Promise<ApplyOrderParams> {
  const k = await operatorKeys();
  return {
    appId: APP,
    self: SELF,
    keys: (d) => (d === OP ? k.signing.publicKey : undefined),
    mayOperate: (d) => d === OP,
    ...over,
  };
}
async function order(op: LockOp, n: number, to = SELF, from = OP, appId = APP): Promise<string> {
  const k = await operatorKeys();
  const r = await signLockOrder({ appId, from, to, op, n, privateKey: k.signing.privateKey });
  if (!r.ok) throw new Error(r.reason);
  return r.text;
}

describe('lock orders', () => {
  it('lock, then unlock, with growing counters', async () => {
    const p = await params();
    const s0 = start(PEER);
    const a = await applyLockOrder(s0, await order('lock', 5), p);
    if (!a.ok) throw new Error(a.reason);
    expect(lockStatus(a.state, 0)).toMatchObject({ status: 'locked', reason: 'operator' });
    expect(a.state).toMatchObject({ held: true, by: OP, opN: 5 });
    const b = await applyLockOrder(a.state, await order('unlock', 6), p);
    if (!b.ok) throw new Error(b.reason);
    expect(lockStatus(b.state, 0).status).toBe('ok');
    expect(b.state).toMatchObject({ held: false, by: null, opN: 6 });
  });
  it('refuses a replay, an older order and a repeated counter', async () => {
    const p = await params();
    const lock5 = await order('lock', 5);
    const a = await applyLockOrder(start(PEER), lock5, p);
    if (!a.ok) throw new Error();
    const b = await applyLockOrder(a.state, await order('unlock', 6), p);
    if (!b.ok) throw new Error();
    expect(await applyLockOrder(b.state, lock5, p)).toEqual({ ok: false, reason: 'replayed' });
    expect(await applyLockOrder(b.state, await order('lock', 6), p)).toEqual({
      ok: false,
      reason: 'replayed',
    });
    expect(await applyLockOrder(b.state, await order('lock', 2), p)).toEqual({
      ok: false,
      reason: 'replayed',
    });
  });
  it('refuses an order for another device, another app, a device not allowed, an unknown key', async () => {
    const p = await params();
    const s = start(PEER);
    expect(await applyLockOrder(s, await order('lock', 1, OTHER), p)).toEqual({
      ok: false,
      reason: 'wrong-device',
    });
    expect(await applyLockOrder(s, await order('lock', 1, SELF, OP, 'otherapp'), p)).toEqual({
      ok: false,
      reason: 'not-an-order',
    });
    expect(
      await applyLockOrder(s, await order('lock', 1), { ...p, mayOperate: () => false }),
    ).toEqual({
      ok: false,
      reason: 'not-allowed',
    });
    expect(
      await applyLockOrder(s, await order('lock', 1), { ...p, keys: () => undefined }),
    ).toEqual({
      ok: false,
      reason: 'unknown-key',
    });
    const throwing = await applyLockOrder(s, await order('lock', 1), {
      ...p,
      keys: () => {
        throw new Error('x');
      },
    });
    expect(throwing).toEqual({ ok: false, reason: 'unknown-key' });
    // the device itself cannot order itself
    expect(
      await applyLockOrder(s, await order('lock', 1, SELF, SELF), { ...p, mayOperate: () => true }),
    ).toEqual({
      ok: false,
      reason: 'not-allowed',
    });
  });
  it('refuses a signature by another key', async () => {
    const other = await generateDeviceKeys();
    const p = await params({ keys: () => other.signing.publicKey });
    expect(await applyLockOrder(start(PEER), await order('lock', 1), p)).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });
  it('tamper sweep: every changed character is refused', async () => {
    const p = await params();
    const text = await order('lock', 77);
    expect(text.length).toBeLessThan(MAX_ORDER_CHARS);
    const s = start(PEER);
    for (let i = 0; i < text.length; i += 1) {
      for (const c of ['0', 'x']) {
        if (text[i] === c) continue;
        const t = text.slice(0, i) + c + text.slice(i + 1);
        const r = await applyLockOrder(s, t, p);
        expect(r.ok, `${i} ${c}`).toBe(false);
      }
    }
    // op and counter swapped by hand
    const swapped = text.replace('"op":"lock"', '"op":"unlock"');
    expect((await applyLockOrder(s, swapped, p)).ok).toBe(false);
    const bumped = text.replace('"n":77', '"n":78');
    expect(await applyLockOrder(s, bumped, p)).toEqual({ ok: false, reason: 'bad-signature' });
  });
  it('signing refuses bad input', async () => {
    const k = await operatorKeys();
    for (const bad of [
      { to: 'a|b' },
      { from: '' },
      { n: 0 },
      { n: 1.5 },
      { op: 'x' as LockOp },
      { appId: 'Bad' },
    ]) {
      const r = await signLockOrder({
        appId: APP,
        from: OP,
        to: SELF,
        op: 'lock',
        n: 1,
        privateKey: k.signing.privateKey,
        ...bad,
      });
      expect(r).toEqual({ ok: false, reason: 'bad-input' });
    }
  });
});

describe('strict order reader', () => {
  it('reads exactly what is written', async () => {
    const t = await order('unlock', 9);
    expect(readLockOrder(t, APP)).toMatchObject({ to: SELF, from: OP, op: 'unlock', n: 9 });
    expect(readLockOrder(t, 'otherapp')).toBeUndefined();
    expect(readLockOrder(` ${t}`, APP)).toBeUndefined();
    expect(readLockOrder(t.replace('"n":9', '"n":09'), APP)).toBeUndefined();
    expect(readLockOrder(t.replace('"n":9', '"n":9.0'), APP)).toBeUndefined();
    expect(readLockOrder(t.replace('"n":9', '"n":1e1'), APP)).toBeUndefined();
    expect(readLockOrder(t.replace('"sig"', '"sig":"x","sig"'), APP)).toBeUndefined();
    expect(readLockOrder('x'.repeat(MAX_ORDER_CHARS + 1), APP)).toBeUndefined();
    expect(readLockOrder(5, APP)).toBeUndefined();
    expect(readLockOrder(t, 'BAD')).toBeUndefined();
  });
  it('seeded fuzz: 3000 damaged texts never throw and only the original reads', async () => {
    const p = await params();
    const t = await order('lock', 123456);
    const rnd = prng(11);
    const alphabet = '0123456789{}[]",:-_abcdefxyz\\u';
    for (let i = 0; i < 3000; i += 1) {
      let m = t;
      for (let j = 0; j <= Math.floor(rnd() * 3); j += 1) {
        const p = Math.floor(rnd() * m.length);
        const c = alphabet[Math.floor(rnd() * alphabet.length)] as string;
        m = rnd() < 0.3 ? m.slice(0, p) + m.slice(p + 1) : m.slice(0, p) + c + m.slice(p + 1);
      }
      const r = readLockOrder(m, APP);
      if (r !== undefined) {
        // the reader is syntactic (one spelling); what it lets through, the signature refuses
        expect(JSON.stringify(r).length).toBeGreaterThan(0);
        if (m !== t) expect((await applyLockOrder(start(PEER), m, p)).ok).toBe(false);
      } else expect((await applyLockOrder(start(PEER), m, p)).ok).toBe(false);
    }
  });
});
