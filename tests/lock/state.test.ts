import { describe, expect, it } from 'vitest';
import {
  lockCheck,
  lockMarkWiped,
  lockObserve,
  lockRemoved,
  lockRemovedBy,
  lockSetDays,
  lockStart,
  lockStatus,
  readLockState,
  recordLockContact,
  storeLockState,
  type LockState,
} from '../../src/lock/index.ts';
import { DAY_MS, PEER, SERVER, prng, start } from './helpers.ts';

const contact = (s: LockState, source: string, at: number, local = at, info = {}): LockState => {
  const r = recordLockContact(s, source, at, local, info);
  if (!r.ok) throw new Error(r.reason);
  return r.state;
};

describe('status boundaries', () => {
  const s = start(PEER);
  const at = (days: number, extraMs = 0) => lockStatus(s, days * DAY_MS + extraMs);
  it('ok until day 7, warn from day 7, locked only after day 10', () => {
    expect(at(0)).toMatchObject({ status: 'ok', daysLeft: 10 });
    expect(at(6)).toMatchObject({ status: 'ok', daysLeft: 4 });
    expect(at(7, -1)).toMatchObject({ status: 'ok', daysLeft: 4 });
    expect(at(7)).toMatchObject({ status: 'warn', daysLeft: 3 });
    expect(at(9)).toMatchObject({ status: 'warn', daysLeft: 1 });
    expect(at(10)).toMatchObject({ status: 'warn', daysLeft: 0, msLeft: 0 });
    expect(at(10, 1)).toMatchObject({ status: 'locked', daysLeft: 0, reason: 'expired' });
    expect(at(0).deadline).toBe(10 * DAY_MS);
  });
  it('a private deadline of 3 days: locked at 3 days + 1 ms, not at 3 days', () => {
    const r = lockSetDays(s, 3, 2);
    if (!r.ok) throw new Error();
    expect(lockStatus(r.state, 3 * DAY_MS).status).toBe('warn');
    expect(lockStatus(r.state, 3 * DAY_MS + 1).status).toBe('locked');
    expect(lockSetDays(s, 3, 4)).toEqual({ ok: false, reason: 'bad-config' });
    expect(lockSetDays(s, 0, 0)).toEqual({ ok: false, reason: 'bad-config' });
  });
  it('refuses bad configuration', () => {
    for (const bad of [
      { ...PEER, maxDays: 0 },
      { ...PEER, maxDays: 3651 },
      { ...PEER, warnDays: 11 },
      { ...PEER, source: 'Peer' },
      { ...PEER, kind: 'x' as 'device' },
      { ...PEER, slackMs: -1 },
      { ...PEER, skewMs: 1.5 },
    ]) {
      expect(lockStart(bad, 0).ok).toBe(false);
    }
    expect(lockStart(PEER, -1)).toEqual({ ok: false, reason: 'bad-input' });
    expect(lockStart(PEER, 5, 6)).toEqual({ ok: false, reason: 'bad-input' });
  });
});

describe('clock guard', () => {
  it('a clock set back never extends the deadline', () => {
    let s = start(PEER);
    s = lockObserve(s, 9 * DAY_MS);
    expect(lockStatus(s, 1 * DAY_MS).status).toBe('locked'); // the clock lock
    expect(lockStatus(s, 1 * DAY_MS).reason).toBe('clock');
    // within the slack: only the guard holds, elapsed time does not shrink
    const t = lockObserve(start(PEER), 9 * DAY_MS);
    expect(lockStatus(t, 9 * DAY_MS - 60_000).elapsedMs).toBe(9 * DAY_MS);
    expect(lockStatus(t, 9 * DAY_MS - 60_000).status).toBe('warn');
  });
  it('expiry stays once seen, also when the clock is turned back', () => {
    let s = start(PEER, 0);
    s = lockObserve(s, 11 * DAY_MS);
    expect(lockStatus(s, 0).status).toBe('locked');
    expect(readLockState(storeLockState(s))?.expired).toBe(true);
  });
  it('a small step back (time zone, correction) does not lock', () => {
    const s = lockObserve(start(PEER), 2 * DAY_MS);
    expect(
      lockStatus(lockObserve(s, 2 * DAY_MS - 9 * 60_000), 2 * DAY_MS - 9 * 60_000).status,
    ).toBe('ok');
    expect(lockObserve(s, 2 * DAY_MS - 11 * 60_000).clock).toBe(true);
  });
  it('a clock jumping forward locks early and a contact renews', () => {
    const s = start(PEER);
    expect(lockStatus(s, 8 * DAY_MS).status).toBe('warn');
    expect(lockStatus(s, 30 * DAY_MS).status).toBe('locked');
  });
  it('lockStatus never stores: observe does', () => {
    const s = start(PEER);
    lockStatus(s, 5 * DAY_MS);
    expect(s.high).toBe(0);
    expect(lockObserve(s, 5 * DAY_MS).high).toBe(5 * DAY_MS);
    expect(lockObserve(s, Number.NaN)).toBe(s);
  });
});

describe('contacts and sources', () => {
  it('a peer contact renews a peer lock', () => {
    const s = contact(start(PEER), 'peer', 6 * DAY_MS);
    expect(lockStatus(s, 6 * DAY_MS).daysLeft).toBe(10);
  });
  it('a server lock is never advanced by a peer, however late the peer says it is', () => {
    let s = start(SERVER, 1000, 0);
    const r = recordLockContact(s, 'peer', 99 * DAY_MS, 5 * DAY_MS);
    if (!r.ok) throw new Error();
    expect(r.counted).toBe(false);
    expect(r.why).toBe('other-source');
    s = r.state;
    expect(s.at).toBe(1000);
    expect(s.local).toBe(0);
    expect(s.others).toEqual([['peer', 99 * DAY_MS]]);
    expect(lockStatus(s, 11 * DAY_MS).status).toBe('locked');
  });
  it('a server contact keeps server time and measures on the device clock', () => {
    const s0 = start(SERVER, 5000, 100);
    const s = contact(s0, 'server', 9000, 3 * DAY_MS);
    expect(s.at).toBe(9000);
    expect(s.local).toBe(3 * DAY_MS);
    expect(lockStatus(s, 3 * DAY_MS + 8 * DAY_MS).status).toBe('warn');
    // an older server answer replayed
    expect(recordLockContact(s, 'server', 8999, 4 * DAY_MS)).toEqual({
      ok: false,
      reason: 'time-went-back',
    });
    // a peer cannot move the other clock either
    expect(recordLockContact(s0, 'peer', 5, 5).ok).toBe(true);
  });
  it('bounds the number of other sources', () => {
    let s = start(PEER);
    for (let i = 0; i < 7; i += 1) s = contact(s, `src${i}`, i);
    expect(recordLockContact(s, 'src7', 1)).toEqual({ ok: false, reason: 'too-many-sources' });
    expect(recordLockContact(s, 'src3', 50).ok).toBe(true);
    expect(recordLockContact(s, 'BAD', 1).ok).toBe(false);
  });
  it('a locked device stays locked when the lock does not revive, and says so at the contact', () => {
    const s0 = lockObserve(start(SERVER), 11 * DAY_MS);
    const r = recordLockContact(s0, 'server', 12 * DAY_MS, 12 * DAY_MS);
    if (!r.ok) throw new Error();
    expect(r).toMatchObject({ counted: false, why: 'locked' });
    expect(lockStatus(r.state, 12 * DAY_MS).status).toBe('locked');
  });
});

describe('parity with the earlier implementation', () => {
  const REVIVE = { ...PEER, revive: true, distinct: true, skewMs: DAY_MS };
  it('only another peer than the last renews; an older file does not; clocks must agree', () => {
    let s = start(REVIVE);
    const x = (at: number, peer: string, created: number) =>
      recordLockContact(s, 'peer', at, at, { peer, created });
    let r = x(1 * DAY_MS, 'a', 1 * DAY_MS);
    if (!r.ok) throw new Error();
    s = r.state;
    expect(r.counted).toBe(true);
    expect(x(2 * DAY_MS, 'a', 2 * DAY_MS)).toMatchObject({ counted: false, why: 'same-peer' });
    expect(x(2 * DAY_MS, 'b', 1 * DAY_MS)).toMatchObject({ counted: false, why: 'old' });
    expect(x(2 * DAY_MS, 'b', 5 * DAY_MS)).toMatchObject({ counted: false, why: 'clock-differs' });
    r = x(2 * DAY_MS, 'b', 2 * DAY_MS);
    expect(r).toMatchObject({ ok: true, counted: true });
    expect(recordLockContact(s, 'peer', 5, 5, {}).ok).toBe(false); // distinct needs a peer
  });
  it('a lock (expiry or clock) opens by a fitting contact when it revives', () => {
    let s = lockObserve(start(REVIVE), 11 * DAY_MS);
    expect(lockStatus(s, 11 * DAY_MS).status).toBe('locked');
    const r = recordLockContact(s, 'peer', 12 * DAY_MS, 12 * DAY_MS, {
      peer: 'a',
      created: 12 * DAY_MS,
    });
    if (!r.ok) throw new Error();
    s = r.state;
    expect(lockStatus(s, 12 * DAY_MS).status).toBe('ok');
    s = lockObserve(s, 5 * DAY_MS);
    expect(lockStatus(s, 5 * DAY_MS).reason).toBe('clock');
  });
  it('removed is final: no contact lifts it, an order cannot either', () => {
    const s = lockRemoved(start(REVIVE));
    expect(lockStatus(s, 0)).toMatchObject({ status: 'locked', reason: 'removed' });
    const r = recordLockContact(s, 'peer', 1, 1, { peer: 'a' });
    expect(r).toMatchObject({ ok: true, counted: false, why: 'removed' });
    expect(lockRemoved(s)).toBe(s);
  });
});

describe('the verdict of a removal notice', () => {
  const REVIVE = { ...PEER, revive: true, distinct: true, skewMs: DAY_MS };
  it('only a proven removal locks; every other verdict, or none, leaves the state as it is', () => {
    const s = start(REVIVE);
    expect(lockStatus(lockRemovedBy(s, { selfRemoved: true }), 0)).toMatchObject({
      status: 'locked',
      reason: 'removed',
    });
    for (const verdict of [
      undefined,
      { selfRemoved: false },
      {},
      { selfRemoved: 'true' as unknown as boolean },
    ]) {
      expect(lockRemovedBy(s, verdict)).toBe(s);
    }
    const locked = lockRemovedBy(s, { selfRemoved: true });
    expect(lockRemovedBy(locked, { selfRemoved: true })).toBe(locked);
    // contacts do not lift it, as with lockRemoved
    expect(recordLockContact(locked, 'peer', 1, 1, { peer: 'a' })).toMatchObject({
      counted: false,
      why: 'removed',
    });
  });
});

describe('wipe hook', () => {
  const onLocked = (i: { reason: string }) => ({ erase: ['everything'], why: i.reason });
  it('hands the instruction out while locked and not marked wiped', () => {
    const s = start(PEER);
    expect(lockCheck(s, 1, { onLocked }).wipe).toBeUndefined();
    const c = lockCheck(s, 11 * DAY_MS, { onLocked });
    expect(c.wipe).toEqual({ erase: ['everything'], why: 'expired' });
    expect(lockCheck(c.state, 11 * DAY_MS, { onLocked }).wipe).toBeDefined(); // until marked
    expect(lockCheck(lockMarkWiped(c.state), 11 * DAY_MS, { onLocked }).wipe).toBeUndefined();
    expect(lockCheck(c.state, 11 * DAY_MS).wipe).toBeUndefined();
  });
  it('wipeOn contact waits for the contact', () => {
    const s = start(SERVER);
    expect(lockCheck(s, 11 * DAY_MS, { onLocked }).wipe).toBeUndefined();
    expect(lockCheck(s, 11 * DAY_MS, { onLocked }, true).wipe).toBeDefined();
  });
});

describe('state text', () => {
  it('round-trips with one spelling', () => {
    let s = start(SERVER, 5, 1);
    s = contact(s, 'peer', 7, 3);
    const t = storeLockState(s);
    expect(readLockState(t)).toEqual(s);
    expect(readLockState(` ${t}`)).toBeUndefined();
    expect(readLockState(t.replace('"v":1', '"v":2'))).toBeUndefined();
    expect(readLockState(t.replace('{"v":1,', '{"v":1,"x":1,'))).toBeUndefined();
    expect(readLockState(t.replace('"high":3', '"high":0'))).toBeUndefined();
    expect(readLockState(t.slice(0, -1))).toBeUndefined();
  });
  it('refuses inconsistent values', () => {
    const base = JSON.parse(storeLockState(start(PEER))) as Record<string, unknown>;
    const bad: Record<string, unknown>[] = [
      { held: true },
      { by: 'device-x' },
      { source: 'a b' },
      { maxDays: 11.5 },
      { warnDays: 11 },
      { opN: -1 },
      { opN: 1.5 },
      { at: 1 },
      { others: [['peer', 1]] },
      {
        others: [
          ['b', 1],
          ['a', 1],
        ],
      },
      { peer: 5 },
      { slackMs: 99_999_999_999 },
    ];
    for (const patch of bad) {
      expect(readLockState(JSON.stringify({ ...base, ...patch }))).toBeUndefined();
    }
  });
  it('seeded fuzz: 3000 damaged texts never throw and never read as another state', () => {
    const rnd = prng(7);
    let s = start(SERVER, 5, 1);
    s = contact(s, 'peer', 7, 3);
    const t = storeLockState(s);
    const junk = ['', '{', '[]', 'null', '1', '"x"', '{"v":1}', '{"__proto__":{}}'];
    for (let i = 0; i < 3000; i += 1) {
      let m = t;
      const k = Math.floor(rnd() * 4);
      for (let j = 0; j <= k; j += 1) {
        const p = Math.floor(rnd() * m.length);
        const c = '0123456789{}[]",:-aznull'[Math.floor(rnd() * 24)] as string;
        m = rnd() < 0.3 ? m.slice(0, p) + m.slice(p + 1) : m.slice(0, p) + c + m.slice(p + 1);
      }
      if (i % 10 === 0) m = junk[i % junk.length] as string;
      const r = readLockState(m);
      if (r !== undefined) expect(storeLockState(r)).toBe(m);
    }
    expect(readLockState(123 as unknown as string)).toBeUndefined();
  });
});

describe('seeded schedules', () => {
  it('300 random runs: no lock opens without a counted contact, time left never grows alone', () => {
    for (let run = 0; run < 300; run += 1) {
      const rnd = prng(run + 1);
      const config = run % 2 === 0 ? { ...PEER, revive: run % 4 === 0 } : SERVER;
      let s = start(config, 1000, 1000);
      let now = 1000;
      let serverNow = 1000;
      for (let step = 0; step < 60; step += 1) {
        const before = lockStatus(s, now);
        const roll = rnd();
        let counted = false;
        if (roll < 0.5) now += Math.floor(rnd() * 3 * DAY_MS);
        else if (roll < 0.65) now = Math.max(0, now - Math.floor(rnd() * 5 * DAY_MS));
        else if (roll < 0.8) {
          serverNow = Math.max(serverNow, now);
          const r = recordLockContact(
            s,
            config.kind === 'remote' ? 'server' : 'peer',
            config.kind === 'remote' ? serverNow : now,
            now,
          );
          if (r.ok) {
            s = r.state;
            counted = r.counted;
          }
        } else if (roll < 0.9) {
          const r = recordLockContact(s, config.kind === 'remote' ? 'peer' : 'server', now, now);
          if (r.ok) {
            expect(r.counted).toBe(false);
            s = r.state;
          }
        } else s = lockObserve(s, now);
        const text = storeLockState(s);
        expect(readLockState(text)).toEqual(s);
        const after = lockStatus(s, now);
        if (!counted) {
          // nothing unlocks or extends the deadline by itself
          expect(after.msLeft).toBeLessThanOrEqual(before.msLeft);
          if (before.status === 'locked') expect(after.status).toBe('locked');
        }
        s = lockObserve(s, now);
        expect(s.high).toBeGreaterThanOrEqual(s.local);
      }
    }
  });
});
