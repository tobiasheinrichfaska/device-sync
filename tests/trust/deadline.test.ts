import { describe, expect, it } from 'vitest';
import {
  MAX_DEADLINE_MS,
  checkDeadline,
  contactDeadline,
  deadlinePolicy,
  deadlineStart,
  isDeadlineMs,
  parseDeadline,
  setDeadlineMs,
} from '../../src/trust/index.ts';

const DAY = 24 * 60 * 60 * 1000;
const T0 = 1_800_000_000_000;
const contact = (
  from: string,
  now: number,
  over: Partial<Parameters<typeof contactDeadline>[1]> = {},
) => ({
  from,
  trusted: true,
  removed: false,
  created: now,
  now,
  ...over,
});

describe('deadlinePolicy', () => {
  const policy = deadlinePolicy({
    standardMs: 10 * DAY,
    privateMs: 3 * DAY,
    noLimitRoles: ['office'],
    roleMs: { lead: 30 * DAY },
  });
  it('gives each device its limit from role and private flag', () => {
    expect(policy({ role: 'member' })).toBe(10 * DAY);
    expect(policy({})).toBe(10 * DAY);
    expect(policy({ role: 'lead' })).toBe(30 * DAY);
    expect(policy({ role: 'office' })).toBeNull();
    expect(policy({ role: 'member', private: true })).toBe(3 * DAY);
  });
  it('never gives a private device the exemption of its role', () => {
    expect(policy({ role: 'office', private: true })).toBe(3 * DAY);
    expect(policy({ role: 'lead', private: true })).toBe(3 * DAY);
  });
  it('a private device without its own limit gets the standard', () => {
    expect(
      deadlinePolicy({ standardMs: 5 * DAY, noLimitRoles: ['office'] })({
        role: 'office',
        private: true,
      }),
    ).toBe(5 * DAY);
  });
  it('refuses limits out of bounds', () => {
    expect(() => deadlinePolicy({ standardMs: 1 })).toThrow(RangeError);
    expect(() => deadlinePolicy({ standardMs: MAX_DEADLINE_MS + 1 })).toThrow(RangeError);
    expect(() => deadlinePolicy({ standardMs: DAY, roleMs: { x: 0 } })).toThrow(RangeError);
    expect(isDeadlineMs(null)).toBe(true);
    expect(isDeadlineMs(1.5)).toBe(false);
  });
});

describe('checkDeadline', () => {
  it('works inside the limit and says when it ends', () => {
    const v = checkDeadline(deadlineStart('A', T0, 10 * DAY), T0 + 9 * DAY);
    expect(v.locked).toBe(false);
    expect(v.until).toBe(T0 + 10 * DAY);
  });
  it('locks after the limit and stays locked when the clock is turned back', () => {
    const v = checkDeadline(deadlineStart('A', T0, 10 * DAY), T0 + 10 * DAY + 1);
    expect(v).toMatchObject({ locked: true, reason: 'deadline' });
    expect(checkDeadline(v.state, T0 + DAY)).toMatchObject({ locked: true, reason: 'deadline' });
  });
  it('a device without a limit never locks by time', () => {
    const v = checkDeadline(deadlineStart(null, T0, null), T0 + 5000 * DAY);
    expect(v.locked).toBe(false);
    expect(v.until).toBeUndefined();
  });
  it('a clock before the last use locks, also without a limit', () => {
    const used = checkDeadline(deadlineStart('A', T0, null), T0 + 5 * DAY).state;
    expect(checkDeadline(used, T0 + DAY)).toMatchObject({ locked: true, reason: 'clock' });
    expect(checkDeadline(used, T0 + 5 * DAY - 5 * 60 * 1000).locked).toBe(false); // inside the slack
  });
});

describe('contactDeadline', () => {
  const start = deadlineStart('A', T0, 10 * DAY);
  it('renews the deadline from another trusted device and lifts a lock', () => {
    const locked = checkDeadline(start, T0 + 11 * DAY).state;
    const r = contactDeadline(locked, contact('B', T0 + 11 * DAY));
    expect(r.counts).toBe(true);
    expect(r.state.lock).toBeUndefined();
    expect(checkDeadline(r.state, T0 + 12 * DAY).locked).toBe(false);
  });
  it('does not count the device of the last renewal again', () => {
    expect(contactDeadline(start, contact('A', T0 + DAY))).toMatchObject({
      counts: false,
      reason: 'same-device',
    });
  });
  it('does not count an untrusted sender', () => {
    expect(contactDeadline(start, contact('B', T0 + DAY, { trusted: false }))).toMatchObject({
      counts: false,
      reason: 'not-trusted',
    });
  });
  it('does not count data whose clock is far from this one', () => {
    expect(
      contactDeadline(start, contact('B', T0 + DAY, { created: T0 + DAY - 2 * DAY })),
    ).toMatchObject({ counts: false, reason: 'clock' });
    expect(contactDeadline(start, contact('B', T0 + DAY, { created: Number.NaN }))).toMatchObject({
      counts: false,
      reason: 'clock',
    });
  });
  it('does not count data that are not newer than the last renewal', () => {
    const r1 = contactDeadline(start, contact('B', T0 + DAY)).state;
    expect(contactDeadline(r1, contact('C', T0 + 2 * DAY, { created: T0 + DAY }))).toMatchObject({
      counts: false,
      reason: 'old',
    });
  });
  it('data that show the device removed lock it for good', () => {
    const r = contactDeadline(start, contact('B', T0 + DAY, { removed: true }));
    expect(r).toMatchObject({ counts: false, reason: 'removed' });
    expect(checkDeadline(r.state, T0 + DAY)).toMatchObject({ locked: true, reason: 'removed' });
    expect(contactDeadline(r.state, contact('C', T0 + 2 * DAY))).toMatchObject({
      counts: false,
      reason: 'removed',
    });
  });
  it('a device without a limit is still locked by removal', () => {
    const r = contactDeadline(
      deadlineStart(null, T0, null),
      contact('B', T0 + DAY, { removed: true }),
    );
    expect(checkDeadline(r.state, T0 + DAY).locked).toBe(true);
  });
});

describe('parseDeadline', () => {
  const good = deadlineStart('A', T0, 10 * DAY);
  it('reads what it wrote, with a lock and without a limit', () => {
    expect(parseDeadline(JSON.parse(JSON.stringify(good)))).toEqual(good);
    const none = checkDeadline(deadlineStart(null, T0, null), T0).state;
    expect(parseDeadline(JSON.parse(JSON.stringify(none)))).toEqual(none);
    const locked = checkDeadline(good, T0 + 11 * DAY).state;
    expect(parseDeadline(JSON.parse(JSON.stringify(locked)))).toEqual(locked);
  });
  it('refuses a damaged state (the caller locks)', () => {
    for (const bad of [
      undefined,
      null,
      'x',
      { ...good, v: 2 },
      { ...good, deadlineMs: undefined },
      { ...good, deadlineMs: 5 },
      { ...good, used: 1.5 },
      { ...good, contact: null },
      { ...good, contact: { device: 3, time: T0 } },
      { ...good, lock: { reason: 'other', since: T0 } },
    ])
      expect(parseDeadline(bad)).toBeUndefined();
  });
  it('a new limit keeps a lock', () => {
    const locked = checkDeadline(good, T0 + 11 * DAY).state;
    expect(setDeadlineMs(locked, null).lock?.reason).toBe('deadline');
    expect(() => setDeadlineMs(good, 1)).toThrow(RangeError);
  });
});
