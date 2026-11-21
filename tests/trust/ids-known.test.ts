import { describe, expect, it } from 'vitest';
import {
  DEVICE_ID,
  forgetDevice,
  newDeviceId,
  noteRelayId,
  parseKnownList,
  rememberDevice,
  renameKnown,
  resolveValidators,
  vouchAll,
  vouchAnyRole,
  vouchRoles,
  type DeviceEntry,
  type KnownDevice,
} from '../../src/trust/index.ts';
import { dev, prng } from './helpers.ts';

describe('newDeviceId', () => {
  it('has the format device-<32 lower-case hex> and matches the default pattern', () => {
    const id = newDeviceId(new Uint8Array(16).fill(0xab));
    expect(id).toBe('device-' + 'ab'.repeat(16));
    expect(DEVICE_ID.test(id)).toBe(true);
    expect(newDeviceId(Uint8Array.from({ length: 16 }, (_, i) => i))).toBe(
      'device-000102030405060708090a0b0c0d0e0f',
    );
  });

  it('different random input gives different ids; same input the same id', () => {
    const rnd = prng(7);
    const ids = new Set<string>();
    for (let i = 0; i < 2000; i++)
      ids.add(newDeviceId(Uint8Array.from({ length: 16 }, () => Math.floor(rnd() * 256))));
    expect(ids.size).toBe(2000);
    expect(newDeviceId(new Uint8Array(16))).toBe(newDeviceId(new Uint8Array(16)));
  });

  it('refuses the wrong amount of randomness', () => {
    for (const bad of [new Uint8Array(15), new Uint8Array(17), new Uint8Array(0), [1] as never]) {
      expect(() => newDeviceId(bad)).toThrow(TypeError);
    }
  });

  it('the default pattern is exact; the check stays a parameter', () => {
    for (const bad of [
      'device-' + 'A'.repeat(32),
      'device-' + 'a'.repeat(31),
      'device-' + 'a'.repeat(33),
      'dev-' + 'a'.repeat(32),
      ' device-' + 'a'.repeat(32),
    ]) {
      expect(DEVICE_ID.test(bad)).toBe(false);
    }
    const mine = resolveValidators({ deviceId: (s) => /^d\d$/.test(s) });
    expect(mine.deviceId('d1')).toBe(true);
    expect(mine.deviceId('device-' + 'a'.repeat(32))).toBe(false);
  });

  it('default relay id: 1 to 80 characters without control characters', () => {
    const v = resolveValidators();
    expect(v.relayId('r')).toBe(true);
    expect(v.relayId('x'.repeat(80))).toBe(true);
    expect(v.relayId('x'.repeat(81))).toBe(false);
    expect(v.relayId('')).toBe(false);
    expect(v.relayId('a\nb')).toBe(false);
    expect(v.relayId('with|bar')).toBe(true);
  });

  it('default role: lower-case start, up to 80 characters', () => {
    const v = resolveValidators();
    for (const ok of ['admin', 'a', 'team:x_y-1']) expect(v.role(ok)).toBe(true);
    for (const bad of ['', 'Admin', '1a', 'a b', 'a'.repeat(81), 'a|b'])
      expect(v.role(bad)).toBe(false);
  });
});

describe('who may vouch (strategies)', () => {
  const entry = (role?: string): DeviceEntry =>
    ({
      device: 'device-' + 'a'.repeat(32),
      name: 'n',
      sig: 's',
      dh: 'd',
      ...(role ? { role } : {}),
      removed: false,
      private: false,
    }) as DeviceEntry;

  it('vouchAll: everybody vouches and invites', () => {
    const v = vouchAll();
    expect(v.canVouch(entry(), [])).toBe(true);
    expect(v.mayInvite?.(entry(), 'x')).toBe(true);
  });

  it('vouchRoles: only the listed roles', () => {
    const v = vouchRoles(['admin', 'lead']);
    expect(v.canVouch(entry('admin'), [])).toBe(true);
    expect(v.canVouch(entry('lead'), [])).toBe(true);
    expect(v.canVouch(entry('member'), [])).toBe(false);
    expect(v.canVouch(entry(), [])).toBe(false);
    expect(v.mayInvite?.(entry('lead'), 'anything')).toBe(true);
    expect(v.mayInvite?.(entry('member'), 'member')).toBe(false);
    expect(vouchRoles([]).canVouch(entry('admin'), [])).toBe(false);
  });

  it('vouchAnyRole: a device with a role', () => {
    const v = vouchAnyRole();
    expect(v.canVouch(entry('x'), [])).toBe(true);
    expect(v.canVouch(entry(), [])).toBe(false);
    expect(v.mayInvite?.(entry(), 'x')).toBe(false);
  });
});

describe('the list of devices met in person', () => {
  const A = 'device-' + 'a'.repeat(32);
  it('a met device joins; again changes nothing; other keys for a known id are refused', async () => {
    const [b, other] = [await dev('B'), await dev('B again')];
    const one = rememberDevice([], A, b.intro, 'member', '2026-11-09', '1111 2222 3333 4444 5555');
    expect(one).toMatchObject({ ok: true, added: true });
    if (!one.ok) return;
    expect(one.list).toEqual([
      { ...b.intro, role: 'member', since: '2026-11-09', checkCode: '1111 2222 3333 4444 5555' },
    ]);
    const again = rememberDevice(
      one.list,
      A,
      b.intro,
      'member',
      '2026-11-10',
      '9999 9999 9999 9999 9999',
    );
    expect(again).toEqual({ ok: true, added: false, list: one.list });
    expect(
      rememberDevice(one.list, A, { ...other.intro, device: b.id }, 'member', 'x', 'y'),
    ).toEqual({ ok: false, reason: 'other-keys' });
    // a new role is noted; none given keeps the old
    const re = rememberDevice(one.list, A, b.intro, 'guest', '2026-11-10', 'x');
    expect(re.ok && re.list[0]?.role).toBe('guest');
    expect(rememberDevice(one.list, A, b.intro, undefined, 'x', 'y')).toMatchObject({
      ok: true,
      added: false,
    });
    expect(forgetDevice(one.list, b.id)).toEqual([]);
  });

  it('the own code and a bad role are refused; the list is sorted by name; a damaged stored entry is dropped', async () => {
    const [own, z, an] = [await dev('Me'), await dev('Zora'), await dev('Anton')];
    expect(rememberDevice([], own.id, own.intro, 'member', 'x', 'y')).toEqual({
      ok: false,
      reason: 'own-device',
    });
    expect(rememberDevice([], A, z.intro, 'Bad Role', 'x', 'y')).toEqual({
      ok: false,
      reason: 'bad-role',
    });
    let list: readonly KnownDevice[] = [];
    for (const d of [z, an]) {
      const r = rememberDevice(
        list,
        A,
        d.intro,
        'member',
        '2026-11-09',
        '1234 5678 9012 3456 7890',
      );
      if (r.ok) list = r.list;
    }
    expect(list.map((b) => b.name)).toEqual(['Anton', 'Zora']);
    const stored = JSON.parse(JSON.stringify(list)) as unknown[];
    expect(parseKnownList(stored)).toEqual(list);
    expect(
      parseKnownList([...stored, { ...z.intro, since: 'yesterday', checkCode: '1' }, 'x', null]),
    ).toEqual(list);
    expect(
      parseKnownList([
        { ...(stored[0] as object), role: 'Bad Role' },
        { ...(stored[0] as object), sig: 'x' },
      ]),
    ).toEqual([]);
    expect(parseKnownList('broken')).toEqual([]);
    // a broken relay id is left out alone
    expect(parseKnownList([{ ...(stored[0] as object), relayId: 'a\u0007' }])).toEqual([stored[0]]);
  });

  it('rename keeps the list sorted; a relay id is noted only when valid', async () => {
    const [x, y] = [await dev('Xavier'), await dev('Yara')];
    let list: readonly KnownDevice[] = [];
    for (const d of [x, y]) {
      const r = rememberDevice(
        list,
        A,
        d.intro,
        undefined,
        '2026-11-09',
        '1234 5678 9012 3456 7890',
      );
      if (r.ok) list = r.list;
    }
    expect(renameKnown(list, x.id, 'Zed').map((b) => b.name)).toEqual(['Yara', 'Zed']);
    expect(noteRelayId(list, x.id, 'r1')[0]?.relayId).toBe('r1');
    expect(noteRelayId(list, x.id, '')).toBe(list);
    expect(noteRelayId(list, 'device-' + '0'.repeat(32), 'r1')).toBe(list);
  });
});
