// Cases of both earlier implementations (their union), with generic roles: "admin" vouches (the
// strategy `vouchRoles(['admin'])`), "member" and "guest" do not. The second family of cases uses
// `vouchAnyRole` plus a `roleCounts` hook (a role counts while a person record exists).
import { describe, expect, it } from 'vitest';
import { checkCode } from '../../src/core/index.ts';
import { merge, softDelete, write, type Replica } from '../../src/log/index.ts';
import {
  DEVICE_COLLECTION,
  addDevice,
  computeTrust,
  deviceNeverErase,
  listDevices,
  removeDevice,
  renameDevice,
  setDevicePrivate,
  vouchAll,
  vouchAnyRole,
  vouchRoles,
} from '../../src/trust/index.ts';
import {
  APP,
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
} from './helpers.ts';

const O = opts();
const trusted = async (r: Replica, direct: ReturnType<typeof known>[], o = O) =>
  (await computeTrust(r, direct, o)).trusted;
const tagged = (list: readonly { name: string; role?: string }[]) =>
  list.map((b) => `${b.name}:${b.role ?? '-'}`);

describe('the device list in the log', () => {
  it('lives in one reserved collection that is never erased', () => {
    expect(DEVICE_COLLECTION).toBe('device');
    expect(deviceNeverErase()).toEqual(['device']);
    expect(deviceNeverErase('d2')).toEqual(['d2']);
  });

  it('the check code differs per device id (keys only are not enough)', async () => {
    const a = await dev('a');
    const b = await dev('b');
    expect(await checkCode(APP, a.id, a.intro)).not.toBe(await checkCode(APP, b.id, a.intro));
  });

  it('uses the collection name it is given', async () => {
    const [a, c] = [await dev('A'), await dev('C')];
    const o = opts(vouchAll(), { collection: 'peers' });
    const r = ok(addDevice(emptyOf(a), o, c.intro, 'member', {}));
    expect(r.collections.peers?.[c.id]).toBeDefined();
    expect(r.collections.device).toBeUndefined();
    expect(listDevices(r, o).map((e) => e.name)).toEqual(['C']);
  });
});

describe('whom a device trusts (admin vouches)', () => {
  // A (admin) entered B (admin) and C (member); C entered X as admin and wrote "admin" into its own entry
  async function setup() {
    const [a, b, c, x, d] = [
      await dev('iPad A'),
      await dev('PC B'),
      await dev('Phone C'),
      await dev('Stranger'),
      await dev('Phone D'),
    ];
    let ra = emptyOf(a);
    ra = ok(addDevice(ra, O, b.intro, 'admin', {}));
    ra = ok(addDevice(ra, O, c.intro, 'member', {}));
    ra = await signed(ra, a);
    let rc = merge(emptyOf(c), ra.log).replica;
    rc = ok(addDevice(rc, O, x.intro, 'admin', {}));
    rc = writeRaw(rc, DEVICE_COLLECTION, c.id, { role: 'admin' });
    rc = await signed(rc, c);
    return { a, b, c, x, d, ra, rc };
  }

  it('through an admin device, step by step; a member vouches for nothing, not even for itself', async () => {
    const { a, d, ra, rc } = await setup();
    const rd = merge(emptyOf(d), [...ra.log, ...rc.log.filter((ch) => ch.device !== a.id)]).replica;
    expect(tagged(await trusted(rd, [known(a, 'admin')]))).toEqual([
      'iPad A:admin',
      'PC B:admin',
      'Phone C:member',
    ]);
  });

  it('unsigned or changed writes of an admin device count for nothing', async () => {
    const { a, b, d } = await setup();
    let ra = addOnly(emptyOf(a), b);
    const rd = holding(d, ra);
    expect(names(await trusted(rd, [known(a, 'admin')]))).toEqual(['iPad A']); // never signed
    ra = await signed(ra, a);
    const changed = ra.log.map((ch) => ({ ...ch, fields: { ...ch.fields, role: 'guest' } }));
    const rd2 = merge(emptyOf(d), changed).replica;
    expect(names(await trusted(rd2, [known(a, 'admin')]))).toEqual(['iPad A']);
  });

  function addOnly(r: Replica, who: { intro: Parameters<typeof addDevice>[2] }) {
    return ok(addDevice(r, O, who.intro, 'admin', {}));
  }

  it('removed by an admin device: no longer trusted, but still checkable for what it wrote before', async () => {
    const { a, b, c, d, ra } = await setup();
    const rb = await drop(b, merge(emptyOf(b), ra.log).replica, c);
    const t = await computeTrust(holding(d, rb), [known(a, 'admin')], O);
    expect(names(t.trusted)).toEqual(['iPad A', 'PC B']);
    expect(names(t.checkable)).toContain('Phone C');
    expect(t.removed).toEqual([c.id]);
    expect(t.selfRemoved).toBe(false);
  });

  it('renamed by an admin: the others trust the new name; same name, unknown device, bad names change nothing', async () => {
    const { a, c, d, ra } = await setup();
    expect(ok(renameDevice(ra, O, c.id, 'Phone C', {}))).toBe(ra);
    for (const bad of ['  ', '', 'x'.repeat(41), ' Lead', 'a|b']) {
      expect(renameDevice(ra, O, c.id, bad, {})).toEqual({ ok: false, reason: 'bad-name' });
    }
    expect(renameDevice(ra, O, 'device-' + '0'.repeat(32), 'New', {}).ok).toBe(false);
    const r = ok(renameDevice(ra, O, c.id, 'Tablet C', {}));
    const t = await trusted(holding(d, await signed(r, a)), [known(a, 'admin')]);
    expect(names(t)).toContain('Tablet C');
    expect(names(t)).not.toContain('Phone C');
  });

  it('a removed admin device cannot take its removal back by writing into its own entry', async () => {
    const { a, b, d, ra } = await setup();
    let rb = merge(emptyOf(b), ra.log).replica;
    const ra2 = await drop(a, ra, b);
    rb = merge(rb, ra2.log).replica;
    rb = await signed(writeRaw(rb, DEVICE_COLLECTION, b.id, { removed: false }), b);
    const rd = merge(emptyOf(d), [
      ...ra2.log,
      ...rb.log.filter((ch) => ch.device === b.id),
    ]).replica;
    expect(names(await trusted(rd, [known(a, 'admin')]))).not.toContain('PC B');
  });

  it('a role that no longer counts is dropped but remembered as vouched (roleCounts hook)', async () => {
    const { a, d, ra } = await setup();
    const o = opts(vouchRoles(['admin']), { roleCounts: (role) => role !== 'member' });
    const list = await trusted(holding(d, ra), [known(a, 'admin')], o);
    expect(tagged(list)).toContain('Phone C:-');
    expect(list.find((e) => e.name === 'Phone C')?.roleVouched).toBe('member');
  });

  it('a vouching strategy decides; vouchAll lets even a device without a role vouch', async () => {
    const [a, b, c] = [await dev('A'), await dev('B'), await dev('C')];
    const rb = await enter(b, emptyOf(b), c, undefined, opts(vouchAll()));
    const rd = holding('device-' + '1'.repeat(32), rb);
    expect(names(await trusted(rd, [known(b)], opts(vouchAll())))).toEqual(['B', 'C']);
    expect(names(await trusted(rd, [known(b)], opts(vouchRoles(['admin']))))).toEqual(['B']);
    expect(names(await trusted(rd, [known(b)], opts(vouchAnyRole())))).toEqual(['B']);
    expect(a).toBeDefined();
  });

  it('a throwing or lying voucher never makes a device trusted by accident', async () => {
    const [b, c] = [await dev('B'), await dev('C')];
    const rb = await enter(b, emptyOf(b), c, 'admin');
    const rd = holding('device-' + '1'.repeat(32), rb);
    const none = { canVouch: () => false };
    expect(names(await trusted(rd, [known(b, 'admin')], opts(none)))).toEqual(['B']);
  });
});

describe('private device flag', () => {
  // only roles other than "admin" may be private (the app's rule, a hook of the package)
  const P = opts(vouchRoles(['admin']), { valid: { privateRoles: (r) => r !== 'admin' } });

  it('entering with private=true writes the flag; without it no private field is written', async () => {
    const c = await dev('Phone');
    const ra = emptyOf('device-' + 'a'.repeat(32));
    const priv = ok(addDevice(ra, P, c.intro, 'member', {}, { private: true }));
    expect(listDevices(priv, P).find((e) => e.device === c.id)?.private).toBe(true);
    const plain = ok(addDevice(ra, P, c.intro, 'member', {}));
    expect(plain.log.some((ch) => ch.fields && 'private' in ch.fields)).toBe(false);
    expect(listDevices(plain, P).find((e) => e.device === c.id)?.private).toBe(false);
  });

  it('an admin cannot be private; an existing differing flag is rewritten, an equal one stands', async () => {
    const [b, c] = [await dev('PC'), await dev('Phone')];
    const ra = emptyOf('device-' + 'a'.repeat(32));
    expect(addDevice(ra, P, b.intro, 'admin', {}, { private: true })).toEqual({
      ok: false,
      reason: 'private-role',
    });
    const set = ok(addDevice(ra, P, c.intro, 'member', {}, { private: true }));
    const back = ok(addDevice(set, P, c.intro, 'member', {}, { private: false }));
    expect(listDevices(back, P).find((e) => e.device === c.id)?.private).toBe(false);
    expect(ok(addDevice(back, P, c.intro, 'member', {}, { private: false }))).toBe(back);
  });

  it('setDevicePrivate sets and clears; idempotent; refuses bad values, unknown and admin devices', async () => {
    const [b, c] = [await dev('PC'), await dev('Phone')];
    let ra = emptyOf('device-' + 'a'.repeat(32));
    ra = ok(addDevice(ra, P, b.intro, 'admin', {}));
    ra = ok(addDevice(ra, P, c.intro, 'member', {}));
    const set = ok(setDevicePrivate(ra, P, c.id, true, {}));
    expect(listDevices(set, P).find((e) => e.device === c.id)?.private).toBe(true);
    expect(ok(setDevicePrivate(set, P, c.id, true, {}))).toBe(set);
    const cleared = ok(setDevicePrivate(set, P, c.id, false, {}));
    expect(listDevices(cleared, P).find((e) => e.device === c.id)?.private).toBe(false);
    expect(ok(setDevicePrivate(ra, P, c.id, false, {}))).toBe(ra); // missing counts as false
    for (const bad of ['yes', 1, undefined, null]) {
      expect(setDevicePrivate(ra, P, c.id, bad as never, {})).toEqual({
        ok: false,
        reason: 'bad-value',
      });
    }
    expect(setDevicePrivate(ra, P, 'device-' + '0'.repeat(32), true, {}).ok).toBe(false);
    expect(setDevicePrivate(ra, P, b.id, true, {})).toEqual({ ok: false, reason: 'private-role' });
    expect(ok(setDevicePrivate(ra, P, b.id, false, {}))).toBe(ra);
    const hidden = merge(ra, []).replica;
    const gone = write(hidden, DEVICE_COLLECTION, c.id, { deleted: true }, {});
    expect(gone.ok && setDevicePrivate(gone.replica, P, c.id, true, {}).ok).toBe(false);
  });
});

describe('vouching with any role (roles name persons that must exist)', () => {
  const PERSONS = 'person';
  const hasPerson = (role: string, r: Replica) => {
    const rec = r.collections[PERSONS]?.[role.replace('person:', '')];
    return !!rec && !rec.deleted && rec.fields.deleted?.value !== true;
  };
  const OA = opts(vouchAnyRole(), { roleCounts: hasPerson });
  const withPersons = (r: Replica, ...ids: string[]) =>
    ids.reduce((x, id) => writeRaw(x, PERSONS, id, { active: true }), r);
  const bei = (viewer: string, ...logs: Replica[]) =>
    logs.reduce((r, x) => merge(r, x.log).replica, withPersons(emptyOf(viewer), 'rolf', 'thomas'));
  const ROLF = 'person:rolf';
  const THOMAS = 'person:thomas';

  it('a chain: A trusts B, B entered C, C entered D', async () => {
    const [a, b, c, d] = [await dev('A'), await dev('B'), await dev('C'), await dev('D')];
    const rb = await enter(b, emptyOf(b), c, THOMAS, OA);
    const ra = bei(a.id, rb);
    const list = await trusted(ra, [known(b, ROLF)], OA);
    expect(names(list)).toEqual(['B', 'C']);
    const viaChain = list.find((x) => x.name === 'C');
    expect(viaChain?.since).toBeUndefined();
    expect(viaChain?.role).toBe(THOMAS);
    const rc = await enter(c, emptyOf(c), d, undefined, OA);
    expect(names(await trusted(merge(ra, rc.log).replica, [known(b, ROLF)], OA))).toEqual([
      'B',
      'C',
      'D',
    ]);
  });

  it('unsigned, changed, or entered by a device nobody trusts: counts for nothing', async () => {
    const [a, b, c, x] = [await dev('A'), await dev('B'), await dev('C'), await dev('X')];
    const rb = await enter(b, emptyOf(b), c, undefined, OA);
    const unsigned = rb.log.map((ch) => {
      const { sig: _s, check: _c, ...rest } = ch;
      return rest;
    });
    expect(names(await trusted(merge(bei(a.id), unsigned).replica, [known(b, ROLF)], OA))).toEqual([
      'B',
    ]);
    const other = rb.log.map((ch) =>
      ch.collection === DEVICE_COLLECTION
        ? { ...ch, fields: { ...ch.fields, dh: x.intro.dh } }
        : ch,
    );
    expect(names(await trusted(merge(bei(a.id), other).replica, [known(b, ROLF)], OA))).toEqual([
      'B',
    ]);
    const rx = await enter(x, emptyOf(x), c, undefined, OA);
    expect(names(await trusted(bei(a.id, rx), [known(b, ROLF)], OA))).toEqual(['B']);
  });

  it('only a device with a counting role vouches', async () => {
    const [a, b, c] = [await dev('A'), await dev('B'), await dev('C')];
    const rb = await enter(b, emptyOf(b), c, THOMAS, OA);
    const ra = bei(a.id, rb);
    expect(names(await trusted(ra, [known(b)], OA))).toEqual(['B']);
    expect(names(await trusted(ra, [known(b, 'person:nobody')], OA))).toEqual(['B']);
    const hidden = ok({ ok: true, replica: ra }); // person hidden: B vouches no more
    const gone = softDelete(hidden, PERSONS, 'rolf', {});
    expect(gone.ok && names(await trusted(gone.replica, [known(b, ROLF)], OA))).toEqual(['B']);
    expect(names(await trusted(ra, [known(b, ROLF)], OA))).toEqual(['B', 'C']);
  });

  it('a role learned later from an entry makes a direct device a voucher (regression)', async () => {
    const [a, b, c, d] = [await dev('A'), await dev('B'), await dev('C'), await dev('D')];
    // B (met without a role) entered D; C (Rolf's) entered B as Thomas's. D's entry comes first.
    const rb = await enter(b, emptyOf(b), d, undefined, OA);
    const rc = await enter(c, emptyOf(c), b, THOMAS, OA);
    const list = await trusted(bei(a.id, rb, rc), [known(b), known(c, ROLF)], OA);
    expect(names(list)).toEqual(['B', 'C', 'D']);
    expect(list.find((x) => x.name === 'B')?.role).toBe(THOMAS);
  });

  it('own entries count without a signature; a met device with other keys stays itself; the own record is left out', async () => {
    const [a, b, c] = [await dev('A'), await dev('B'), await dev('C')];
    const ra = ok(addDevice(emptyOf(a), OA, c.intro, undefined, {}));
    expect(names(await trusted(ra, [], OA))).toEqual(['C']);
    const forged = { ...c, intro: { ...c.intro, dh: b.intro.dh, sig: b.intro.sig } };
    const rb = await enter(b, emptyOf(b), forged, undefined, OA);
    const list = await trusted(bei(a.id, rb), [known(b, ROLF), known(c)], OA);
    expect(list.find((x) => x.name === 'C')?.dh).toBe(c.intro.dh);
    const self = ok(addDevice(emptyOf(a), OA, a.intro, undefined, {}));
    expect(await trusted(self, [], OA)).toEqual([]);
  });

  it('a removal by a trusted device ends trust, also of what came only through the removed', async () => {
    const [a, b, c, d] = [await dev('A'), await dev('B'), await dev('C'), await dev('D')];
    let rb = await enter(b, emptyOf(b), c, THOMAS, OA);
    const rc = await enter(c, emptyOf(c), d, undefined, OA);
    rb = merge(rb, rc.log).replica;
    const ra = bei(a.id, rb);
    expect(names(await trusted(ra, [known(b, ROLF)], OA))).toEqual(['B', 'C', 'D']);
    const rb2 = await drop(b, rb, c, OA);
    const ra2 = merge(ra, rb2.log).replica;
    expect(names(await trusted(ra2, [known(b, ROLF)], OA))).toEqual(['B']);
    expect(listDevices(ra2, OA).find((e) => e.name === 'C')?.removed).toBe(true);
    // a removal of B by somebody A does not trust changes nothing
    const x = await dev('X');
    const rx = await drop(x, await enter(x, emptyOf(x), b, undefined, OA), b, OA);
    expect(names(await trusted(merge(ra, rx.log).replica, [known(b, ROLF)], OA))).toContain('B');
    // nor one by a trusted device without a role (regression)
    const y = await dev('Y');
    const ry = await drop(y, merge(emptyOf(y), rb.log).replica, c, OA);
    const withY = merge(ra, ry.log).replica;
    expect(listDevices(withY, OA).find((e) => e.name === 'C')?.removed).toBe(true);
    expect(names(await trusted(withY, [known(b, ROLF), known(y)], OA))).toEqual([
      'B',
      'C',
      'D',
      'Y',
    ]);
    // nor a removal written under B's name but signed with another key
    const forged = await drop(y, rb, c, OA);
    expect(names(await trusted(merge(ra, forged.log).replica, [known(b, ROLF)], OA))).toEqual([
      'B',
      'C',
      'D',
    ]);
  });

  it('a removed device stays checkable, never trusted, vouches for nothing; a met one stays checkable with the met keys', async () => {
    const [a, b, c, d] = [await dev('A'), await dev('B'), await dev('C'), await dev('D')];
    let rb = await enter(b, emptyOf(b), c, THOMAS, OA);
    const rc = await enter(c, emptyOf(c), d, undefined, OA);
    rb = merge(rb, rc.log).replica;
    const ra = merge(bei(a.id, rb), (await drop(b, rb, c, OA)).log).replica;
    const both = await computeTrust(ra, [known(b, ROLF)], OA);
    expect(names(both.trusted)).toEqual(['B']);
    expect(names(both.checkable)).toEqual(['B', 'C']);
    expect(both.removed).toEqual([c.id]);
    expect((await computeTrust(bei(a.id, rb), [known(b, ROLF)], OA)).removed).toEqual([]);
    expect(both.checkable.find((x) => x.name === 'C')?.sig).toBe(c.intro.sig);
    const y = await dev('Y');
    const withY = await enter(b, rb, y, THOMAS, OA);
    const out = merge(bei(a.id, withY), (await drop(b, withY, y, OA)).log).replica;
    const here = [known(b, ROLF), known(y, THOMAS)];
    expect(names(await trusted(out, here, OA))).toEqual(['B', 'C', 'D']);
    expect(names((await computeTrust(out, here, OA)).checkable)).toEqual(['B', 'C', 'D', 'Y']);
  });

  it('hiding ("deleting") an entry by anybody does not end the trust', async () => {
    const [a, b, c, y] = [await dev('A'), await dev('B'), await dev('C'), await dev('Y')];
    const rb = await enter(b, emptyOf(b), c, THOMAS, OA);
    const ry0 = merge(emptyOf(y), rb.log).replica;
    const hid = softDelete(ry0, DEVICE_COLLECTION, c.id, { time: 5 });
    if (!hid.ok) throw new Error(hid.reason);
    const ry = await signed(hid.replica, y);
    expect(names(await trusted(bei(a.id, rb, ry), [known(b, ROLF), known(y)], OA))).toEqual([
      'B',
      'C',
      'Y',
    ]);
  });

  it('a removed device cannot undo its removal by writing into its own entry', async () => {
    const [a, b, c] = [await dev('A'), await dev('B'), await dev('C')];
    const rb = await drop(b, await enter(b, emptyOf(b), c, THOMAS, OA), c, OA);
    const rc = merge(emptyOf(c), rb.log).replica;
    const back = ok(addDevice(rc, OA, c.intro, THOMAS, { time: 3 }));
    expect(listDevices(back, OA).find((e) => e.name === 'C')?.removed).toBe(false);
    const rc2 = await signed(back, c);
    const both = [known(b, ROLF), known(c, THOMAS)];
    expect(names(await trusted(bei(a.id, rb), both, OA))).toEqual(['B']);
    expect(names(await trusted(bei(a.id, rb, rc2), both, OA))).toEqual(['B']);
  });

  it('what a device without a role writes into an entry counts for nothing', async () => {
    const [a, b, c, y] = [await dev('A'), await dev('B'), await dev('C'), await dev('Y')];
    const rb = await enter(b, emptyOf(b), c, THOMAS, OA);
    const ry0 = merge(emptyOf(y), rb.log).replica;
    const ry1 = writeRaw(ry0, DEVICE_COLLECTION, c.id, {
      sig: y.intro.sig,
      dh: y.intro.dh,
      role: ROLF,
    });
    const ry = await signed(ry1, y);
    const ra = bei(a.id, rb, ry);
    expect(listDevices(ra, OA).find((e) => e.name === 'C')?.sig).toBe(y.intro.sig);
    const list = await trusted(ra, [known(b, ROLF), known(y)], OA);
    expect(list.find((x) => x.name === 'C')).toMatchObject({ sig: c.intro.sig, role: THOMAS });
  });

  it('entering again changes nothing; a role from an entry is added to a met device; bad input is refused', async () => {
    const [a, b, c] = [await dev('A'), await dev('B'), await dev('C')];
    const r1 = ok(addDevice(emptyOf(a), OA, c.intro, ROLF, {}));
    expect(ok(addDevice(r1, OA, c.intro, ROLF, {}))).toBe(r1);
    expect(addDevice(r1, OA, { ...c.intro, dh: b.intro.dh }, undefined, {})).toEqual({
      ok: false,
      reason: 'other-keys',
    });
    expect(addDevice(r1, OA, c.intro, 'has blanks', {})).toEqual({ ok: false, reason: 'bad-role' });
    expect(addDevice(r1, OA, { ...c.intro, device: 'nope' }, ROLF, {})).toEqual({
      ok: false,
      reason: 'bad-id',
    });
    expect(addDevice(r1, OA, { ...c.intro, name: '' }, ROLF, {})).toEqual({
      ok: false,
      reason: 'bad-name',
    });
    expect(addDevice(r1, OA, c.intro, ROLF, {}, { relayId: 'a\u0007b' })).toEqual({
      ok: false,
      reason: 'bad-relay-id',
    });
    const rb = await enter(b, emptyOf(b), c, ROLF, OA);
    const list = await trusted(bei(a.id, rb), [known(b, THOMAS), known(c)], OA);
    expect(list.find((x) => x.name === 'C')?.role).toBe(ROLF);
  });

  it('"remove first, then meet again": a removed id takes other keys; removing nothing writes nothing', async () => {
    const [a, b, c] = [await dev('A'), await dev('B'), await dev('C')];
    const empty = emptyOf(a);
    expect(ok(removeDevice(empty, OA, c.id, {}))).toBe(empty);
    const r1 = ok(addDevice(empty, OA, c.intro, undefined, {}));
    const gone = ok(removeDevice(r1, OA, c.id, {}));
    expect(ok(removeDevice(gone, OA, c.id, {}))).toBe(gone);
    const renewed = { ...c.intro, sig: b.intro.sig, dh: b.intro.dh };
    const r2 = ok(addDevice(gone, OA, renewed, undefined, {}));
    expect(listDevices(r2, OA).find((e) => e.device === c.id)).toMatchObject({
      sig: b.intro.sig,
      removed: false,
    });
    expect(names(await trusted(r2, [], OA))).toEqual(['C']);
  });

  it('a relay id is carried by the entry and read back only when the app accepts it', async () => {
    const [a, c] = [await dev('A'), await dev('C')];
    const r = ok(addDevice(emptyOf(a), OA, c.intro, ROLF, {}, { relayId: 'relay-1' }));
    expect(listDevices(r, OA)[0]?.relayId).toBe('relay-1');
    const strict = opts(vouchAll(), { valid: { relayId: (s) => /^r-/.test(s) } });
    expect(listDevices(r, strict)[0]?.relayId).toBeUndefined();
    expect((await trusted(r, [], strict))[0]?.relayId).toBeUndefined();
    expect((await trusted(r, [], OA))[0]?.relayId).toBe('relay-1');
  });
});
