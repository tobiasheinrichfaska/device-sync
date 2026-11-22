// Trust and log together: invitation -> entry in the log -> signed changes of the new device judged by
// a third replica with `readChanges` + `deviceKeySource`.
import { beforeAll, describe, expect, it } from 'vitest';
import {
  insertSignatures,
  merge,
  readChanges,
  signOwnChanges,
  write,
  type Change,
  type JudgeOptions,
  type Replica,
} from '../../src/log/index.ts';
import {
  DEVICE_COLLECTION,
  addDevice,
  checkReply,
  computeTrust,
  createInvitation,
  deviceKeySource,
  deviceNeverErase,
  invitationLink,
  invitationProof,
  parseInvitation,
  parseReply,
  removeDevice,
  replyText,
  vouchRoles,
  type DeviceEntry,
  type KnownDevice,
  type TrustOptions,
} from '../../src/trust/index.ts';
import { APP, SET, dev, emptyOf, known, names, ok, opts, signed, type Dev } from './helpers.ts';

const NOW = 1_800_000_000_000;
const O: TrustOptions = opts(vouchRoles(['admin']));
const entryOf = (d: Dev, role: string): DeviceEntry => ({
  ...d.intro,
  role,
  removed: false,
  private: false,
});

const note = async (d: Dev, r: Replica, id: string, text: string): Promise<Replica> => {
  const w = write(r, 'notes', id, { text }, { time: 1, by: d.name });
  if (!w.ok) throw new Error(w.reason);
  return signed(w.replica, d);
};

/** Device `inviter` invites `joiner` with a role through the whole text exchange; returns the inviter's replica with the entry. */
async function join(inviter: Dev, replica: Replica, joiner: Dev, role: string, seed: number) {
  const made = createInvitation(
    { appId: APP, voucher: O.voucher },
    entryOf(inviter, 'admin'),
    role,
    new Uint8Array(16).fill(seed),
    NOW,
  );
  if (!made.ok) throw new Error(made.reason);
  const read = parseInvitation(
    { appId: APP },
    invitationLink(APP, 'https://example.org/app', made.invitation),
  );
  if (!read) throw new Error('unreadable invitation');
  const proof = await invitationProof(APP, read, joiner.intro);
  const text = replyText(APP, { to: read.from.device, introduction: joiner.intro, proof });
  const reply = parseReply({ appId: APP }, text);
  if (!reply) throw new Error('unreadable reply');
  const checked = await checkReply(
    { appId: APP, voucher: O.voucher },
    made.open,
    inviter.id,
    reply,
    NOW + 1000,
    entryOf(inviter, 'admin'),
  );
  if (!checked.ok) throw new Error(checked.reason);
  return signed(
    ok(addDevice(replica, O, reply.introduction, made.open.role, { time: NOW })),
    inviter,
  );
}

let a: Dev, b: Dev, c: Dev, z: Dev, r: Dev;
beforeAll(async () => {
  [a, b, c, z, r] = [
    await dev('A'),
    await dev('B'),
    await dev('C'),
    await dev('Z'),
    await dev('R'),
  ];
});

const judge = (
  me: Dev,
  direct: readonly KnownDevice[],
  extra: Partial<JudgeOptions> = {},
): JudgeOptions => ({
  appId: APP,
  dataSet: SET,
  ownDevice: me.id,
  neverErase: deviceNeverErase(),
  keys: deviceKeySource({ ...O, direct }),
  ...extra,
});

describe('a new device joins by invitation and is trusted only through the vouching strategy', () => {
  it('A (admin) invites B; B writes signed changes; a third replica takes them; they are pending without the entry', async () => {
    const ra = await join(a, emptyOf(a), b, 'admin', 1);
    let rb = merge(emptyOf(b), ra.log).replica;
    rb = await note(b, rb, 'n1', 'hello');
    rb = await note(b, rb, 'n2', 'world');
    const fromB = rb.log.filter((ch) => ch.device === b.id);
    const R = emptyOf(r);
    const direct = [known(a, 'admin')];

    // without A's entry the changes of B cannot be checked yet
    const lone = await readChanges(R, fromB, judge(r, direct));
    expect(lone).toMatchObject({ accepted: [], rejected: 0 });
    expect(lone.pending).toHaveLength(2);

    // together with the entry (in the order B's changes first, then the entry: the same batch)
    const batch = [...fromB, ...ra.log];
    const res = await readChanges(R, batch, judge(r, direct));
    expect(res.rejected).toBe(0);
    expect(res.pending).toEqual([]);
    expect(res.accepted).toHaveLength(batch.length);
    const taken = merge(R, res.accepted).replica;
    expect(taken.collections.notes?.n1?.fields.text?.value).toBe('hello');
    expect((await computeTrust(taken, direct, O)).trusted.map((t) => t.name)).toEqual(['A', 'B']);
  });

  it('a device nobody vouches for stays pending, nothing is rejected', async () => {
    const rz = await note(z, emptyOf(z), 'z1', 'spam');
    const res = await readChanges(emptyOf(r), rz.log, judge(r, [known(a, 'admin')]));
    expect(res).toMatchObject({ accepted: [], rejected: 0 });
    expect(res.pending).toHaveLength(1);
  });

  it('a member vouches for nobody: its entry for another device leaves that device pending', async () => {
    const ra = await join(a, emptyOf(a), b, 'member', 2);
    let rb = merge(emptyOf(b), ra.log).replica;
    rb = await signed(ok(addDevice(rb, O, c.intro, 'member', {})), b);
    const rc = await note(c, emptyOf(c), 'c1', 'x');
    const res = await readChanges(
      emptyOf(r),
      [...ra.log, ...rb.log.filter((x) => x.device === b.id), ...rc.log],
      judge(r, [known(a, 'admin')]),
    );
    expect(res.rejected).toBe(0);
    expect(res.pending.map((p) => p.device)).toEqual([c.id]);
    // B's own entry change is signed by B, whose key is known: it is taken but gives C no trust
    expect(res.accepted.some((x) => x.device === b.id)).toBe(true);
  });

  it('chain A -> B -> C: C writes, the third replica takes the changes in one batch', async () => {
    const ra = await join(a, emptyOf(a), b, 'admin', 3);
    let rb = merge(emptyOf(b), ra.log).replica;
    rb = await join(b, rb, c, 'member', 4);
    const rc = await note(c, merge(emptyOf(c), rb.log).replica, 'c1', 'from c');
    const batch: Change[] = [
      ...rc.log.filter((x) => x.device === c.id),
      ...rb.log.filter((x) => x.device === b.id),
      ...ra.log,
    ];
    const res = await readChanges(emptyOf(r), batch, judge(r, [known(a, 'admin')]));
    expect(res.rejected).toBe(0);
    expect(res.pending).toEqual([]);
    expect(res.accepted).toHaveLength(batch.length);
    const taken = merge(emptyOf(r), res.accepted).replica;
    expect(names((await computeTrust(taken, [known(a, 'admin')], O)).trusted)).toEqual([
      'A',
      'B',
      'C',
    ]);
  });

  it('removal by a vouching device ends trust; earlier signed changes stay checkable; what came through the removed is checkable but not trusted', async () => {
    const ra0 = await join(a, emptyOf(a), b, 'admin', 5);
    let rb = merge(emptyOf(b), ra0.log).replica;
    rb = await join(b, rb, c, 'member', 6);
    rb = await note(b, rb, 'b1', 'before removal');
    const rc = await note(c, merge(emptyOf(c), rb.log).replica, 'c1', 'c wrote');
    const ra = merge(ra0, rb.log).replica;
    const removed = await signed(ok(removeDevice(ra, O, b.id, { time: NOW + 5 })), a);
    const all = [
      ...rb.log.filter((x) => x.device === b.id),
      ...rc.log.filter((x) => x.device === c.id),
      ...removed.log.filter((x) => x.device === a.id),
    ];
    const direct = [known(a, 'admin')];
    const res = await readChanges(emptyOf(r), all, judge(r, direct));
    expect(res.rejected).toBe(0);
    // B's earlier notes are checkable though B is removed (its keys are vouched for)
    expect(res.accepted.filter((x) => x.device === b.id).length).toBeGreaterThan(0);
    // C was entered by B only: B's vouching no longer makes C trusted, but its key was vouched for
    // while B stood, so C's changes are checked and taken (an app decides what untrusted data may do)
    expect(res.pending).toEqual([]);
    expect(res.accepted.filter((x) => x.device === c.id).length).toBeGreaterThan(0);
    const taken = merge(emptyOf(r), res.accepted).replica;
    const t = await computeTrust(taken, direct, O);
    expect(names(t.trusted)).toEqual(['A']);
    expect(t.removed).toEqual([b.id]);
    expect(names(t.checkable)).toEqual(['A', 'B', 'C']);
  });

  it('a forged entry never becomes trusted: changed fields by a non-vouching device, or a tampered signed entry', async () => {
    const ra = await join(a, emptyOf(a), b, 'member', 7);
    const direct = [known(a, 'admin')];
    // B (member, not vouching) rewrites its own entry and C's with its own keys and "admin"
    let rb = merge(emptyOf(b), ra.log).replica;
    rb = await signed(ok(addDevice(rb, O, c.intro, 'admin', {})), b);
    const w = write(rb, DEVICE_COLLECTION, b.id, { role: 'admin' }, {});
    if (!w.ok) throw new Error(w.reason);
    rb = await signed(w.replica, b);
    const rc = await note(c, emptyOf(c), 'c1', 'x');
    const res = await readChanges(
      emptyOf(r),
      [...ra.log, ...rb.log.filter((x) => x.device === b.id), ...rc.log],
      judge(r, direct),
    );
    const taken = merge(emptyOf(r), res.accepted).replica;
    const t = await computeTrust(taken, direct, O);
    expect(names(t.trusted)).toEqual(['A', 'B']);
    expect(t.trusted.find((x) => x.name === 'B')?.role).toBe('member');
    expect(res.pending.map((x) => x.device)).toEqual([c.id]);
    // every tampered field of A's signed entry is refused outright
    for (const [field, value] of [
      ['role', 'admin'],
      ['name', 'Evil'],
      ['sig', c.intro.sig],
      ['dh', c.intro.dh],
    ] as const) {
      const bad = ra.log.map((x) =>
        x.collection === DEVICE_COLLECTION ? { ...x, fields: { ...x.fields, [field]: value } } : x,
      );
      const out = await readChanges(emptyOf(r), bad, judge(r, direct));
      expect(out.rejected, field).toBeGreaterThan(0);
      expect(out.accepted).toEqual([]);
    }
    // a final deletion of a device entry is refused (never erased)
    const del = { ...(ra.log[0] as Change), kind: 'delete' as const, seq: 9 };
    expect((await readChanges(emptyOf(r), [del], judge(r, direct))).rejected).toBe(1);
  });

  it('entry changes in the same batch make the changes they enable checkable, in any order', async () => {
    const ra = await join(a, emptyOf(a), b, 'admin', 8);
    let rb = merge(emptyOf(b), ra.log).replica;
    rb = await join(b, rb, c, 'member', 9);
    const rc = await note(c, merge(emptyOf(c), rb.log).replica, 'c1', 'deep');
    const parts: (readonly Change[])[] = [
      rc.log.filter((x) => x.device === c.id),
      rb.log.filter((x) => x.device === b.id),
      ra.log,
    ];
    const perms = [
      [0, 1, 2],
      [0, 2, 1],
      [1, 0, 2],
      [1, 2, 0],
      [2, 0, 1],
      [2, 1, 0],
    ];
    for (const p of perms) {
      const batch = p.flatMap((i) => parts[i] as readonly Change[]);
      const res = await readChanges(emptyOf(r), batch, judge(r, [known(a, 'admin')]));
      expect(res.rejected, p.join()).toBe(0);
      expect(res.pending, p.join()).toEqual([]);
    }
  });

  it('with a replica that holds the entry already, later changes are taken in a later batch', async () => {
    const ra = await join(a, emptyOf(a), b, 'admin', 10);
    const direct = [known(a, 'admin')];
    const first = await readChanges(emptyOf(r), ra.log, judge(r, direct));
    const R1 = merge(emptyOf(r), first.accepted).replica;
    const rb = await note(b, merge(emptyOf(b), ra.log).replica, 'n', 'later');
    const second = await readChanges(
      R1,
      rb.log.filter((x) => x.device === b.id),
      judge(r, direct),
    );
    expect(second.accepted).toHaveLength(1);
  });

  it('the own device key is used for the changes the device holds itself', async () => {
    const ra = await join(a, emptyOf(a), b, 'admin', 11);
    const src = deviceKeySource({
      ...O,
      direct: [],
      own: { device: a.id, publicKey: a.keys.signing.publicKey },
    });
    expect(await src.keyFor(a.id, ra)).toBe(a.keys.signing.publicKey);
    expect(await src.keyFor(b.id, merge(emptyOf(r), ra.log).replica)).toBeUndefined(); // nobody met
    expect(await src.keyFor(b.id, ra)).toBeDefined(); // the entering device's own entry counts unsigned
    expect(await src.keyFor('device-' + '9'.repeat(32), ra)).toBeUndefined();
  });

  it('a direct list given as a function is asked for every new state', async () => {
    let calls = 0;
    const src = deviceKeySource({ ...O, direct: () => (calls++, [known(a, 'admin')]) });
    const ra = await join(a, emptyOf(a), b, 'admin', 12);
    expect(await src.keyFor(a.id, emptyOf(r))).toBeDefined();
    expect(await src.keyFor(b.id, merge(emptyOf(r), ra.log).replica)).toBeDefined();
    expect(calls).toBe(2);
  });

  it('signatures made under another app or data set never open a device', async () => {
    const ra = await join(a, emptyOf(a), b, 'admin', 13);
    const other = emptyOf(a);
    const w = write(
      other,
      DEVICE_COLLECTION,
      b.id,
      { name: b.name, sig: b.intro.sig, dh: b.intro.dh, role: 'admin' },
      {},
    );
    if (!w.ok) throw new Error(w.reason);
    const wrongSet = insertSignatures(
      w.replica,
      await signOwnChanges(APP, a.keys.signing.privateKey, w.replica, 'other-set'),
    );
    const t = await computeTrust(merge(emptyOf(r), wrongSet.log).replica, [known(a, 'admin')], O);
    expect(names(t.trusted)).toEqual(['A']);
    const wrongApp = insertSignatures(
      w.replica,
      await signOwnChanges('otherapp', a.keys.signing.privateKey, w.replica, SET),
    );
    const t2 = await computeTrust(merge(emptyOf(r), wrongApp.log).replica, [known(a, 'admin')], O);
    expect(names(t2.trusted)).toEqual(['A']);
    expect(
      names(
        (await computeTrust(merge(emptyOf(r), ra.log).replica, [known(a, 'admin')], O)).trusted,
      ),
    ).toEqual(['A', 'B']);
  });

  it('a device removed by a trusted device that removes itself by hand: selfRemoved is reported', async () => {
    const ra = await join(a, emptyOf(a), b, 'admin', 14);
    const removed = await signed(ok(removeDevice(ra, O, r.id, {})), a); // nothing entered: no-op
    expect(removed).toBe(ra);
    const withR = await join(a, ra, r, 'member', 15);
    const gone = await signed(ok(removeDevice(withR, O, r.id, { time: 2 })), a);
    const mine = merge(emptyOf(r), gone.log).replica;
    expect((await computeTrust(mine, [known(a, 'admin')], O)).selfRemoved).toBe(true);
    expect(
      (await computeTrust(merge(emptyOf(r), withR.log).replica, [known(a, 'admin')], O))
        .selfRemoved,
    ).toBe(false);
  });
});
