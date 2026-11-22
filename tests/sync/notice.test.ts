// The removal notice in the sync driver: a removed device is told once, safely, and nothing else is
// sent to it; a notice that arrives is judged on a throw-away copy and only a valid proof stops the
// step; the lock takes the verdict. Real keys, signatures, trust layer and relay client; nothing is mocked.
import { describe, expect, it } from 'vitest';
import { sealFile } from '../../src/core/index.ts';
import { lockRemovedBy, lockStatus } from '../../src/lock/index.ts';
import { queueFile, totals, type SyncRelay } from '../../src/sync/index.ts';
import { rememberTold } from '../../src/sync/notice.ts';
import { newSyncState } from '../../src/sync/state.ts';
import { removalNotice, writeRemovalNotice } from '../../src/trust/index.ts';
import { start } from '../lock/helpers.ts';
import {
  APP,
  TRUST,
  chaotic,
  freshRandom,
  note,
  prng,
  removeFrom,
  rounds,
  step,
  text,
  world,
  type Member,
  type World,
} from './helpers.ts';

const trio = async (opts: Parameters<typeof world>[1] = {}) => {
  const w = await world(['A', 'B', 'C', 'D'], opts);
  const [a, b, c, d] = w.members as [Member, Member, Member, Member];
  return { w, a, b, c, d };
};

/** Counts what each member drops, by recipient relay id. */
const spy =
  (log: Map<string, number>) =>
  (inner: SyncRelay): SyncRelay => ({
    deviceId: () => inner.deviceId(),
    collectAll: (o) => inner.collectAll(o),
    drop: (r, o) => {
      for (const x of r) log.set(x.device, (log.get(x.device) ?? 0) + 1);
      return inner.drop(r, o);
    },
  });

const lastOf = (m: Member) => m.reports[m.reports.length - 1]!;

describe('a removed device is told once, safely', () => {
  it('C learns of its removal from a notice, locks for good and does nothing more; its data is left as it was', async () => {
    const { w, a, c } = await trio();
    note(a, 'n1', 'before');
    await rounds(w, 8);
    expect(text(c, 'n1')).toBe('before');
    removeFrom(a, c);
    const before = c.replica;
    await rounds(w, 8);
    const proofs = c.reports.filter((r) => r.notice?.selfRemoved === true);
    expect(proofs).toHaveLength(1);
    expect(proofs[0]!.notice).toEqual({ selfRemoved: true, reason: 'removed' });
    expect(c.state.removedProof).toBe(true);
    // the notice was judged apart: nothing of it is in C's replica
    expect(c.replica.log).toEqual(before.log);
    expect(JSON.stringify(c.replica.vector)).toBe(JSON.stringify(before.vector));
    // from then on the step does nothing
    const after = c.reports.slice(c.reports.indexOf(proofs[0]!) + 1);
    expect(after.length).toBeGreaterThan(0);
    expect(after.every((r) => r.selfRemoved && r.collected === 0 && r.framesSent === 0)).toBe(true);
    // the lock layer takes it: locked for good, reason removed
    const locked = lockRemovedBy(
      start({ source: 'peer', kind: 'device', maxDays: 10, warnDays: 7 }),
      proofs[0]!.notice,
    );
    expect(lockStatus(locked, 0)).toMatchObject({ status: 'locked', reason: 'removed' });
    // data written after the removal does not reach it
    note(a, 'n2', 'after');
    await rounds(w, 6);
    expect(text(c, 'n2')).toBeUndefined();
  });

  it('every removed device is told exactly once; nothing else is sent to it (not a sync packet, not a queued file)', async () => {
    const sent = new Map<string, number>();
    const { w, a, b, c } = await trio({ relayWrap: (m) => spy(sent)(m) });
    void b;
    note(a, 'n1', 'x');
    await rounds(w, 6);
    removeFrom(a, c);
    sent.clear();
    // a grant (any file) for the removed device is queued as well: it must be dropped at the step
    await send(w, a, c, new TextEncoder().encode('any file for the removed device'));
    await rounds(w, 10);
    expect(a.reports.flatMap((r) => r.told)).toEqual([c.id]);
    // the queued file never reached it: all it collected was the notice
    expect(c.reports.flatMap((r) => r.passed)).toEqual([]);
    expect(c.state.removedProof).toBe(true);
    // only A and B (both trusted) tell it; each at most once
    const toC = sent.get(c.relayId) ?? 0;
    expect(toC).toBeGreaterThan(0);
    expect(toC).toBeLessThanOrEqual(2 * 40);
    await rounds(w, 5);
    expect(sent.get(c.relayId) ?? 0).toBe(toC);
  });

  it('a device that was offline when it was removed is told when it shows up, and only then', async () => {
    const { w, a, b, c } = await trio();
    note(a, 'n1', 'x');
    await rounds(w, 6);
    removeFrom(a, c);
    // C stays away until the relay does not list it as present any more: A and B step alone
    w.advance(60_000);
    await rounds(w, 6, [a, b]);
    expect(a.reports.flatMap((r) => r.told)).toEqual([]);
    expect(c.state.removedProof).toBe(false);
    await rounds(w, 8);
    expect(c.state.removedProof).toBe(true);
  });

  it("the notice carries the chain only: a bystander's entry is not in it", async () => {
    const { w, a, c, d } = await trio();
    note(a, 'n1', 'x');
    await rounds(w, 6);
    removeFrom(a, c);
    await step(w, a);
    const made = removalNotice(a.replica, c.id, { ...TRUST, direct: [] });
    expect(made.ok).toBe(true);
    if (!made.ok) return;
    expect(made.changes.every((x) => x.id !== d.id)).toBe(true);
    expect(made.changes.some((x) => x.id === c.id)).toBe(true);
  });
});

/** A sealed notice from `from`, queued to `to` (a hostile or mistaken peer can do exactly this). */
async function send(w: World, from: Member, to: Member, payload: Uint8Array): Promise<void> {
  const sealed = await sealFile({
    appId: APP,
    own: { device: from.id, agreement: from.keys.agreement },
    to: { device: to.id, dh: to.intro.dh },
    payload,
    random: freshRandom(3)(12),
  });
  if (!sealed.ok) throw new Error(sealed.reason);
  expect(queueFile(from.config, from.state, to.id, sealed.file, w.now()).ok).toBe(true);
}

describe('a received notice is judged, never believed', () => {
  async function removed() {
    const k = await trio();
    note(k.a, 'n1', 'x');
    await rounds(k.w, 6);
    // the real notice is not in play here: A counts C as told already
    k.a.state.told.set(k.c.id, k.w.now());
    removeFrom(k.a, k.c);
    await step(k.w, k.a);
    const made = removalNotice(k.a.replica, k.c.id, { ...TRUST, direct: [] });
    if (!made.ok) throw new Error(made.reason);
    return { ...k, changes: made.changes };
  }

  it("the notice of C's removal proves nothing about D: D goes on, and says why", async () => {
    const { w, a, d, changes } = await removed();
    await send(w, a, d, writeRemovalNotice(APP, changes));
    await rounds(w, 4);
    const verdicts = d.reports.map((r) => r.notice).filter(Boolean);
    expect(verdicts).toEqual([{ selfRemoved: false, reason: 'no-proof' }]);
    expect(d.state.removedProof).toBe(false);
    expect(totals(d.state)['notice-no-proof']).toBe(1);
    expect(lastOf(d).selfRemoved).toBe(false);
    note(a, 'n5', 'still works');
    await rounds(w, 6);
    expect(text(d, 'n5')).toBe('still works');
  });

  it('a changed write is refused as a whole; a notice that does not read is dropped; neither locks', async () => {
    const { w, a, b, c, changes } = await removed();
    // B has not heard of the removal yet, so it is still a peer of C and can send it what it likes
    void a;
    const last = changes.length - 1;
    const forged = changes.map((x, i) =>
      i === last ? { ...x, fields: { ...x.fields, name: 'Other' } } : x,
    );
    await send(w, b, c, writeRemovalNotice(APP, forged));
    await send(w, b, c, new TextEncoder().encode(`{"m":"${APP}-removal:1","changes":[]}`));
    await rounds(w, 1, [b, c]);
    await rounds(w, 3, [c]);
    expect(totals(c.state)['notice-refused']).toBe(1);
    expect(totals(c.state)['bad-notice']).toBe(1);
    expect(c.state.removedProof).toBe(false);
    expect(c.reports.some((r) => r.selfRemoved)).toBe(false);
  });

  it('at most maxNoticesPerStep are judged per step, the rest are dropped', async () => {
    const { w, a, d, changes } = await removed();
    for (let i = 0; i < 4; i += 1) await send(w, a, d, writeRemovalNotice(APP, changes));
    await rounds(w, 3, [a, d]);
    expect(totals(d.state)['notice-no-proof']).toBeGreaterThan(0);
    expect(totals(d.state)['notice-rate-limited']).toBeGreaterThan(0);
  });

  it('a notice from a device that is no peer is dropped before anything is read', async () => {
    const w = await world(['A', 'B', 'C', 'Z'], { outsiders: 1 });
    const [a, b, c, z] = w.members as [Member, Member, Member, Member];
    note(a, 'n1', 'x');
    await rounds(w, 6, [a, b, c]);
    // A and B count C as told already: only Z's notice is in play
    a.state.told.set(c.id, w.now());
    b.state.told.set(c.id, w.now());
    removeFrom(a, c);
    await step(w, a);
    const made = removalNotice(a.replica, c.id, { ...TRUST, direct: [] });
    if (!made.ok) throw new Error(made.reason);
    // Z seals it to C with its own keys: Z is not in C's device list
    const sealed = await sealFile({
      appId: APP,
      own: { device: z.id, agreement: z.keys.agreement },
      to: { device: c.id, dh: c.intro.dh },
      payload: writeRemovalNotice(APP, made.changes),
      random: freshRandom(4)(12),
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    // Z has no entry anywhere, so it cannot queue through its own roster; it drops straight at the relay
    const { splitPayload } = await import('../../src/relay/index.ts');
    const frames = splitPayload(APP, sealed.file, '0123456789abcdef');
    if (!frames.ok) throw new Error('frames');
    for (const f of frames.frames) await z.client.drop([{ device: c.relayId, content: f }]);
    await rounds(w, 3, [c]);
    expect(totals(c.state)['unknown-sender']).toBeGreaterThan(0);
    expect(c.state.removedProof).toBe(false);
  });
});

describe('bounds', () => {
  it('the memory of who was told is bounded and forgets the oldest first', () => {
    const state = newSyncState(APP);
    for (let i = 0; i < 5; i += 1) rememberTold(state, `d${i}`, i, 3);
    expect([...state.told.keys()]).toEqual(['d2', 'd3', 'd4']);
    rememberTold(state, 'd2', 9, 3);
    expect([...state.told.keys()]).toEqual(['d3', 'd4', 'd2']);
  });

  it('at most maxNoticeTargets removed devices are asked for presence at once', async () => {
    const { w, a, b, c, d } = await trio({});
    note(a, 'n1', 'x');
    await rounds(w, 6);
    w.advance(60_000);
    removeFrom(a, c);
    removeFrom(a, d);
    await step(w, a);
    a.config = { ...a.config, limits: { maxNoticeTargets: 1 } };
    await step(w, a);
    expect(a.state.noticeTargets.size).toBe(1);
    void b;
  });
});

describe('seeded schedules with a misbehaving relay', () => {
  it('a device that is not removed never concludes it is; a removed one that gets the notice does, and stops', async () => {
    let learned = 0;
    for (let seed = 1; seed <= 8; seed += 1) {
      const rnd = prng(seed);
      const w = await world(['A', 'B', 'C', 'D'], {
        seed,
        relayWrap: (m) =>
          chaotic(
            m,
            rnd,
            { loseDrop: 0.15, duplicate: 0.2, reorder: 0.2, loseCollect: 0.1, forgeFrom: 0.05 },
            () => w.members.map((m) => m.relayId),
          ),
      });
      const [a, b, c, d] = w.members as [Member, Member, Member, Member];
      note(a, 'n1', 'x');
      await rounds(w, 6);
      removeFrom(a, rnd() < 0.5 ? c : d);
      await rounds(w, 30);
      const gone = [c, d].filter((m) => m.state.removedProof);
      expect(gone.length).toBeLessThanOrEqual(1);
      for (const m of [a, b]) expect(m.state.removedProof).toBe(false);
      learned += gone.length;
      // never two removed: only one device was removed
      for (const m of gone)
        expect(a.replica.collections.device?.[m.id]?.fields.removed?.value).toBe(true);
    }
    expect(learned).toBeGreaterThan(0);
  }, 120_000);
});
