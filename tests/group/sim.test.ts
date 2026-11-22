// Seeded multi-device simulations with the real trust layer: devices see removals at different
// times, rotate concurrently (also a removed device on a stale view), grants arrive shuffled and
// repeated. After the group repairs itself every trusted device chooses the same key, no removed
// device holds it, and every message is readable by the devices that hold its key.
import { describe, expect, it } from 'vitest';
import {
  acceptGrant,
  decryptGroup,
  encryptGroup,
  findGroupKey,
  isRotationLead,
  issueGrants,
  needsRotation,
  preferredKey,
  rotateGroup,
  type GroupState,
  type IssuedGrant,
} from '../../src/group/index.ts';
import { APP, fresh, prng, seeded, text, world, type World } from './helpers.ts';

interface Pending {
  readonly grant: IssuedGrant;
}

async function run(seed: number): Promise<{ epochs: number; concurrent: number }> {
  const next = prng(seed);
  const rnd = seeded(seed * 7 + 1);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(next() * list.length)] as T;
  const w: World = await world(['A', 'B', 'C', 'D', 'E']);
  const states = new Map<string, GroupState>(w.devs.map((d) => [d.id, fresh()]));
  const seen = new Map<string, number>(w.devs.map((d) => [d.id, 0]));
  const removed = new Set<string>();
  let pending: Pending[] = [];
  const messages: { text: string; by: string; epoch: number; kid: string; plain: string }[] = [];
  let concurrent = 0;

  const trust = (id: string) =>
    w.trustOf(
      w.devs.find((d) => d.id === id)!,
      seen.get(id),
    );
  const deliverSome = async (share: number, dup: boolean) => {
    const batch = pending.filter(() => next() < share);
    pending = pending.filter((p) => !batch.includes(p));
    for (let i = batch.length - 1; i > 0; i -= 1) {
      const j = Math.floor(next() * (i + 1));
      [batch[i], batch[j]] = [batch[j] as Pending, batch[i] as Pending];
    }
    for (const { grant } of dup ? [...batch, ...batch.filter(() => next() < 0.3)] : batch) {
      const d = w.devs.find((x) => x.id === grant.to)!;
      const r = await acceptGrant({
        appId: APP,
        own: w.own(d),
        trust: await trust(d.id),
        state: states.get(d.id)!,
        file: grant.file,
      });
      if (r.ok) states.set(d.id, r.state);
    }
  };
  const rotate = async (id: string) => {
    const d = w.devs.find((x) => x.id === id)!;
    const r = await rotateGroup({
      appId: APP,
      own: w.own(d),
      trust: await trust(id),
      state: states.get(id)!,
      random: rnd,
    });
    if (!r.ok) return false;
    states.set(id, r.state);
    pending.push(...r.grants.map((grant) => ({ grant })));
    return true;
  };

  // start: the admin makes epoch 1, everybody receives it
  await rotate(w.admin.id);
  await deliverSome(1, false);

  for (let round = 0; round < 8; round += 1) {
    if (removed.size < 2 && next() < 0.3) {
      const victim = pick(w.devs.filter((d) => d !== w.admin && !removed.has(d.id)));
      await w.remove(victim);
      removed.add(victim.id);
      seen.set(w.admin.id, w.versions.length - 1);
    }
    for (const d of w.devs) {
      if (next() < 0.5)
        seen.set(d.id, Math.max(seen.get(d.id)!, Math.floor(next() * w.versions.length)));
    }
    const rotators = new Set<string>();
    const holders = w.devs.filter((d) => preferredKey(states.get(d.id)!));
    for (let i = Math.floor(next() * 3); i > 0 && holders.length > 0; i -= 1)
      rotators.add(pick(holders).id);
    if (rotators.size > 1) concurrent += 1;
    for (const id of rotators) await rotate(id);
    await deliverSome(0.6, true);
    const writer = pick(holders);
    const state = states.get(writer.id)!;
    const plain = `m${round}-${writer.id.slice(-3)}`;
    const enc = await encryptGroup({ appId: APP, state, plaintext: text(plain), random: rnd });
    if (enc.ok)
      messages.push({ text: enc.text, by: writer.id, epoch: enc.epoch, kid: enc.kid, plain });
  }

  // quiescence: everybody sees everything, the group repairs itself
  for (const d of w.devs) seen.set(d.id, w.versions.length - 1);
  const active = async () => {
    const out = [];
    for (const d of w.devs) if (!(await trust(d.id)).removed.includes(d.id)) out.push(d);
    return out.filter((d) => !removed.has(d.id));
  };
  for (let iteration = 0; iteration < 8; iteration += 1) {
    await deliverSome(1, true);
    const members = await active();
    let acted = false;
    const preferred = members.map((d) => ({ d, k: preferredKey(states.get(d.id)!) }));
    const best = preferred
      .map((p) => p.k)
      .filter((k) => k !== undefined)
      .sort((a, b) => b.epoch - a.epoch || (a.author < b.author ? -1 : 1))[0];
    for (const { d, k } of preferred) {
      const t = await trust(d.id);
      if (
        k &&
        needsRotation(states.get(d.id)!, t).removedHolders.length > 0 &&
        isRotationLead(states.get(d.id)!, t, d.id)
      ) {
        acted = (await rotate(d.id)) || acted;
      }
    }
    if (best) {
      const holder = members.find((m) => findGroupKey(states.get(m.id)!, best.epoch, best.kid));
      for (const { d, k } of preferred) {
        if (k?.kid === best.kid || !holder) continue;
        const r = await issueGrants({
          appId: APP,
          own: w.own(holder),
          trust: await trust(holder.id),
          state: states.get(holder.id)!,
          to: [d.id],
          which: 'current',
          random: rnd,
        });
        if (r.ok) {
          states.set(holder.id, r.state);
          pending.push(...r.grants.map((grant) => ({ grant })));
          acted = true;
        }
      }
    }
    if (!acted && pending.length === 0) break;
  }
  await deliverSome(1, false);

  // the properties
  const members = await active();
  const finalTrust = await trust(w.admin.id);
  const kids = new Set(members.map((d) => preferredKey(states.get(d.id)!)?.kid));
  expect(kids.size, `seed ${seed}: one key chosen`).toBe(1);
  const best = preferredKey(states.get(members[0]!.id)!)!;
  for (const d of members) {
    const need = needsRotation(states.get(d.id)!, await trust(d.id));
    expect(need.removedHolders, `seed ${seed}: nobody removed holds the key`).toEqual([]);
    expect(need.missing, `seed ${seed}`).toEqual([]);
  }
  expect(finalTrust.removed.length).toBe(removed.size);
  const after = await encryptGroup({
    appId: APP,
    state: states.get(members[0]!.id)!,
    plaintext: text('final'),
    random: rnd,
  });
  if (!after.ok) throw new Error();
  for (const d of w.devs) {
    const dec = await decryptGroup({ appId: APP, state: states.get(d.id)!, text: after.text });
    expect(dec.ok, `seed ${seed}: ${d.name}`).toBe(!removed.has(d.id));
  }
  // every message opens for every device that holds its key, and for its author
  for (const m of messages) {
    for (const d of w.devs) {
      const dec = await decryptGroup({ appId: APP, state: states.get(d.id)!, text: m.text });
      if (dec.ok) expect(Buffer.from(dec.plaintext).toString()).toBe(m.plain);
      else if (d.id === m.by) throw new Error(`author cannot read own message (seed ${seed})`);
      else expect(dec.reason).toBe('unknown-key');
    }
  }
  return { epochs: best.epoch, concurrent };
}

describe('seeded simulations with the real trust layer', () => {
  it('40 runs converge, exclude removed devices and keep every held message readable', async () => {
    let concurrentRuns = 0;
    let maxEpoch = 0;
    for (let seed = 1; seed <= 40; seed += 1) {
      const r = await run(seed);
      if (r.concurrent > 0) concurrentRuns += 1;
      maxEpoch = Math.max(maxEpoch, r.epochs);
    }
    expect(concurrentRuns).toBeGreaterThan(10);
    expect(maxEpoch).toBeGreaterThan(3);
  }, 120_000);
});
