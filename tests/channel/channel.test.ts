// The channel glue: changes of one data set sealed into envelopes for named readers and opened again
// by a device that checks author, role and rights. The earlier app's channel cases, re-expressed:
// readers by role, an archive identity as the writer, the next file carries only what is new, an
// author nobody vouched for waits, another channel and a wrong role are refused, many entries cut
// into several envelopes, no reader is said, one bad envelope does not cost the others.
import { describe, expect, it } from 'vitest';
import {
  exportDeviceKeys,
  generateExportableDeviceKeys,
  importDeviceKeys,
  publicKeys,
  type DeviceKeys,
  type Envelope,
} from '../../src/core/index.ts';
import {
  channelKeys,
  openChannel,
  readChannelBody,
  sealChannel,
  writeChannelBody,
  type OpenChannelParams,
} from '../../src/channel/index.ts';
import {
  emptyReplica,
  insertSignatures,
  merge,
  signOwnChanges,
  write,
  type Replica,
} from '../../src/log/index.ts';
import {
  EMPTY_MAILBOX,
  addEnvelopes,
  receiptsOf,
  writeReceiptRecord,
  applyReceipts,
} from '../../src/post/index.ts';
import { computeTrust, addDevice, newDeviceId, type Trust } from '../../src/trust/index.ts';
import { prng } from '../log/helpers.ts';
import { APP, TRUST, world, type Member } from '../sync/helpers.ts';

const CH = 'times:c';
const DAY = '2027-01-15';
const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

interface Setup {
  readonly a: Member;
  readonly b: Member;
  readonly c: Member;
  /** The archive identity: its own id and keys, entered by A as a device. */
  readonly archive: { id: string; keys: DeviceKeys; dh: string; sig: string };
  /** C's view: the replica with the archive in the device list and its derived trust. */
  readonly trust: Trust;
}

async function setup(enterArchive = true): Promise<Setup> {
  const w = await world(['A', 'B', 'C']);
  const [a, b, c] = w.members as [Member, Member, Member];
  const keys = await generateExportableDeviceKeys();
  const id = newDeviceId(rand(16));
  const pub = await publicKeys(keys);
  const archive = { id, keys, dh: pub.dh, sig: pub.sig };
  if (enterArchive) {
    const added = addDevice(a.replica, TRUST, { device: id, name: 'Archive', ...pub }, 'member', {
      time: 1,
    });
    if (!added.ok) throw new Error(added.reason);
    a.replica = insertSignatures(
      added.replica,
      await signOwnChanges(APP, a.keys.signing.privateKey, added.replica, TRUST.dataSet),
    );
    c.replica = merge(c.replica, a.replica.log).replica;
  }
  const direct = typeof c.config.direct === 'function' ? c.config.direct() : c.config.direct;
  const trust = await computeTrust(c.replica, direct, TRUST);
  return { a, b, c, archive, trust };
}

const times = (author: string, n: number, text = 'x'): Replica => {
  let r = emptyReplica(author);
  for (let i = 0; i < n; i += 1) {
    const out = write(r, 'times', `t${i}`, { text: `${text}${i}`, from: '08:00' }, { time: 1 });
    if (!out.ok) throw new Error(out.reason);
    r = out.replica;
  }
  return r;
};

const seal = (
  s: Setup,
  replica: Replica,
  readers: readonly string[],
  extra: { known?: Record<string, number>; day?: string } = {},
) =>
  sealChannel({
    appId: APP,
    author: { device: s.archive.id, signing: s.archive.keys.signing.privateKey },
    channel: CH,
    replica,
    readers,
    day: extra.day ?? DAY,
    random: rand,
    ...(extra.known ? { known: extra.known } : {}),
  });

const openParams = (
  s: Setup,
  envelopes: readonly (Envelope | string)[],
  extra: Partial<OpenChannelParams> = {},
): OpenChannelParams => {
  const keys = channelKeys(s.trust, { device: s.c.id, publicKey: s.c.keys.signing.publicKey });
  return {
    appId: APP,
    own: { device: s.c.id, agreements: [s.c.keys.agreement] },
    envelopes,
    authorKey: keys.authorKey,
    keys: keys.keys,
    mayWrite: (device, channel) => device === s.archive.id && channel === CH,
    ...extra,
  };
};

describe('sealing a channel', () => {
  it('seals what the readers lack; the reader opens it, a carrier does not, a changed copy has no id', async () => {
    const s = await setup();
    const sealed = await seal(s, times(s.archive.id, 3), [s.c.intro.dh]);
    if (!sealed.ok) throw new Error(sealed.reason);
    expect(sealed.envelopes.length).toBe(1);
    expect(sealed.changes).toBe(3);
    const opened = await openChannel(openParams(s, sealed.envelopes));
    expect(opened.rejected).toEqual([]);
    expect(opened.taken.map((t) => [t.channel, t.from, t.applied, t.day])).toEqual([
      [CH, s.archive.id, 3, DAY],
    ]);
    expect(opened.replicas[CH]?.collections.times?.t1?.fields.text?.value).toBe('x1');
    // a carrier (B is no reader) cannot open it
    const asB = await openChannel({
      ...openParams(s, sealed.envelopes),
      own: { device: s.b.id, agreements: [s.b.keys.agreement] },
    });
    expect(asB.skipped).toBe(1);
    expect(asB.taken).toEqual([]);
    // a changed copy is not an envelope any more
    const text = (sealed.envelopes[0] as Envelope).text;
    const changed =
      text.slice(0, text.length - 12) +
      (text[text.length - 12] === 'A' ? 'B' : 'A') +
      text.slice(-11);
    const bad = await openChannel(openParams(s, [changed]));
    expect(bad.taken).toEqual([]);
    expect(bad.rejected.length + bad.skipped).toBe(1);
  });

  it('readers by role: only the devices the app names can open it', async () => {
    const s = await setup();
    const readers = s.trust.trusted.filter((d) => d.role === 'admin').map((d) => d.dh);
    expect(readers.length).toBe(1);
    const sealed = await seal(s, times(s.archive.id, 1), readers);
    if (!sealed.ok) throw new Error(sealed.reason);
    // C (a member) is not among them
    const asC = await openChannel(openParams(s, sealed.envelopes));
    expect(asC.skipped).toBe(1);
    expect(asC.taken).toEqual([]);
    const asA = await openChannel({
      ...openParams(s, sealed.envelopes),
      own: { device: s.a.id, agreements: [s.a.keys.agreement] },
      mayWrite: () => true,
    });
    expect(asA.taken.length).toBe(1);
  });

  it('the next file carries only what is new', async () => {
    const s = await setup();
    const first = await seal(s, times(s.archive.id, 2), [s.c.intro.dh]);
    if (!first.ok) throw new Error(first.reason);
    const opened = await openChannel(openParams(s, first.envelopes));
    const stand = opened.taken[0]?.stand ?? {};
    // nothing new: nothing sealed
    const again = await seal(s, first.replica, [s.c.intro.dh], { known: first.replica.vector });
    expect(again).toMatchObject({ ok: true, envelopes: [], changes: 0 });
    // one more entry: one envelope with one change
    const more = write(first.replica, 'times', 't9', { text: 'new' }, { time: 2 });
    if (!more.ok) throw new Error(more.reason);
    const second = await seal(s, more.replica, [s.c.intro.dh], { known: stand });
    if (!second.ok) throw new Error(second.reason);
    expect(second.changes).toBe(1);
    const next = await openChannel(openParams(s, second.envelopes, { replicas: opened.replicas }));
    expect(next.applied).toBe(1);
    expect(Object.keys(next.replicas[CH]?.collections.times ?? {})).toEqual(['t0', 't1', 't9']);
  });

  it('many entries go into several envelopes, each under the limit, and all arrive', async () => {
    const s = await setup();
    const sealed = await seal(s, times(s.archive.id, 120, 'a longer text of an entry '), [
      s.c.intro.dh,
    ]);
    if (!sealed.ok) throw new Error(sealed.reason);
    expect(sealed.envelopes.length).toBeGreaterThan(3);
    for (const e of sealed.envelopes) expect(e.text.length).toBeLessThanOrEqual(11_000);
    const opened = await openChannel(openParams(s, sealed.envelopes));
    expect(opened.rejected).toEqual([]);
    expect(opened.taken.length).toBe(sealed.envelopes.length);
    expect(opened.applied).toBe(120);
    // in any order too (the later ones hold until the earlier ones are in: they wait, then count)
    const reversed = await openChannel(openParams(s, [...sealed.envelopes].reverse()));
    expect(reversed.applied + 0).toBeGreaterThan(0);
    const again = await openChannel(
      openParams(s, sealed.envelopes, {
        replicas: reversed.replicas,
        already: new Set(reversed.taken.map((t) => t.id)),
      }),
    );
    expect(again.applied + reversed.applied).toBe(120);
  });

  it('something to send but nobody who may read it: no-reader, said and not silent', async () => {
    const s = await setup();
    const none = await seal(s, times(s.archive.id, 2), []);
    expect(none).toMatchObject({ ok: false, reason: 'no-reader' });
    // nothing to send and nobody to read it is not a problem
    expect(await seal(s, emptyReplica(s.archive.id), [])).toMatchObject({
      ok: true,
      envelopes: [],
    });
    // the signed replica comes back even on a refusal
    expect(none.replica.log.every((c) => c.sig !== undefined)).toBe(true);
  });

  it('refusals are codes: too many readers, a reader that is no key, a replica of another device', async () => {
    const s = await setup();
    const r = times(s.archive.id, 1);
    expect(
      await seal(
        s,
        r,
        Array.from({ length: 65 }, (_, i) => `${i}`),
      ),
    ).toMatchObject({ ok: false, reason: 'too-many-readers' });
    expect(await seal(s, r, ['nope'])).toMatchObject({ ok: false, reason: 'bad-reader' });
    expect(await seal(s, times('someone-else', 1), [s.c.intro.dh])).toMatchObject({
      ok: false,
      reason: 'wrong-device',
    });
    expect(await seal(s, r, [s.c.intro.dh], { day: 'yesterday' })).toMatchObject({
      ok: false,
      reason: 'bad-day',
    });
    // one change that is larger than an envelope (of a small limit) can ever be
    const huge = write(emptyReplica(s.archive.id), 'times', 'h', { text: 'x'.repeat(2000) });
    if (!huge.ok) throw new Error(huge.reason);
    const tiny = await sealChannel({
      appId: APP,
      author: { device: s.archive.id, signing: s.archive.keys.signing.privateKey },
      channel: CH,
      replica: huge.replica,
      readers: [s.c.intro.dh],
      day: DAY,
      random: rand,
      limits: { maxEnvelopeBytes: 2800 },
    });
    expect(tiny).toMatchObject({ ok: false, reason: 'change-too-large' });
  });
});

describe('opening a channel', () => {
  it('an author nobody vouched for waits; once the device list has it, the envelope is taken', async () => {
    const s = await setup(false);
    const sealed = await seal(s, times(s.archive.id, 2), [s.c.intro.dh]);
    if (!sealed.ok) throw new Error(sealed.reason);
    const first = await openChannel(openParams(s, sealed.envelopes));
    expect(first.taken).toEqual([]);
    expect(first.waiting.map((w) => w.code)).toEqual(['unknown-author']);
    // the archive is entered as a device; the same envelope now opens
    const later = await setup(true);
    void later;
    const added = addDevice(
      s.a.replica,
      TRUST,
      { device: s.archive.id, name: 'Archive', sig: s.archive.sig, dh: s.archive.dh },
      'member',
      { time: 1 },
    );
    if (!added.ok) throw new Error(added.reason);
    const a2 = insertSignatures(
      added.replica,
      await signOwnChanges(APP, s.a.keys.signing.privateKey, added.replica, TRUST.dataSet),
    );
    const c2 = merge(s.c.replica, a2.log).replica;
    const direct =
      typeof s.c.config.direct === 'function' ? s.c.config.direct() : s.c.config.direct;
    const trust = await computeTrust(c2, direct, TRUST);
    const second = await openChannel(openParams({ ...s, trust }, sealed.envelopes));
    expect(second.taken.length).toBe(1);
    expect(second.waiting).toEqual([]);
  });

  it('a device whose role may not write the channel is refused; another channel is not taken at all', async () => {
    const s = await setup();
    const sealed = await seal(s, times(s.archive.id, 1), [s.c.intro.dh]);
    if (!sealed.ok) throw new Error(sealed.reason);
    const refused = await openChannel(openParams(s, sealed.envelopes, { mayWrite: () => false }));
    expect(refused.rejected.map((r) => r.code)).toEqual(['author-not-allowed']);
    expect(refused.taken).toEqual([]);
    const throwing = await openChannel(
      openParams(s, sealed.envelopes, {
        mayWrite: () => {
          throw new Error('boom');
        },
      }),
    );
    expect(throwing.rejected.map((r) => r.code)).toEqual(['author-not-allowed']);
    const other = await openChannel(
      openParams(s, sealed.envelopes, { channels: new Set(['times:other']) }),
    );
    expect(other.skipped).toBe(1);
    expect(other.taken).toEqual([]);
    const fn = await openChannel(
      openParams(s, sealed.envelopes, { channels: (c) => c.startsWith('times:') }),
    );
    expect(fn.taken.length).toBe(1);
  });

  it('an envelope already taken is skipped without opening', async () => {
    const s = await setup();
    const sealed = await seal(s, times(s.archive.id, 1), [s.c.intro.dh]);
    if (!sealed.ok) throw new Error(sealed.reason);
    const id = (sealed.envelopes[0] as Envelope).id;
    const out = await openChannel(openParams(s, sealed.envelopes, { already: new Set([id]) }));
    expect(out.skipped).toBe(1);
    expect(out.taken).toEqual([]);
  });

  it('one bad envelope is dropped and the others still count', async () => {
    const s = await setup();
    const good = await seal(s, times(s.archive.id, 2), [s.c.intro.dh]);
    if (!good.ok) throw new Error(good.reason);
    // a change signed by a key the device list does not have for the author: forged signature
    const forgedKeys = await generateExportableDeviceKeys();
    const forgedReplica = times(s.archive.id, 2, 'forged');
    const forged = insertSignatures(
      forgedReplica,
      await signOwnChanges(APP, forgedKeys.signing.privateKey, forgedReplica, CH),
    );
    // sealed by the real archive key (the envelope is genuine), the inner changes are not
    const body = writeChannelBody(forged.vector, forged.log);
    const { sealEnvelope } = await import('../../src/core/index.ts');
    const inside = await sealEnvelope({
      appId: APP,
      author: { device: s.archive.id, signing: s.archive.keys.signing.privateKey },
      recipients: [s.c.intro.dh],
      channel: CH,
      day: DAY,
      body,
      random: rand,
    });
    if (!inside.ok) throw new Error(inside.reason);
    // junk body in a genuine envelope
    const junk = await sealEnvelope({
      appId: APP,
      author: { device: s.archive.id, signing: s.archive.keys.signing.privateKey },
      recipients: [s.c.intro.dh],
      channel: CH,
      day: DAY,
      body: new TextEncoder().encode('{"v":1,"stand":{},"changes":"x"}'),
      random: rand,
    });
    if (!junk.ok) throw new Error(junk.reason);
    // an envelope from a device that is in the list but writes as the wrong channel role: B
    const fromB = await sealEnvelope({
      appId: APP,
      author: { device: s.b.id, signing: s.b.keys.signing.privateKey },
      recipients: [s.c.intro.dh],
      channel: CH,
      day: DAY,
      body: writeChannelBody({}, []),
      random: rand,
    });
    if (!fromB.ok) throw new Error(fromB.reason);
    const out = await openChannel(
      openParams(s, [inside.envelope, junk.envelope, fromB.envelope, ...good.envelopes]),
    );
    expect(out.taken.length).toBe(1);
    expect(out.replicas[CH]?.collections.times?.t0?.fields.text?.value).toBe('x0');
    const codes = Object.fromEntries(out.rejected.map((r) => [r.id, r.code]));
    expect(codes[inside.envelope.id]).toBe('bad-change');
    expect(codes[junk.envelope.id]).toBe('bad-body');
    expect(codes[fromB.envelope.id]).toBe('author-not-allowed');
    expect(out.rejected.find((r) => r.code === 'bad-change')?.detail).toMatch(
      /bad-signature|unsigned/,
    );
    // nothing of the forged content leaked in
    expect(JSON.stringify(out.replicas)).not.toContain('forged');
  });

  it('a change of an author the role rule does not allow refuses its envelope even from an allowed carrier', async () => {
    const s = await setup();
    // B's own signed change inside an envelope the archive sealed
    let br = emptyReplica(s.b.id);
    const w = write(br, 'times', 'tb', { text: 'from b' }, { time: 1 });
    if (!w.ok) throw new Error(w.reason);
    br = insertSignatures(
      w.replica,
      await signOwnChanges(APP, s.b.keys.signing.privateKey, w.replica, CH),
    );
    const { sealEnvelope } = await import('../../src/core/index.ts');
    const env = await sealEnvelope({
      appId: APP,
      author: { device: s.archive.id, signing: s.archive.keys.signing.privateKey },
      recipients: [s.c.intro.dh],
      channel: CH,
      day: DAY,
      body: writeChannelBody(br.vector, br.log),
      random: rand,
    });
    if (!env.ok) throw new Error(env.reason);
    const out = await openChannel(openParams(s, [env.envelope]));
    expect(out.taken).toEqual([]);
    expect(out.rejected[0]).toMatchObject({ code: 'bad-change', detail: 'not-allowed' });
    // with a rule that allows B, the same envelope is taken
    const allowed = await openChannel(openParams(s, [env.envelope], { mayWrite: () => true }));
    expect(allowed.taken.length).toBe(1);
  });

  it('the rights hooks of the log apply per channel (final deletion is refused by default)', async () => {
    const s = await setup();
    let r = times(s.archive.id, 1);
    const sealedFirst = await seal(s, r, [s.c.intro.dh]);
    if (!sealedFirst.ok) throw new Error(sealedFirst.reason);
    const { remove } = await import('../../src/log/index.ts');
    const gone = remove(sealedFirst.replica, 'times', 't0');
    if (!gone.ok) throw new Error(gone.reason);
    r = gone.replica;
    const sealed = await seal(s, r, [s.c.intro.dh]);
    if (!sealed.ok) throw new Error(sealed.reason);
    const out = await openChannel(openParams(s, sealed.envelopes));
    // an erased change cannot be taken without its deletion, and the deletion is refused: nothing is taken
    expect(out.taken).toEqual([]);
    const allowed = await openChannel(
      openParams(s, sealed.envelopes, { judge: () => ({ allowFinalDelete: () => true }) }),
    );
    expect(allowed.rejected).toEqual([]);
  });

  it('the archive identity: exported, kept in an encrypted store, imported; envelopes wait while it is closed', async () => {
    const s = await setup();
    // the office device (A) is a reader of the channel besides C; the archive is the writer
    const exported = await exportDeviceKeys(s.archive.keys);
    if (!exported.ok) throw new Error(exported.reason);
    const reopened = await importDeviceKeys(exported.text, {
      expect: { sig: s.archive.sig, dh: s.archive.dh },
    });
    if (!reopened.ok) throw new Error(reopened.reason);
    const sealed = await sealChannel({
      appId: APP,
      author: { device: s.archive.id, signing: reopened.keys.signing.privateKey },
      channel: CH,
      replica: times(s.archive.id, 2),
      readers: [s.archive.dh, s.c.intro.dh],
      day: DAY,
      random: rand,
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    // the office device holds the envelope while the archive is closed: it is not for its own keys
    const closed = await openChannel({
      ...openParams(s, sealed.envelopes),
      own: { device: s.a.id, agreements: [s.a.keys.agreement] },
    });
    expect(closed.skipped).toBe(1);
    // the archive opens: its key first, then the device's own
    const open = await openChannel({
      ...openParams(s, sealed.envelopes),
      own: { device: s.a.id, agreements: [reopened.keys.agreement, s.a.keys.agreement] },
      mayWrite: () => true,
    });
    expect(open.taken.length).toBe(1);
  });

  it('the channel the other way: a device of the person writes, the office reads and receipts, the carrier drops', async () => {
    const s = await setup();
    // C writes its own times for the office (A) through the channel; B carries
    let cr = emptyReplica(s.c.id);
    const w = write(cr, 'times', 'recorded', { text: 'in the app' }, { time: 1 });
    if (!w.ok) throw new Error(w.reason);
    const sealed = await sealChannel({
      appId: APP,
      author: { device: s.c.id, signing: s.c.keys.signing.privateKey },
      channel: CH,
      replica: w.replica,
      readers: [s.a.intro.dh],
      day: DAY,
      random: rand,
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    cr = sealed.replica;
    const carried = addEnvelopes(APP, EMPTY_MAILBOX, sealed.envelopes, DAY, { from: s.c.id });
    if (!carried.ok) throw new Error(carried.reason);
    // A: author C is a trusted device of the person
    const directA =
      typeof s.a.config.direct === 'function' ? s.a.config.direct() : s.a.config.direct;
    const trustA = await computeTrust(s.a.replica, directA, TRUST);
    const keys = channelKeys(trustA, { device: s.a.id, publicKey: s.a.keys.signing.publicKey });
    const opened = await openChannel({
      appId: APP,
      own: { device: s.a.id, agreements: [s.a.keys.agreement] },
      envelopes: carried.mailbox.items,
      authorKey: keys.authorKey,
      keys: keys.keys,
      mayWrite: (device) => device === s.c.id,
    });
    expect(opened.taken.length).toBe(1);
    // A writes the receipt; the carrier that sees it drops the envelope
    const receipt = writeReceiptRecord(emptyReplica(s.a.id), opened.taken, DAY);
    if (!receipt.ok) throw new Error(receipt.reason);
    const dropped = applyReceipts(
      APP,
      carried.mailbox,
      receiptsOf(receipt.replica),
      (by) => by === s.a.id,
      DAY,
    );
    expect(dropped).toMatchObject({ ok: true, dropped: 1 });
  });
});

describe('the envelope body', () => {
  const stand = { a: 2 };
  it('is read strictly and refuses every other spelling', () => {
    const bytes = writeChannelBody(stand, []);
    expect(readChannelBody(bytes)).toEqual({ stand, changes: [] });
    const text = new TextDecoder().decode(bytes);
    const enc = (t: string): Uint8Array => new TextEncoder().encode(t);
    for (const bad of [
      text.replace('"v":1', '"v":2'),
      text.replace('"changes":[]', '"changes":[],"x":1'),
      text.replace('"stand":{"a":2},', ''),
      text.replace('"stand":{"a":2}', '"stand":{"a":-1}'),
      text.replace('"changes":[]', '"changes":[{}]'),
      '{"v":1,"v":1,"stand":{},"changes":[]}',
      '',
      '[]',
    ]) {
      expect(readChannelBody(enc(bad)), bad).toBeUndefined();
    }
    expect(readChannelBody('text')).toBeUndefined();
    expect(readChannelBody(new Uint8Array(0))).toBeUndefined();
  });

  it('never throws on 3000 seeded damages', async () => {
    const s = await setup();
    const r0 = times(s.archive.id, 2);
    const signed = insertSignatures(
      r0,
      await signOwnChanges(APP, s.archive.keys.signing.privateKey, r0, CH),
    );
    const bytes = writeChannelBody(signed.vector, signed.log);
    expect(readChannelBody(bytes)?.changes.length).toBe(2);
    const r = prng(31);
    for (let i = 0; i < 3000; i += 1) {
      const copy = Uint8Array.from(bytes);
      for (let k = 0; k < 1 + Math.floor(r() * 3); k += 1)
        copy[Math.floor(r() * copy.length)] = Math.floor(r() * 256);
      const cut = r() < 0.3 ? copy.subarray(0, Math.floor(r() * copy.length)) : copy;
      expect(() => readChannelBody(cut)).not.toThrow();
    }
  });
});
