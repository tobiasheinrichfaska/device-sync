import { beforeAll, describe, expect, it } from 'vitest';
import { base64url, fromBase64url } from '../../src/core/index.ts';
import {
  INVITATION_MS,
  checkReply,
  createInvitation,
  invitationLink,
  invitationProof,
  parseInvitation,
  parseOpenInvitation,
  parseReply,
  proofText,
  replyText,
  vouchRoles,
  type DeviceEntry,
  type Invitation,
  type OpenInvitation,
  type Reply,
} from '../../src/trust/index.ts';
import { APP, dev, type Dev } from './helpers.ts';

const NOW = 1_800_000_000_000;
const PAGE = 'https://example.org/app/index.html';
const RANDOM = new Uint8Array(16).fill(7);
const VOUCHER = vouchRoles(['admin']);
const P = { appId: APP };
const PV = { appId: APP, voucher: VOUCHER };
const entryOf = (d: Dev, role: string): DeviceEntry => ({
  ...d.intro,
  role,
  removed: false,
  private: false,
});
const decodeLink = (link: string) =>
  JSON.parse(new TextDecoder().decode(fromBase64url(link.split('#join=')[1] as string)));
const linkOf = (o: unknown, page = PAGE) =>
  `${page}#join=${base64url(new TextEncoder().encode(JSON.stringify(o)))}`;

let a: Dev;
let n: Dev;
let invitation: Invitation;
let open: OpenInvitation;
let link: string;
let reply: Reply;
beforeAll(async () => {
  a = await dev('Admin A');
  n = await dev('New N');
  const made = createInvitation(PV, entryOf(a, 'admin'), 'member', RANDOM, NOW);
  if (!made.ok) throw new Error(made.reason);
  invitation = made.invitation;
  open = made.open;
  link = invitationLink(APP, `${PAGE}#old`, invitation);
  reply = {
    to: a.id,
    introduction: n.intro,
    proof: await invitationProof(APP, invitation, n.intro),
  };
});

describe('creating an invitation', () => {
  it('lives 24 hours, carries inviter, role, one-time code; the inviter keeps its own record', () => {
    expect(INVITATION_MS).toBe(86_400_000);
    expect(invitation).toEqual({
      from: a.intro,
      role: 'member',
      code: base64url(RANDOM),
      until: NOW + INVITATION_MS,
    });
    expect(open).toEqual({ role: 'member', code: base64url(RANDOM), until: NOW + INVITATION_MS });
    expect(link.startsWith(`${PAGE}#join=`)).toBe(true);
  });

  it('only an inviter the voucher allows may invite that role', () => {
    const member = createInvitation(PV, entryOf(a, 'member'), 'member', RANDOM, NOW);
    expect(member).toEqual({ ok: false, reason: 'not-allowed' });
    expect(
      createInvitation(
        PV,
        { ...entryOf(a, 'admin'), role: undefined } as never,
        'member',
        RANDOM,
        NOW,
      ).ok,
    ).toBe(false);
    const picky = {
      appId: APP,
      voucher: {
        canVouch: () => true,
        mayInvite: (_i: DeviceEntry, role: string) => role === 'guest',
      },
    };
    expect(createInvitation(picky, entryOf(a, 'admin'), 'member', RANDOM, NOW)).toEqual({
      ok: false,
      reason: 'not-allowed',
    });
    expect(createInvitation(picky, entryOf(a, 'admin'), 'guest', RANDOM, NOW).ok).toBe(true);
    // without mayInvite only a device that can vouch invites
    const plain = { appId: APP, voucher: { canVouch: (d: DeviceEntry) => d.role === 'admin' } };
    expect(createInvitation(plain, entryOf(a, 'member'), 'member', RANDOM, NOW).ok).toBe(false);
    expect(createInvitation(plain, entryOf(a, 'admin'), 'member', RANDOM, NOW).ok).toBe(true);
  });

  it('refuses bad random, role, name and a private device with a role that may not be private', () => {
    const inviter = entryOf(a, 'admin');
    for (const bad of [new Uint8Array(8), new Uint8Array(17), [1] as never]) {
      expect(createInvitation(PV, inviter, 'member', bad, NOW)).toEqual({
        ok: false,
        reason: 'bad-random',
      });
    }
    expect(createInvitation(PV, inviter, 'Bad Role', RANDOM, NOW)).toEqual({
      ok: false,
      reason: 'bad-role',
    });
    expect(createInvitation(PV, inviter, 'member', RANDOM, NOW, { newName: 'a|b' })).toEqual({
      ok: false,
      reason: 'bad-name',
    });
    const strict = { ...PV, valid: { privateRoles: (r: string) => r !== 'admin' } };
    expect(createInvitation(strict, inviter, 'admin', RANDOM, NOW, { private: true })).toEqual({
      ok: false,
      reason: 'private-role',
    });
    expect(createInvitation(strict, inviter, 'member', RANDOM, NOW, { private: true }).ok).toBe(
      true,
    );
    expect(createInvitation(strict, inviter, 'admin', RANDOM, NOW, { private: false }).ok).toBe(
      true,
    );
    expect(createInvitation(PV, { ...inviter, device: 'nope' }, 'member', RANDOM, NOW)).toEqual({
      ok: false,
      reason: 'bad-inviter',
    });
  });

  it('carries the optional name, relay id of the inviter and the private flag; without them no member', () => {
    const inviter = { ...entryOf(a, 'admin'), relayId: 'relay-a' };
    const made = createInvitation(PV, inviter, 'guest', RANDOM, NOW, {
      newName: 'Tablet',
      private: true,
    });
    if (!made.ok) throw new Error('refused');
    expect(made.invitation).toMatchObject({ newName: 'Tablet', relayId: 'relay-a', private: true });
    expect(made.open).toEqual({
      role: 'guest',
      code: base64url(RANDOM),
      until: NOW + INVITATION_MS,
      private: true,
    });
    const read = parseInvitation(P, invitationLink(APP, PAGE, made.invitation));
    expect(read).toEqual(made.invitation);
    expect('private' in invitation).toBe(false);
    const payload = decodeLink(link);
    expect(Object.keys(payload)).toEqual([
      'm',
      'device',
      'name',
      'sig',
      'dh',
      'role',
      'code',
      'until',
    ]);
  });
});

describe('reading the invitation', () => {
  it('round trip from a link, a padded text and the part from #', () => {
    expect(parseInvitation(P, link)).toEqual(invitation);
    expect(parseInvitation(P, `  ${link}  `)).toEqual(invitation);
    expect(parseInvitation(P, link.slice(link.indexOf('#')))).toEqual(invitation);
  });

  it('another app, another kind, no fragment, junk: nothing', () => {
    expect(parseInvitation({ appId: 'otherapp' }, link)).toBeUndefined();
    expect(parseInvitation(P, PAGE)).toBeUndefined();
    expect(parseInvitation(P, `${link}x!`)).toBeUndefined();
    expect(parseInvitation(P, `${PAGE}#join=${'A'.repeat(2001)}`)).toBeUndefined();
    expect(parseInvitation(P, `${PAGE}#join=`)).toBeUndefined();
    expect(parseInvitation(P, `${PAGE}#join=xyz`)).toBeUndefined();
    expect(parseInvitation(P, 5 as never)).toBeUndefined();
    const o = decodeLink(link);
    expect(parseInvitation(P, linkOf({ ...o, m: 'syncdemo-meeting:2' }))).toBeUndefined();
    expect(parseInvitation(P, linkOf({ ...o, m: 'syncdemo-invite:1' }))).toBeUndefined();
  });

  it('values must be exactly right', () => {
    const o = decodeLink(link);
    const bad: Record<string, unknown[]> = {
      device: ['device-zz', 7],
      name: ['', 'a|b'],
      sig: [o.dh, 'short'],
      role: ['Admin', 'a b', 5],
      code: ['short', 'A'.repeat(22), 5, o.code + 'A'], // 22 x A is not the canonical spelling of 16 bytes? checked below
      until: ['1', -1, 1.5, null],
      newName: ['', 'a|b', 5],
      relayId: ['', 'a\u0007', 5],
      private: [false, 2, '1'],
    };
    for (const [member, values] of Object.entries(bad)) {
      for (const v of values) {
        if (member === 'code' && v === 'A'.repeat(22)) continue; // canonical (all-zero bytes), valid by shape
        expect(
          parseInvitation(P, linkOf({ ...o, [member]: v })),
          `${member}=${String(v)}`,
        ).toBeUndefined();
      }
    }
    // a non-canonical spelling of the same code bytes is refused (last character carries unused bits)
    const code = o.code as string;
    const sibling = code.slice(0, -1) + 'B'; // low bits of the last character are unused
    expect(base64url(fromBase64url(sibling))).not.toBe(sibling);
    expect(parseInvitation(P, linkOf({ ...o, code: sibling }))).toBeUndefined();
  });

  it('a private invitation for a role that may not be private is refused', () => {
    const o = decodeLink(link);
    const strict = { appId: APP, valid: { privateRoles: (r: string) => r !== 'admin' } };
    expect(parseInvitation(strict, linkOf({ ...o, role: 'admin', private: true }))).toBeUndefined();
    expect(parseInvitation(strict, linkOf({ ...o, role: 'member', private: true }))).toMatchObject({
      private: true,
    });
  });

  it('one spelling only: other member order, spaces, duplicates, a non-canonical payload', () => {
    const o = decodeLink(link);
    const { m, ...rest } = o;
    expect(parseInvitation(P, linkOf({ ...rest, m }))).toBeUndefined();
    expect(parseInvitation(P, linkOf(JSON.parse(JSON.stringify(o)), PAGE))).toEqual(invitation);
    const spaced = `${PAGE}#join=${base64url(new TextEncoder().encode(JSON.stringify(o, null, 1)))}`;
    expect(parseInvitation(P, spaced)).toBeUndefined();
  });

  it('the open record is read strictly and ends at `until`', () => {
    expect(parseOpenInvitation(P, open, NOW)).toEqual(open);
    expect(parseOpenInvitation(P, open, open.until - 1)).toEqual(open);
    expect(parseOpenInvitation(P, open, open.until)).toBeUndefined();
    expect(parseOpenInvitation(P, { ...open, private: true }, NOW)).toEqual({
      ...open,
      private: true,
    });
    for (const bad of [
      { ...open, private: 'yes' },
      { ...open, code: 'x' },
      { ...open, role: 'A b' },
      { ...open, until: '5' },
      { ...open, extra: 1 },
      null,
      5,
      [],
    ]) {
      expect(parseOpenInvitation(P, bad, NOW)).toBeUndefined();
    }
  });
});

describe('the answer and its proof', () => {
  it('the proof text is exactly this, the proof is an HMAC keyed by the code', async () => {
    expect(proofText('demo', 'device-a', 'member', n.intro)).toBe(
      `demo-invite:2|device-a|member|${n.id}|${n.intro.name}|${n.intro.sig}|${n.intro.dh}`,
    );
    const key = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(fromBase64url(invitation.code)),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const mac = await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(proofText(APP, a.id, 'member', n.intro)),
    );
    expect(reply.proof).toBe(base64url(new Uint8Array(mac)));
    expect(reply.proof).toHaveLength(43);
  });

  it('the holder of the code is taken', async () => {
    expect(await checkReply(PV, open, a.id, reply, NOW + 1)).toEqual({ ok: true });
    expect(await checkReply(PV, open, a.id, reply, NOW + 1, entryOf(a, 'admin'))).toEqual({
      ok: true,
    });
  });

  it('the reply text round trips; strict reading', () => {
    const text = replyText(APP, reply);
    expect(parseReply(P, text)).toEqual(reply);
    expect(parseReply(P, `  ${text}\n`)).toEqual(reply);
    expect(parseReply({ appId: 'otherapp' }, text)).toBeUndefined();
    for (const bad of ['', 'x!', text + 'x', text.slice(0, -2), 'A'.repeat(2001)]) {
      expect(parseReply(P, bad)).toBeUndefined();
    }
  });

  it('a withdrawn or foreign invitation, the device itself, expiry, a later inviter without the right', async () => {
    expect(await checkReply(PV, undefined, a.id, reply, NOW)).toEqual({
      ok: false,
      reason: 'no-invitation',
    });
    const other = await dev('Other admin');
    expect(await checkReply(PV, open, other.id, { ...reply, to: other.id }, NOW)).toEqual({
      ok: false,
      reason: 'bad-proof',
    });
    expect(await checkReply(PV, open, other.id, reply, NOW)).toEqual({
      ok: false,
      reason: 'wrong-inviter',
    });
    const self = {
      to: a.id,
      introduction: a.intro,
      proof: await invitationProof(APP, invitation, a.intro),
    };
    expect(await checkReply(PV, open, a.id, self, NOW)).toEqual({
      ok: false,
      reason: 'own-device',
    });
    expect(await checkReply(PV, open, a.id, reply, NOW, entryOf(a, 'member'))).toEqual({
      ok: false,
      reason: 'not-allowed',
    });
    expect(
      await checkReply(
        PV,
        open,
        a.id,
        { ...reply, introduction: { ...n.intro, sig: n.intro.dh } },
        NOW,
      ),
    ).toEqual({ ok: false, reason: 'bad-introduction' });
    expect(await checkReply(PV, open, a.id, { ...reply, proof: 'x'.repeat(10) }, NOW)).toEqual({
      ok: false,
      reason: 'bad-proof',
    });
  });

  describe('expiry boundary', () => {
    it.each([
      ['one ms before the end', INVITATION_MS - 1, true],
      ['at the end', INVITATION_MS, false],
      ['one ms after', INVITATION_MS + 1, false],
    ])('%s', async (_l, delta, good) => {
      const r = await checkReply(PV, open, a.id, reply, NOW + delta);
      expect(r.ok).toBe(good);
      if (!good) expect(r).toEqual({ ok: false, reason: 'expired' });
    });
  });

  describe('a proof is good for exactly one invitation, role, inviter and device', () => {
    it('reuse for another device, role, key, name, inviter or code', async () => {
      const m = await dev('Mallory');
      // the same proof with the introduction of another device
      expect((await checkReply(PV, open, a.id, { ...reply, introduction: m.intro }, NOW)).ok).toBe(
        false,
      );
      for (const swap of [
        { name: 'Renamed' },
        { sig: m.intro.sig },
        { dh: m.intro.dh },
        { device: m.id },
      ]) {
        const changed = { ...n.intro, ...swap };
        expect(
          (await checkReply(PV, open, a.id, { ...reply, introduction: changed }, NOW)).ok,
          JSON.stringify(Object.keys(swap)),
        ).toBe(false);
      }
      // the proof for role "member" under an open invitation for another role, or another inviter's invitation
      expect((await checkReply(PV, { ...open, role: 'admin' }, a.id, reply, NOW)).ok).toBe(false);
      expect(
        await checkReply(
          PV,
          open,
          a.id,
          {
            ...reply,
            proof: await invitationProof(APP, { ...invitation, role: 'admin' }, n.intro),
          },
          NOW,
        ),
      ).toEqual({ ok: false, reason: 'bad-proof' });
      expect(
        await checkReply(
          PV,
          open,
          a.id,
          {
            ...reply,
            proof: await invitationProof(APP, { ...invitation, from: m.intro }, n.intro),
          },
          NOW,
        ),
      ).toEqual({ ok: false, reason: 'bad-proof' });
      // a proof under a different code
      const otherCode = base64url(new Uint8Array(16).fill(9));
      expect(
        await checkReply(
          PV,
          open,
          a.id,
          {
            ...reply,
            proof: await invitationProof(APP, { ...invitation, code: otherCode }, n.intro),
          },
          NOW,
        ),
      ).toEqual({ ok: false, reason: 'bad-proof' });
      expect((await checkReply(PV, { ...open, code: otherCode }, a.id, reply, NOW)).ok).toBe(false);
    });

    it("two apps never accept each other's proofs or replies", async () => {
      const foreign = { appId: 'otherapp', voucher: VOUCHER };
      const theirProof = await invitationProof('otherapp', invitation, n.intro);
      expect(theirProof).not.toBe(reply.proof);
      expect((await checkReply(PV, open, a.id, { ...reply, proof: theirProof }, NOW)).ok).toBe(
        false,
      );
      expect((await checkReply(foreign, open, a.id, reply, NOW)).ok).toBe(false);
      expect(parseReply({ appId: 'otherapp' }, replyText(APP, reply))).toBeUndefined();
      expect(parseInvitation({ appId: 'otherapp' }, link)).toBeUndefined();
    });

    it('every character of the proof altered, one at a time', async () => {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      let taken = 0;
      for (let i = 0; i < reply.proof.length; i++) {
        const other = chars[(chars.indexOf(reply.proof[i] as string) + 1) % 64] as string;
        const proof = reply.proof.slice(0, i) + other + reply.proof.slice(i + 1);
        if ((await checkReply(PV, open, a.id, { ...reply, proof }, NOW)).ok) taken++;
      }
      expect(taken).toBe(0);
    });
  });
});

describe('tamper sweep over the texts', () => {
  const MEMBERS = ['m', 'device', 'name', 'sig', 'dh', 'role', 'code', 'until'];

  // what the inviter's check depends on: the invitation's inviter id, role and code (via the proof)
  async function flow(text: string): Promise<'unreadable' | 'refused' | 'taken'> {
    const read = parseInvitation(P, text);
    if (!read) return 'unreadable';
    const proof = await invitationProof(APP, read, n.intro);
    const r = await checkReply(
      PV,
      open,
      a.id,
      { to: read.from.device, introduction: n.intro, proof },
      NOW + 1,
    );
    return r.ok ? 'taken' : 'refused';
  }

  it('invitation: every member changed, deleted or added, one at a time', async () => {
    const o = decodeLink(link);
    const flip = (v: unknown) =>
      typeof v === 'number'
        ? v + 1
        : typeof v === 'string'
          ? v.slice(0, -1) + (v.at(-1) === 'A' ? 'B' : 'A')
          : v;
    // bound by the proof or by the inviter's own record: the exchange must fail
    const bound = ['m', 'device', 'role', 'code'];
    // only carried advice (the inviter's own record decides): the exchange is not affected
    const carried = ['name', 'sig', 'dh', 'until'];
    for (const f of MEMBERS) {
      const flipped = await flow(linkOf({ ...o, [f]: flip(o[f]) }));
      const { [f]: _g, ...rest } = o;
      const deleted = await flow(linkOf(rest));
      const added = await flow(linkOf({ ...o, [`${f}2`]: o[f] }));
      expect(added, `add ${f}`).toBe('unreadable');
      expect(deleted, `delete ${f}`).toBe('unreadable');
      if (bound.includes(f)) expect(flipped, `flip ${f}`).not.toBe('taken');
      if (carried.includes(f)) expect(['taken', 'unreadable'], `flip ${f}`).toContain(flipped);
    }
    expect(await flow(link)).toBe('taken');
    // optional members: added with a valid value they are carried, with an invalid one unreadable
    expect(await flow(linkOf({ ...o, private: false }))).toBe('unreadable');
    expect(await flow(linkOf({ ...o, newName: 'a|b' }))).toBe('unreadable');
  });

  it('invitation: a changed role or inviter id gives a refused exchange, not a taken one', async () => {
    const o = decodeLink(link);
    expect(await flow(linkOf({ ...o, role: 'admin' }))).toBe('refused');
    expect(await flow(linkOf({ ...o, device: n.id }))).toBe('refused');
    expect(await flow(linkOf({ ...o, code: base64url(new Uint8Array(16).fill(1)) }))).toBe(
      'refused',
    );
  });

  it('invitation: every character of the payload altered never reads as the same invitation', () => {
    const at = link.indexOf('#join=') + 6;
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let same = 0;
    for (let i = at; i < link.length; i++) {
      for (const ch of [
        chars[(chars.indexOf(link[i] as string) + 1) % 64] as string,
        chars[(chars.indexOf(link[i] as string) + 17) % 64] as string,
      ]) {
        const read = parseInvitation(P, link.slice(0, i) + ch + link.slice(i + 1));
        if (read && JSON.stringify(read) === JSON.stringify(invitation)) same++;
      }
    }
    expect(same).toBe(0);
  });

  it('reply: every member changed, deleted or added never gets taken', async () => {
    const o = JSON.parse(new TextDecoder().decode(fromBase64url(replyText(APP, reply))));
    const enc = (v: unknown) => base64url(new TextEncoder().encode(JSON.stringify(v)));
    const flip = (v: string) => v.slice(0, -1) + (v.at(-1) === 'A' ? 'B' : 'A');
    const taken = async (text: string) => {
      const r = parseReply(P, text);
      return !!r && (await checkReply(PV, open, a.id, r, NOW + 1)).ok;
    };
    for (const f of ['m', 'to', 'device', 'name', 'sig', 'dh', 'proof']) {
      const { [f]: _g, ...rest } = o;
      expect(await taken(enc({ ...o, [f]: flip(o[f]) })), `flip ${f}`).toBe(false);
      expect(await taken(enc(rest)), `delete ${f}`).toBe(false);
      expect(await taken(enc({ ...o, [`${f}2`]: o[f] })), `add ${f}`).toBe(false);
    }
    expect(await taken(replyText(APP, reply))).toBe(true);
  });

  it('reply: every character of the text altered never gets taken', async () => {
    const text = replyText(APP, reply);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let taken = 0;
    for (let i = 0; i < text.length; i += 1) {
      const ch = chars[(chars.indexOf(text[i] as string) + 1) % 64] as string;
      const r = parseReply(P, text.slice(0, i) + ch + text.slice(i + 1));
      if (r && (await checkReply(PV, open, a.id, r, NOW + 1)).ok) taken++;
    }
    expect(taken).toBe(0);
  });
});
