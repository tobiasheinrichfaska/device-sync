// The relay's own invitation inside the invitation link of the trust layer (`relayInvitation`), refused as
// a whole when its role or inviter disagree with the log invitation; and the whole way of a new device: the
// link, enrolment at the relay with the `e2`, the reply through the relay, the check by the inviter.
import { describe, expect, it } from 'vitest';
import { base64url, fromBase64url } from '../../src/core/index.ts';
import {
  RelayClient,
  encodeInviteReply,
  relayInvitationValidator,
  relayRoleOf,
  startReply,
  stepReply,
  takeInviteReplies,
} from '../../src/relay/index.ts';
import {
  checkReply,
  createInvitation,
  invitationLink,
  invitationProof,
  parseInvitation,
  parseReply,
  replyText,
  resolveValidators,
  vouchRoles,
  type DeviceEntry,
  type ProtocolOptions,
} from '../../src/trust/index.ts';
import { dev } from '../trust/helpers.ts';
import { ALPHA, mintProof, serverForR2 } from './helpers.ts';
import { DEV, DEV2, inv2Text, memoryStore, newSigner } from './helpers-r2.ts';

const NOW = 1_800_000_000_000;
const PAGE = 'https://example.org/app/index.html';
const RANDOM = new Uint8Array(16).fill(7);
const VOUCHER = vouchRoles(['admin']);
// The trust layer's roles map to the relay's: `admin` is the office, a `member:<id>` a member's device.
const relayRole = (role: string): string =>
  role === 'admin' ? 'buero' : role.startsWith('member:') ? `lb:${role.slice(7)}` : 'ohne';
const OPTIONS: ProtocolOptions = {
  appId: 'alpha',
  valid: {
    role: (r) => /^[a-z][a-z0-9:_-]{0,79}$/.test(r),
    relayInvitation: relayInvitationValidator({ appId: 'alpha', relayRole }),
  },
};
const decode = (link: string) =>
  JSON.parse(new TextDecoder().decode(fromBase64url(link.split('#join=')[1] as string)));
const linkOf = (o: unknown) =>
  `${PAGE}#join=${base64url(new TextEncoder().encode(JSON.stringify(o)))}`;

async function inviter(relayId?: string): Promise<DeviceEntry> {
  const d = await dev('Admin A');
  return {
    ...d.intro,
    role: 'admin',
    removed: false,
    private: false,
    ...(relayId ? { relayId } : {}),
  };
}

describe('the relay part in the invitation link (`relayInvitation`)', () => {
  it('goes into the link and comes back; without it nothing changes', async () => {
    const a = await inviter(DEV);
    const e2 = inv2Text({ role: 'lb:art', inviter: DEV });
    const made = createInvitation({ ...OPTIONS, voucher: VOUCHER }, a, 'member:art', RANDOM, NOW, {
      relayInvitation: e2,
    });
    if (!made.ok) throw new Error(made.reason);
    expect(made.invitation).toMatchObject({ relayInvitation: e2, relayId: DEV });
    const link = invitationLink('alpha', PAGE, made.invitation);
    expect(decode(link).relayInvitation).toBe(e2);
    expect(parseInvitation(OPTIONS, link)).toEqual(made.invitation);
    // without the relay part the invitation is what it was
    const plain = createInvitation({ ...OPTIONS, voucher: VOUCHER }, a, 'member:art', RANDOM, NOW);
    if (!plain.ok) throw new Error(plain.reason);
    expect(plain.invitation.relayInvitation).toBeUndefined();
    expect(decode(invitationLink('alpha', PAGE, plain.invitation))).not.toHaveProperty(
      'relayInvitation',
    );
    expect(
      parseInvitation(OPTIONS, invitationLink('alpha', PAGE, plain.invitation))?.relayInvitation,
    ).toBeUndefined();
  });

  it('a long name, a long role and a long relay id still fit in a link the parser takes', async () => {
    const d = await dev('Admin A');
    const longId = `geraet-${'f'.repeat(32)}`;
    const a: DeviceEntry = {
      ...d.intro,
      role: 'admin',
      removed: false,
      private: false,
      relayId: longId,
    };
    const role = `member:${'x'.repeat(40)}`;
    const e2 = inv2Text({ role: `lb:${'x'.repeat(40)}`, inviter: longId, group: 'y'.repeat(20) });
    const made = createInvitation({ ...OPTIONS, voucher: VOUCHER }, a, role, RANDOM, NOW, {
      relayInvitation: e2,
      newName: 'n'.repeat(40),
    });
    if (!made.ok) throw new Error(made.reason);
    const link = invitationLink('alpha', PAGE, made.invitation);
    expect(parseInvitation(OPTIONS, link)?.relayInvitation).toBe(e2);
  });

  it('the creator refuses what the reader would refuse: a relay part that does not fit this role and inviter', async () => {
    const a = await inviter(DEV);
    const make = (e2: string, role = 'member:art') =>
      createInvitation({ ...OPTIONS, voucher: VOUCHER }, a, role, RANDOM, NOW, {
        relayInvitation: e2,
      });
    expect(make(inv2Text({ role: 'buero', inviter: DEV }))).toEqual({
      ok: false,
      reason: 'bad-relay-invitation',
    });
    expect(make(inv2Text({ role: 'lb:art', inviter: DEV2 }))).toEqual({
      ok: false,
      reason: 'bad-relay-invitation',
    });
    expect(make('not an invitation')).toEqual({ ok: false, reason: 'bad-relay-invitation' });
    // without a validator no relay part is acceptable at all
    const bare = createInvitation({ appId: 'alpha', voucher: VOUCHER }, a, 'member', RANDOM, NOW, {
      relayInvitation: inv2Text({ role: 'ohne', inviter: DEV }),
    });
    expect(bare).toEqual({ ok: false, reason: 'bad-relay-invitation' });
  });

  it("is refused as a whole: not an e2, another app's, a role other than the link's, an inviter other than the one named", async () => {
    const a = await inviter(DEV);
    const made = createInvitation({ ...OPTIONS, voucher: VOUCHER }, a, 'member:art', RANDOM, NOW, {
      relayInvitation: inv2Text({ role: 'lb:art', inviter: DEV }),
    });
    if (!made.ok) throw new Error(made.reason);
    const raw = decode(invitationLink('alpha', PAGE, made.invitation));
    const parse = (change: Record<string, unknown>) =>
      parseInvitation(OPTIONS, linkOf({ ...raw, ...change }));
    expect(parse({})).toBeDefined();
    expect(
      parse({ relayInvitation: inv2Text({ role: 'lb:art', inviter: DEV }).replace('e2.', 'e1.') }),
    ).toBeUndefined();
    expect(
      parse({ relayInvitation: inv2Text({ app: 'beta', role: 'lb:art', inviter: DEV }) }),
    ).toBeUndefined();
    // the relay sets the role from the e2: an e2 for the office in the link of a member's device would make an office device
    expect(parse({ relayInvitation: inv2Text({ role: 'buero', inviter: DEV }) })).toBeUndefined();
    expect(parse({ relayInvitation: inv2Text({ role: 'ohne', inviter: DEV }) })).toBeUndefined();
    expect(
      parse({ relayInvitation: inv2Text({ role: 'lb:other', inviter: DEV }) }),
    ).toBeUndefined();
    expect(parse({ relayInvitation: inv2Text({ role: 'lb:art', inviter: DEV2 }) })).toBeUndefined(); // made by another device than the link names
    expect(parse({ relayInvitation: 5 })).toBeUndefined();
    expect(parse({ relayInvitation: '' })).toBeUndefined();
    expect(parse({ relayInvitation: 'x'.repeat(500) })).toBeUndefined();
    // a link that names no relay id of its inviter takes any inviter in the e2 (the reply cannot go there either)
    const { relayId: _gone, ...noRelayId } = raw;
    expect(
      parseInvitation(
        OPTIONS,
        linkOf({ ...noRelayId, relayInvitation: inv2Text({ role: 'lb:art', inviter: DEV2 }) }),
      ),
    ).toBeDefined();
    // a role that maps to none (an app role the relay cannot hold) is an e2 for `ohne`, never more
    const none = {
      ...raw,
      role: 'guest',
      relayInvitation: inv2Text({ role: 'ohne', inviter: DEV }),
    };
    expect(parseInvitation(OPTIONS, linkOf(none))).toBeDefined();
    expect(
      parseInvitation(
        OPTIONS,
        linkOf({ ...none, relayInvitation: inv2Text({ role: 'buero', inviter: DEV }) }),
      ),
    ).toBeUndefined();
    // and one spelling: a reordered or re-encoded link is no link
    expect(
      parseInvitation(OPTIONS, linkOf({ relayInvitation: raw.relayInvitation, ...raw })),
    ).toBeUndefined();
  });

  it('an app that passes no validator never takes the member; a validator that throws or answers badly refuses', async () => {
    const a = await inviter(DEV);
    const made = createInvitation({ ...OPTIONS, voucher: VOUCHER }, a, 'member:art', RANDOM, NOW, {
      relayInvitation: inv2Text({ role: 'lb:art', inviter: DEV }),
    });
    if (!made.ok) throw new Error(made.reason);
    const link = invitationLink('alpha', PAGE, made.invitation);
    expect(
      parseInvitation({ appId: 'alpha', valid: { role: OPTIONS.valid?.role as never } }, link),
    ).toBeUndefined();
    for (const bad of [
      () => {
        throw new Error('x');
      },
      () => 'yes' as never,
      () => undefined as never,
    ]) {
      expect(
        parseInvitation({ ...OPTIONS, valid: { ...OPTIONS.valid, relayInvitation: bad } }, link),
      ).toBeUndefined();
    }
    expect(resolveValidators().relayInvitation('x', { role: 'a', inviterRelayId: undefined })).toBe(
      false,
    );
  });

  it('the role map is a parameter: by default the same text where the relay can hold it, else none', () => {
    const v = relayInvitationValidator({ appId: 'alpha' });
    const ctx = (role: string) => ({ role, inviterRelayId: undefined });
    expect(v(inv2Text({ role: 'buero' }), ctx('buero'))).toBe(true);
    expect(v(inv2Text({ role: 'lb:art' }), ctx('lb:art'))).toBe(true);
    expect(v(inv2Text({ role: 'ohne' }), ctx('admin'))).toBe(true); // `admin` is no relay role
    expect(v(inv2Text({ role: 'buero' }), ctx('admin'))).toBe(false);
    expect(relayRoleOf('admin')).toBe('ohne');
    expect(v(undefined as never, ctx('x'))).toBe(false);
    expect(
      relayInvitationValidator({
        appId: 'alpha',
        relayRole: () => {
          throw new Error('x');
        },
      })(inv2Text(), ctx('x')),
    ).toBe(false);
  });
});

describe('the whole way of a new device: link, enrolment with the e2, reply through the relay, check', () => {
  it('the new device takes the e2 into the relay, answers through the relay, and the inviter checks the proof', async () => {
    const server = serverForR2();
    const mk = async () => {
      const { signer } = await newSigner();
      const store = memoryStore();
      const c = new RelayClient({
        baseUrl: 'https://relay.test',
        appId: 'alpha',
        origin: ALPHA.origin,
        fetch: server.fetch,
        store,
        clock: server.now,
        signer,
        maxAttempts: 1,
      });
      return { c, store };
    };
    // the inviting (office) device is at the relay already
    const office = await mk();
    const o = await office.c.enrol({
      proof: await mintProof('alpha', server.now()),
      role: 'buero',
    });
    if (!o.ok) throw new Error(o.kind);
    const e2 = await office.c.invite({ role: 'lb:art' });
    if (!e2.ok) throw new Error(e2.kind);
    // the log invitation carries it, with the inviter's relay id
    const a = await dev('Admin A');
    const entry: DeviceEntry = {
      ...a.intro,
      role: 'admin',
      removed: false,
      private: false,
      relayId: o.value.device,
    };
    const made = createInvitation(
      { ...OPTIONS, voucher: VOUCHER },
      entry,
      'member:art',
      RANDOM,
      NOW,
      { relayInvitation: e2.value.invitation },
    );
    if (!made.ok) throw new Error(made.reason);
    const link = invitationLink('alpha', PAGE, made.invitation);
    // the new device reads the link, enrols at the relay with the relay part: the role comes from it
    const parsed = parseInvitation(OPTIONS, link);
    if (!parsed?.relayInvitation || !parsed.relayId) throw new Error('the link did not parse');
    const joining = await mk();
    const enrolled = await joining.c.enrol({ invitation: parsed.relayInvitation });
    if (!enrolled.ok) throw new Error(enrolled.kind);
    expect(enrolled.value).toMatchObject({ group: '1', role: 'lb:art' });
    // it answers: the reply text of the trust layer, through the relay, in clear
    const n = await dev('New N');
    const proof = await invitationProof('alpha', parsed, n.intro);
    const text = replyText('alpha', { to: a.id, introduction: n.intro, proof });
    const t0 = server.now();
    // sent until the invitation's end (here a few seconds after "now": the link says 24 hours)
    const live = startReply('alpha', { to: parsed.relayId, text, until: t0 + 3_600_000 }, t0)!;
    expect(startReply('alpha', { to: parsed.relayId, text, until: t0 - 1 }, t0)).toBeUndefined();
    const sent = await stepReply(joining.c, 'alpha', live, t0);
    expect(sent).toMatchObject({ done: false, outcome: 'sent' });
    // the inviter collects, takes the reply out and checks it
    const got = await office.c.collect();
    if (!got.ok) throw new Error(got.kind);
    const taken = takeInviteReplies('alpha', got.value.messages, t0);
    expect(taken.replies).toHaveLength(1);
    expect(taken.rest).toHaveLength(0);
    const reply = parseReply(OPTIONS, taken.replies[0]!.text);
    expect(reply).toBeDefined();
    const open = { role: 'member:art', code: made.open.code, until: NOW + 1000 };
    expect(await checkReply({ ...OPTIONS, voucher: VOUCHER }, open, a.id, reply!, NOW)).toEqual({
      ok: true,
    });
    // a forged reply from another device does not pass the proof; the relay only carried it
    const forged = encodeInviteReply(
      'alpha',
      replyText('alpha', { to: a.id, introduction: n.intro, proof: base64url(new Uint8Array(32)) }),
    );
    expect(forged).toBeDefined();
  });
});
