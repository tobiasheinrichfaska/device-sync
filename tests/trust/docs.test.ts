// The "Trust" section of the wire-format document is held to the code.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { base64url } from '../../src/core/index.ts';
import {
  INVITATION_MS,
  MEETING_AHEAD_MS,
  MEETING_RENEW_MS,
  MEETING_VALID_MS,
  deviceNeverErase,
  invitationLink,
  meetingSigningText,
  proofText,
  replyText,
  signMeetingCode,
} from '../../src/trust/index.ts';
import { dev } from './helpers.ts';

const DOC = readFileSync(new URL('../../docs/wire-format.md', import.meta.url), 'utf8');
const TRUST = DOC.slice(DOC.indexOf('## Trust'));

describe('docs/wire-format.md, section Trust', () => {
  it('names the numbers the code uses', () => {
    expect(TRUST).toContain(`**${MEETING_VALID_MS.toLocaleString('en').replace(/,/g, ' ')} ms**`);
    expect(TRUST).toContain(`**${MEETING_RENEW_MS.toLocaleString('en').replace(/,/g, ' ')} ms**`);
    expect(TRUST).toContain(`**${MEETING_AHEAD_MS.toLocaleString('en').replace(/,/g, ' ')} ms**`);
    expect(TRUST).toContain(String(INVITATION_MS).replace(/(\d)(?=(\d{3})+$)/g, '$1 '));
    expect(TRUST).toContain('default `device`');
    expect(deviceNeverErase()).toEqual(['device']);
  });

  it('the signed and MACed texts are the documented ones', async () => {
    const d = await dev('Doc');
    expect(TRUST).toContain('<appId>-meeting:2|device|name|sig|dh|role|time|0');
    expect(meetingSigningText('app', d.intro, 'r', 1, false)).toBe(
      `app-meeting:2|${d.id}|Doc|${d.intro.sig}|${d.intro.dh}|r|1|0`,
    );
    expect(TRUST).toContain(
      '<appId>-invite:2|<inviter device>|<role>|<new device>|<new name>|<new sig>|<new dh>',
    );
    expect(proofText('app', 'i', 'r', d.intro)).toBe(
      `app-invite:2|i|r|${d.id}|Doc|${d.intro.sig}|${d.intro.dh}`,
    );
  });

  it('the layouts are the documented member orders', async () => {
    const d = await dev('Doc');
    const meeting = JSON.parse(
      new TextDecoder().decode(
        await signMeetingCode({ appId: 'app' }, d.intro, 'r', 1, d.keys.signing.privateKey),
      ),
    );
    expect(Object.keys(meeting)).toEqual([
      'm',
      'device',
      'name',
      'sig',
      'dh',
      'role',
      'time',
      'proof',
    ]);
    expect(TRUST).toContain('"role":"…","time":<ms>,["private":true,]"proof":"…"');
    const link = invitationLink('app', 'p', {
      from: d.intro,
      role: 'r',
      code: base64url(new Uint8Array(16)),
      until: 5,
      newName: 'n',
      relayId: 'x',
      private: true,
    });
    const payload = JSON.parse(
      Buffer.from(link.split('#join=')[1] as string, 'base64url').toString(),
    );
    expect(Object.keys(payload)).toEqual([
      'm',
      'device',
      'name',
      'sig',
      'dh',
      'role',
      'code',
      'until',
      'newName',
      'relayId',
      'private',
    ]);
    const reply = JSON.parse(
      Buffer.from(
        replyText('app', {
          to: 'device-' + 'a'.repeat(32),
          introduction: d.intro,
          proof: 'A'.repeat(43),
        }),
        'base64url',
      ).toString(),
    );
    expect(Object.keys(reply)).toEqual(['m', 'to', 'device', 'name', 'sig', 'dh', 'proof']);
  });

  it('lists every field of an entry', () => {
    for (const f of ['name', 'sig', 'dh', 'role', 'relayId', 'removed', 'private']) {
      expect(TRUST).toContain(`| \`${f}\``);
    }
  });
});
