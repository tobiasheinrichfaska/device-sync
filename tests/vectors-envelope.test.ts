// Runs the committed envelope and mailbox vectors (tests/vectors/envelope.json, mailbox.json) against
// the code AND against an independent derivation written from docs/wire-format.md with node:crypto
// only. The vectors are meant for other implementations too. All keys in them are throw-away keys.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  announcedStand,
  base64url,
  dayChecks,
  mailboxCheck,
  openEnvelope,
  readEnvelope,
  readPostMessage,
  verifyText,
  writePostMessage,
  importPublicKey,
  type Envelope,
} from '../src/index.ts';
import { refHeader, refSigned } from './core/envelope-reference.ts';
import { refOpen } from './core/envelope-reference.ts';
import type { PrivateJwk } from './core/reference.ts';
import { pairFromJwk } from './core/secure-helpers.ts';

const load = <T>(name: string): T =>
  JSON.parse(readFileSync(new URL(`./vectors/${name}.json`, import.meta.url), 'utf8')) as T;
const sha = (t: string): Buffer => createHash('sha256').update(t).digest();
const field = (t: string): string => `${Buffer.byteLength(t)}:${t}`;

interface EnvelopeVectors {
  appId: string;
  author: { device: string; signingPoint: string };
  channel: string;
  day: string;
  bodyText: string;
  envelope: string;
  id: string;
  idHashedText: string;
  idHashHex: string;
  headerText: string;
  saltHex: string;
  readers: {
    agreementPrivateJwk: PrivateJwk;
    agreementPoint: string;
    slotIndex: number;
    kekHex: string;
    contentKeyHex: string;
  }[];
  innerText: string;
  signedText: string;
  signatureBase64url: string;
  mustRefuse: {
    name: string;
    text: string;
    recipient: number | 'stranger';
    appId?: string;
    reason: string;
  }[];
  stranger: { agreementPrivateJwk: PrivateJwk };
}

describe('envelope vectors', () => {
  const v = load<EnvelopeVectors>('envelope');
  const authors = { [v.author.device]: v.author.signingPoint };
  const authorKey = (from: string): string | undefined =>
    Object.hasOwn(authors, from) ? authors[from] : undefined;

  it('the id is the first 16 bytes of the SHA-256 of the documented text', () => {
    const parts = JSON.parse(v.envelope) as {
      day: string;
      eph: string;
      iv: string;
      ct: string;
      k: string[];
    };
    const text = `demo-envid:2|${field(parts.day)}|${field(parts.eph)}|${field(parts.iv)}|${field(parts.ct)}|${parts.k.length}|${parts.k.map(field).join('|')}`;
    expect(text).toBe(v.idHashedText);
    expect(sha(text).toString('hex')).toBe(v.idHashHex);
    expect(base64url(sha(text).subarray(0, 16))).toBe(v.id);
    expect(readEnvelope(v.appId, v.envelope)?.id).toBe(v.id);
    expect(parts.k).toHaveLength(8);
  });

  it('the header text and the independent derivation reproduce the keys', () => {
    const parts = JSON.parse(v.envelope) as { day: string; eph: string };
    expect(refHeader(v.appId, parts.day, parts.eph)).toBe(v.headerText);
    expect(sha(v.headerText).toString('hex')).toBe(v.saltHex);
    for (const r of v.readers) {
      const o = refOpen(v.appId, v.envelope, r.agreementPrivateJwk);
      expect(o?.slotIndex).toBe(r.slotIndex);
      expect(o?.kek.toString('hex')).toBe(r.kekHex);
      expect(o?.contentKey.toString('hex')).toBe(r.contentKeyHex);
      expect(o?.inner).toBe(v.innerText);
    }
  });

  it('the inside and the author signature are what the document says', async () => {
    const inner = JSON.parse(v.innerText) as {
      from: string;
      channel: string;
      sig: string;
      body: string;
    };
    expect(Object.keys(inner)).toEqual(['from', 'channel', 'sig', 'body']);
    expect(Buffer.from(inner.body, 'base64url').toString()).toBe(v.bodyText);
    expect(inner.sig).toBe(v.signatureBase64url);
    const signed = refSigned(v.appId, v.author.device, v.channel, v.day, inner.body);
    expect(signed).toBe(v.signedText);
    const key = await importPublicKey(v.author.signingPoint, 'sig');
    expect(key && (await verifyText(key, signed, inner.sig))).toBe(true);
    // the signature binds the other values: any change does not verify
    for (const other of [
      refSigned('other', v.author.device, v.channel, v.day, inner.body),
      refSigned(v.appId, 'device-x', v.channel, v.day, inner.body),
      refSigned(v.appId, v.author.device, 'chan-2', v.day, inner.body),
      refSigned(v.appId, v.author.device, v.channel, '2026-11-11', inner.body),
      refSigned(v.appId, v.author.device, v.channel, v.day, `${inner.body}A`),
    ]) {
      expect(key && (await verifyText(key, other, inner.sig))).toBe(false);
    }
  });

  it('every reader opens it with the code', async () => {
    for (const r of v.readers) {
      const got = await openEnvelope({
        appId: v.appId,
        own: { agreement: await pairFromJwk(r.agreementPrivateJwk) },
        envelope: v.envelope,
        authorKey,
      });
      expect(got).toMatchObject({
        ok: true,
        from: v.author.device,
        channel: v.channel,
        day: v.day,
        id: v.id,
      });
      expect(got.ok && Buffer.from(got.body).toString()).toBe(v.bodyText);
    }
  });

  it('what must be refused is refused, with the code that is written down', async () => {
    for (const m of v.mustRefuse) {
      const jwk =
        m.recipient === 'stranger'
          ? v.stranger.agreementPrivateJwk
          : (v.readers[m.recipient] as (typeof v.readers)[number]).agreementPrivateJwk;
      const got = await openEnvelope({
        appId: m.appId ?? v.appId,
        own: { agreement: await pairFromJwk(jwk) },
        envelope: m.text,
        authorKey,
      });
      expect(got, m.name).toEqual({ ok: false, reason: m.reason });
    }
  });
});

interface MailboxVectors {
  appId: string;
  envelopes: Envelope[];
  dayChecks: Record<string, string>;
  dayCheckTexts: Record<string, string>;
  dayCheckHashes: Record<string, string>;
  mailboxCheck: string;
  mailboxCheckText: string;
  fingerprint: string;
  announcedStand: string;
  announcedStandText: string;
  announcedStandHashHex: string;
  messages: { days: string; ids: string; envelopes: string };
  mustRefuse: { name: string; text: string }[];
}

describe('mailbox vectors', () => {
  const v = load<MailboxVectors>('mailbox');
  const read = v.envelopes.map((e) => readEnvelope(v.appId, e.text) as Envelope);
  const mailbox = { items: read };

  it('the envelopes are read again with the ids they carry', () => {
    expect(read.map((e) => e.id)).toEqual(v.envelopes.map((e) => e.id));
    expect(read.map((e) => e.day)).toEqual(v.envelopes.map((e) => e.day));
  });

  it('the check values are hashes of the documented texts', () => {
    for (const [day, text] of Object.entries(v.dayCheckTexts)) {
      expect(base64url(sha(text).subarray(0, 16))).toBe(v.dayCheckHashes[day]);
      expect(v.dayChecks[day]).toBe(v.dayCheckHashes[day]);
    }
    expect({ ...dayChecks(v.appId, mailbox) }).toEqual(v.dayChecks);
    expect(base64url(sha(v.mailboxCheckText).subarray(0, 16))).toBe(v.mailboxCheck);
    expect(mailboxCheck(v.appId, mailbox)).toBe(v.mailboxCheck);
    expect(sha(v.announcedStandText).subarray(0, 16).toString('hex')).toBe(v.announcedStandHashHex);
    expect(announcedStand(v.appId, v.fingerprint, mailbox)).toBe(v.announcedStand);
    expect(announcedStand(v.appId, v.fingerprint, { items: [] })).toBe(v.fingerprint);
  });

  it('the messages are read and written in exactly this spelling', () => {
    const days = readPostMessage(v.appId, v.messages.days);
    expect(days?.t).toBe('days');
    expect(writePostMessage(v.appId, days as never)).toBe(v.messages.days);
    const ids = readPostMessage(v.appId, v.messages.ids);
    expect(ids).toMatchObject({ t: 'ids', last: false });
    expect(writePostMessage(v.appId, ids as never)).toBe(v.messages.ids);
    const envelopes = readPostMessage(v.appId, v.messages.envelopes);
    expect(envelopes).toMatchObject({ t: 'envelopes', last: true });
    expect(writePostMessage(v.appId, envelopes as never)).toBe(v.messages.envelopes);
    expect(v.messages.envelopes).toContain(v.envelopes[2]?.text);
  });

  it('what must be refused is refused', () => {
    for (const m of v.mustRefuse) expect(readPostMessage(v.appId, m.text), m.name).toBeUndefined();
  });
});
