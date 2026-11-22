// Round 5 review of the post layer: findings turned into tests (each failed before its fix).
import { describe, expect, it } from 'vitest';
import {
  addEnvelopes,
  postStart,
  postStep,
  readPostMessage,
  writePostMessage,
  type Mailbox,
  type PostMessage,
  type PostSession,
} from '../../src/index.ts';
import { A, APP, B, TODAY, fake, mailboxOf } from './helpers.ts';

const text = (m: PostMessage): string => writePostMessage(APP, m);

describe('round 5: the exchange is bounded in messages, not only in items', () => {
  it('an empty ids or envelopes message that is not the last one is not a message', () => {
    // an honest sender never makes one (the last piece alone may be empty), so the reader refuses it
    expect(readPostMessage(APP, text({ t: 'ids', ids: [], last: false }))).toBeUndefined();
    expect(
      readPostMessage(APP, text({ t: 'envelopes', envelopes: [], last: false })),
    ).toBeUndefined();
    expect(readPostMessage(APP, text({ t: 'ids', ids: [], last: true }))).toBeDefined();
    expect(readPostMessage(APP, text({ t: 'envelopes', envelopes: [], last: true }))).toBeDefined();
  });

  it('a neighbour cannot keep a session open with endless empty messages', () => {
    const started = postStart({ appId: APP, mailbox: mailboxOf(fake()), today: TODAY });
    if (!started.ok) throw new Error('start');
    let session: PostSession = started.session;
    let mailbox: Mailbox = started.mailbox;
    const feed = (m: PostMessage): boolean => {
      const r = postStep({ appId: APP, session, mailbox, message: text(m), today: TODAY, from: B });
      if (r.ok) {
        session = r.session;
        mailbox = r.mailbox;
      }
      return r.ok;
    };
    expect(feed({ t: 'days', days: {} })).toBe(true);
    let accepted = 0;
    for (let i = 0; i < 5000; i += 1) if (feed({ t: 'ids', ids: [], last: false })) accepted += 1;
    expect(accepted).toBe(0);
    expect(feed({ t: 'ids', ids: [], last: true })).toBe(true);
    for (let i = 0; i < 5000; i += 1) {
      if (feed({ t: 'envelopes', envelopes: [], last: false })) accepted += 1;
    }
    expect(accepted).toBe(0);
  });
});

describe('round 5: what a device sends, its own reader takes (also with other limits)', () => {
  it('ids pieces stay under the message cap when maxPerMessage is raised', () => {
    const limits = { maxPerMessage: 1000 };
    const box = mailboxOf(...Array.from({ length: 1000 }, () => fake()));
    const started = postStart({ appId: APP, mailbox: box, today: TODAY, limits });
    if (!started.ok) throw new Error('start');
    const r = postStep({
      appId: APP,
      session: started.session,
      mailbox: started.mailbox,
      message: text({ t: 'days', days: {} }),
      today: TODAY,
      from: A,
      limits,
    });
    if (!r.ok) throw new Error(r.reason);
    for (const message of r.send) expect(readPostMessage(APP, message, limits)).toBeDefined();
  });
});

describe('round 5: a known envelope is checked against the limits of the mailbox it enters', () => {
  it('an envelope read under generous limits does not pass a mailbox with tight ones', () => {
    const big = fake(TODAY, 3000);
    const tight = { maxEnvelopeBytes: 2000 };
    const r = addEnvelopes(APP, mailboxOf(), [big], TODAY, { limits: tight });
    expect(r.ok && r.added.length).toBe(0);
  });
});
