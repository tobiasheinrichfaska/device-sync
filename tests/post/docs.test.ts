// The "envelope and mailbox" part of docs/wire-format.md is held to the code: the texts, the limits and
// the refusal codes it names are the ones the code uses.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ENVELOPE_LIMITS, FAN_GROUP, POST_LIMITS } from '../../src/index.ts';
import { APP, fake } from './helpers.ts';
import { startMessage } from './docs-helpers.ts';

const DOC = readFileSync(new URL('../../docs/wire-format.md', import.meta.url), 'utf8');
const PART = DOC.slice(
  DOC.indexOf('# Wire format: envelope and mailbox'),
  DOC.indexOf('# Cross-language notes'),
);
const spaced = (n: number): string => n.toLocaleString('en').replace(/,/g, ' ');

describe('docs/wire-format.md, envelope and mailbox', () => {
  it('exists and names every text exactly', () => {
    expect(PART.length).toBeGreaterThan(8000);
    for (const t of [
      '{"m":"<appId>-envelope:2","id":"<id>","day":"<YYYY-MM-DD>","eph":"<ephemeral point>","iv":"<12 bytes>","ct":"<base64url of ciphertext || tag>","k":["<48 bytes>", ...]}',
      '<appId>-envid:2|<n>:<day>|<n>:<eph>|<n>:<iv>|<n>:<ct>|<number of slots>|<n>:<slot 1>|<n>:<slot 2>|...',
      '<appId>-envelope:2|header|<n>:<day>|<n>:<eph>',
      '"<appId>-envelope:2|slot|<n>:<dh>"',
      '{"from":"<device id>","channel":"<channel>","sig":"<64 bytes>","body":"<base64url of the content>"}',
      '<appId>-envsig:2|<n>:<from>|<n>:<channel>|<n>:<day>|<n>:<body as base64url>',
      '<appId>-postday:2|<n>:<day>|<number of ids>|<n>:<id>|<n>:<id>|...',
      '<appId>-postbox:2|<number of ids>|<n>:<id>|<n>:<id>|...',
      '<appId>-poststand:2|<n>:<fingerprint>|<n>:<mailbox check>',
      '{"m":"<appId>-post:2","t":"days","days":{"<day>":"<day check>", ...}}',
      '{"m":"<appId>-post:2","t":"ids","ids":["<id>", ...],"last":<true|false>}',
      '{"m":"<appId>-post:2","t":"envelopes","envelopes":[{<envelope>}, ...],"last":<bool>}',
    ]) {
      expect(PART, t).toContain(t);
    }
  });

  it('what a real envelope and a real message look like, as documented', () => {
    expect(fake().text).toMatch(
      /^\{"m":"demo-envelope:2","id":"[A-Za-z0-9_-]{22}","day":"\d{4}-\d{2}-\d{2}","eph":"[A-Za-z0-9_-]{87}","iv":"[A-Za-z0-9_-]{16}","ct":"[A-Za-z0-9_-]+","k":\[("[A-Za-z0-9_-]{64}",?){8}\]\}$/,
    );
    expect(startMessage()).toMatch(/^\{"m":"demo-post:2","t":"days","days":\{.*\}\}$/);
  });

  it('every limit is in a table with its default, and the tables name no other limit', () => {
    const all = { ...POST_LIMITS };
    for (const [name, value] of Object.entries(all)) {
      const row = PART.split('\n').find((line) => line.startsWith(`| \`${name}\``));
      expect(row, name).toBeDefined();
      expect(row, name).toContain(spaced(value));
    }
    expect(ENVELOPE_LIMITS).toEqual({ maxEnvelopeBytes: 11000, maxFans: 64 });
    expect(FAN_GROUP).toBe(8);
    const named = [...PART.matchAll(/^\| `(\w+)`/gm)].map((m) => m[1] as string);
    expect(named.sort()).toEqual(Object.keys(all).sort());
  });

  it('every refusal code the code can return is documented', () => {
    const codes = [
      // sealing
      'bad-author',
      'bad-channel',
      'bad-day',
      'bad-input',
      'bad-random',
      'no-recipients',
      'too-many-recipients',
      'bad-recipient',
      'too-large',
      'crypto-failure',
      // opening
      'bad-own',
      'not-an-envelope',
      'bad-point',
      'not-for-me',
      'damaged',
      'unknown-author',
      'bad-signature',
      // mailbox and session
      'bad-supplier',
      'too-many',
      'unexpected',
      'bad-message',
      'too-many-ids',
      'too-many-envelopes',
    ];
    for (const code of codes) expect(PART, code).toContain(`\`${code}\``);
  });

  it('states what is hidden and what is not', () => {
    for (const phrase of [
      'the sender',
      'the readers',
      'the number of readers',
      'Size',
      'The author is not deniable',
      'Replay',
      'No forward secrecy against a reader',
      'A reader can re-seal',
      'A carrier can drop, delay or multiply',
      'zero nonce',
      'Fisher-Yates',
      'at most `maxFans` small AES-GCM trials',
      'a device called `__proto__`',
      'linear',
    ]) {
      expect(PART.replace(/\s+/g, ' ').toLowerCase(), phrase).toContain(phrase.toLowerCase());
    }
  });

  it('the marker kinds it names are the ones the code uses', () => {
    expect(APP).toBe('demo');
    for (const kind of ['envelope', 'envid', 'envsig', 'post', 'postday', 'postbox', 'poststand']) {
      expect(PART).toContain(`-${kind}:2`);
    }
  });
});
