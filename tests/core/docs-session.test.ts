// The "end-to-end layer" part of docs/wire-format.md is held to the code: the texts, the limits and the
// refusal codes it names are the ones the code uses.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  FILE_LIMITS,
  SESSION_LIMITS,
  encodeHello,
  maxFileBytes,
  maxSealedChars,
} from '../../src/core/index.ts';
import { APP, connect, party, A, B, text } from './secure-helpers.ts';

const DOC = readFileSync(new URL('../../docs/wire-format.md', import.meta.url), 'utf8');
const E2E = DOC.slice(
  DOC.indexOf('# Wire format: end-to-end layer'),
  DOC.indexOf('# Cross-language notes'),
);
const spaced = (n: number): string => n.toLocaleString('en').replace(/,/g, ' ');

describe('docs/wire-format.md, end-to-end layer', () => {
  it('exists and names every text of the session and the file exactly', () => {
    expect(E2E.length).toBeGreaterThan(5000);
    for (const t of [
      '{"m":"<appId>-hello:2","device":"<device id>","eph":"<ephemeral point>"}',
      '{"m":"<appId>-msg:2","n":<counter>,"ct":"<base64url of ciphertext || tag>"}',
      '<appId>-session:2|<n>:<lo device>|<n>:<lo dh>|<n>:<lo eph>|<n>:<hi device>|<n>:<hi dh>|<n>:<hi eph>',
      '<appId>-session:2|key|<n>:<X>',
      '<appId>-msg:2|<n>:<sender>|<n>:<receiver>|<counter>',
      '<appId>-file:2|<n>:<from>|<n>:<to>|<n>:<from dh>|<n>:<to dh>|<n>:<eph>',
      '<appId>-file:2|key',
      'ikm = ee || t1 || t2 || ss',
      'ikm = ECDH(E, S_to) || ECDH(S_from, S_to)',
      '"eph":"<ephemeral point>","iv":"<12 bytes>","ct":"<base64url of ciphertext || tag>"}',
    ]) {
      expect(E2E, t).toContain(t);
    }
  });

  it('the hello and a message look as documented', async () => {
    const { a, helloA } = await connect(await party(A), await party(B));
    expect(encodeHello(APP, helloA)).toMatch(
      /^\{"m":"demo-hello:2","device":"[^"]+","eph":"[A-Za-z0-9_-]{87}"\}$/,
    );
    const sealed = await a.seal(text('x'));
    expect(sealed.ok && sealed.text).toMatch(/^\{"m":"demo-msg:2","n":0,"ct":"[A-Za-z0-9_-]+"\}$/);
  });

  it('the limits in the tables are the defaults of the code', () => {
    expect(E2E).toContain(`(${spaced(SESSION_LIMITS.maxPlaintextBytes)} bytes)`);
    expect(E2E).toContain(`(${spaced(SESSION_LIMITS.maxMessages)})`);
    expect(E2E).toContain(`(${spaced(FILE_LIMITS.maxPlaintextBytes)} bytes)`);
    expect(E2E).toContain('`ceil((maxPlaintextBytes + 16) * 4 / 3) + 256`');
    expect(maxSealedChars(SESSION_LIMITS)).toBe(
      Math.ceil(((SESSION_LIMITS.maxPlaintextBytes + 16) * 4) / 3) + 256,
    );
    expect(maxFileBytes(FILE_LIMITS)).toBeGreaterThan(FILE_LIMITS.maxPlaintextBytes);
    expect(E2E).toContain('a hello is at most 1024 characters');
  });

  it('every refusal code the code can return is documented', () => {
    const codes = [
      // opening a session
      'bad-own',
      'bad-peer',
      'bad-hello',
      'own-hello-mismatch',
      'wrong-device',
      'same-device',
      'mirrored',
      'bad-peer-key',
      'same-key',
      'bad-point',
      'ephemeral-reused',
      'crypto-failure',
      // messages
      'replayed',
      'gap',
      'counter-limit',
      'bad-message',
      'bad-seal',
      'too-large',
      // files
      'not-a-file',
      'wrong-recipient',
      'wrong-sender',
      'cannot-open',
      'bad-sender',
      'bad-recipient',
      'bad-random',
      'bad-input',
    ];
    for (const code of codes) expect(E2E, code).toContain(`\`${code}\``);
  });

  it('states the limits of what is protected', () => {
    for (const phrase of [
      'Forward secrecy',
      'no forward secrecy within a',
      'Key-compromise impersonation resistance',
      "No forward secrecy against the recipient's static key",
      'No replay protection',
      'Truncation',
      'counter-based',
      'UTF-8 byte order',
      'Metadata',
    ]) {
      expect(E2E.toLowerCase(), phrase).toContain(phrase.toLowerCase());
    }
  });
});
