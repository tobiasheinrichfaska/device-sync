// docs/group.md is held to the code: texts, limits and refusal codes.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  GROUP_LIMITS,
  encryptGroup,
  rotateGroup,
  storeGroupState,
  type DecryptRefusal,
  type EncryptRefusal,
  type GroupAddRefusal,
  type GroupRefusal,
} from '../../src/group/index.ts';
import { maxDataChars, maxGrantChars, maxStateChars } from '../../src/group/limits.ts';
import { grantSigText, grantText, requestSigText, requestText } from '../../src/group/wire.ts';
import { APP, fresh, seeded, text, world } from './helpers.ts';

const DOC = readFileSync(new URL('../../docs/group.md', import.meta.url), 'utf8');
const spaced = (n: number): string => n.toLocaleString('en').replace(/,/g, ' ');

// A Record over the union forces this list to be complete when a code is added.
const REFUSALS: Record<GroupRefusal, true> = {
  'bad-input': true,
  'bad-own': true,
  'bad-random': true,
  'self-removed': true,
  'epoch-exhausted': true,
  'too-many-devices': true,
  'not-a-grant': true,
  'not-a-request': true,
  'wrong-recipient': true,
  'sender-not-trusted': true,
  'cannot-open': true,
  'bad-payload': true,
  'bad-signature': true,
  'wrong-data-set': true,
  'author-removed': true,
  'not-in-audience': true,
  'bad-recipient': true,
  'no-key': true,
  'below-floor': true,
  'epoch-jump': true,
  'author-conflict': true,
  'epoch-full': true,
  'too-many-keys': true,
  'audience-full': true,
};
const ADD: Record<GroupAddRefusal, true> = {
  'below-floor': true,
  'epoch-jump': true,
  'author-conflict': true,
  'epoch-full': true,
  'too-many-keys': true,
  'audience-full': true,
};
const DECRYPT: Record<DecryptRefusal, true> = {
  'not-group-data': true,
  'wrong-data-set': true,
  'unknown-key': true,
  'cannot-open': true,
  'bad-input': true,
};
const ENCRYPT: Record<EncryptRefusal, true> = {
  'no-key': true,
  'bad-input': true,
  'too-large': true,
  'bad-random': true,
  'crypto-failure': true,
};

describe('docs/group.md', () => {
  it('names the texts and derivations exactly', () => {
    for (const t of [
      '{"m":"<appId>-gkey:3","set":"<set>","epoch":<n>,"author":"<device>","from":"<device>","to":"<device>","kid":"<16 bytes>","key":"<32 bytes>","audience":["<device>",...],"sig":"<64 bytes>"}',
      '{"m":"<appId>-gkeysig:3","set":"<set>","epoch":<n>,"author":"<device>","from":"<device>","to":"<device>","kid":"<16 bytes>","audience":["<device>",...]}',
      '{"m":"<appId>-greq:3","set":"<set>","epoch":<n>,"from":"<device>","to":"<device>","sig":"<64 bytes>"}',
      '{"m":"<appId>-greqsig:3","set":"<set>","epoch":<n>,"from":"<device>","to":"<device>"}',
      '{"m":"<appId>-gdata:2","set":"<set>","epoch":<n>,"kid":"<16 bytes>","salt":"<16 bytes>","ct":"<ciphertext || 16-byte tag>"}',
      '{"m":"<appId>-gstate:2","set":"<set>","floor":<n>,"keys":[{"epoch":<n>,"author":"<device>","key":"<32 bytes>","audience":["<device>",...]},...]}',
      '<appId>-group:2|<n>:<set>',
      'info = "<appId>-group:2|kid|<epoch>"',
      'info = <appId>-gdata:2|<n>:<set>|<epoch>|<kid>',
      'AAD  = <info>|<n>:<context>',
    ]) {
      expect(DOC, t).toContain(t);
    }
  });

  it('the texts look as documented', async () => {
    const g = { set: 's', epoch: 1, author: 'a', from: 'f', to: 't', kid: 'i', audience: ['a'] };
    expect(grantText(APP, { ...g, key: 'k', sig: 'x' })).toBe(
      '{"m":"syncdemo-gkey:3","set":"s","epoch":1,"author":"a","from":"f","to":"t","kid":"i","key":"k","audience":["a"],"sig":"x"}',
    );
    expect(grantSigText(APP, g)).toBe(
      '{"m":"syncdemo-gkeysig:3","set":"s","epoch":1,"author":"a","from":"f","to":"t","kid":"i","audience":["a"]}',
    );
    const q = { set: 's', epoch: 0, from: 'f', to: 't' };
    expect(requestText(APP, { ...q, sig: 'x' })).toBe(
      '{"m":"syncdemo-greq:3","set":"s","epoch":0,"from":"f","to":"t","sig":"x"}',
    );
    expect(requestSigText(APP, q)).toBe(
      '{"m":"syncdemo-greqsig:3","set":"s","epoch":0,"from":"f","to":"t"}',
    );
    const w = await world(['A', 'B']);
    const r = await rotateGroup({
      appId: APP,
      own: w.own(w.devs[0]!),
      trust: await w.trustOf(w.devs[0]!),
      state: fresh(),
      random: seeded(1),
    });
    if (!r.ok) throw new Error();
    expect(storeGroupState(APP, r.state)).toMatch(
      /^\{"m":"syncdemo-gstate:2","set":"main","floor":0,"keys":\[\{"epoch":1,"author":"[^"]+","key":"[\w-]{43}","audience":\["[^"]+","[^"]+"\]\}\]\}$/,
    );
    const e = await encryptGroup({
      appId: APP,
      state: r.state,
      plaintext: text('x'),
      random: seeded(2),
    });
    expect(e.ok && e.text).toMatch(
      /^\{"m":"syncdemo-gdata:2","set":"main","epoch":1,"kid":"[\w-]{22}","salt":"[\w-]{22}","ct":"[\w-]+"\}$/,
    );
  });

  it('the limits table holds the defaults', () => {
    expect(GROUP_LIMITS).toEqual({
      maxKeys: 64,
      maxPerEpoch: 8,
      maxAudience: 128,
      maxEpochJump: 1000,
      maxPlaintextBytes: 1_048_576,
    });
    expect(DOC).toContain('| `maxKeys`           | 64 ');
    expect(DOC).toContain('| `maxPerEpoch`       | 8 ');
    expect(DOC).toContain('| `maxAudience`       | 128 ');
    expect(DOC).toContain('| `maxEpochJump`      | 1000 ');
    expect(DOC).toContain(`| ${spaced(GROUP_LIMITS.maxPlaintextBytes)} `);
    expect(DOC).toContain('4 294 967 295');
    expect(maxGrantChars(GROUP_LIMITS) * 3).toBeLessThan(200_000);
    expect(maxStateChars(GROUP_LIMITS)).toBeGreaterThan(maxGrantChars(GROUP_LIMITS));
    expect(maxDataChars(GROUP_LIMITS)).toBeGreaterThan(1_398_101);
  });

  it('every refusal code is in the code table', () => {
    for (const code of [
      ...Object.keys(REFUSALS),
      ...Object.keys(ADD),
      ...Object.keys(DECRYPT),
      ...Object.keys(ENCRYPT),
    ]) {
      expect(DOC, code).toContain(`\`${code}\``);
    }
  });

  it('states the honest limits', () => {
    for (const t of [
      'A removed device keeps every key it already held',
      'A compromised trusted device leaks the current key',
      'No forward secrecy',
      'no post-compromise security beyond rotation',
      'Not security-reviewed by a human',
      'AES-GCM is not key-committing',
      'a compromised signer can still issue grants',
      'no forward secrecy',
      'any trusted holder that\n  notices a removal may rotate',
      'No key commitment in `gdata`',
    ]) {
      expect(DOC, t).toContain(t);
    }
  });
});
