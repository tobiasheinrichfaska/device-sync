// Round 5 review of the end-to-end layer: findings turned into tests (each failed before its fix).
import { describe, expect, it } from 'vitest';
import { openSession, publicKeys, sealEnvelope } from '../../src/core/index.ts';
import { DAY, APP, member, seededRandom } from './envelope-helpers.ts';

describe('round 5: unusable keys are refused with the documented code', () => {
  it('a signing key that cannot sign is bad-author, not crypto-failure', async () => {
    const a = await member('author-a');
    const r = await member('reader-r');
    const make = (signing: CryptoKey) =>
      sealEnvelope({
        appId: APP,
        author: { device: a.device, signing },
        recipients: [r.dh],
        channel: 'chan',
        day: DAY,
        body: new Uint8Array(3),
        random: seededRandom(1),
      });
    // a public half, an agreement key and a symmetric key cannot sign
    for (const key of [
      a.keys.signing.publicKey,
      a.keys.agreement.privateKey,
      await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']),
    ]) {
      expect(await make(key)).toEqual({ ok: false, reason: 'bad-author' });
    }
    expect((await make(a.keys.signing.privateKey)).ok).toBe(true);
  });
});

describe('round 5: the ephemeral key is never the static key', () => {
  it('a session whose "ephemeral" pair is the static agreement pair is refused', async () => {
    const a = await member('device-a');
    const b = await member('device-b');
    const pa = await publicKeys(a.keys);
    const pb = await publicKeys(b.keys);
    // forward secrecy would be gone without a word: the "ephemeral" terms would be static ones
    const r = await openSession({
      appId: APP,
      own: { device: a.device, agreement: a.keys.agreement },
      peer: { device: b.device, dh: pb.dh },
      ephemeral: a.keys.agreement,
      ownHello: { device: a.device, eph: pa.dh },
      peerHello: { device: b.device, eph: pb.sig },
    });
    expect(r).toEqual({ ok: false, reason: 'bad-own' });
  });
});
