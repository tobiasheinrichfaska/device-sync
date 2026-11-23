// Round 5 review of the transfer layer: a description with a line break inside a "line" (smuggled media
// section), several different DTLS fingerprints, and an inbox bounded by bytes, not only by count.
import { describe, expect, it } from 'vitest';
import {
  TRANSFER_LIMITS as L,
  candidatesOfSdp,
  chunkMessage,
  createDirect,
  fingerprintsOf,
  readDirectText,
  readSdp,
  writeDirectText,
  type DirectConnection,
  type DirectReason,
  type TransferResult,
} from '../../src/transfer/index.ts';
import { VirtualTime } from '../browser/fakes.ts';
import { FakeChannel, FakePeer, settle } from './direct-fakes.ts';
import { APP } from './helpers.ts';

const head = ['v=0', 'o=- 1 2 IN IP4 127.0.0.1', 's=-', 't=0 0'];
const media = 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel';
const fp = (n: string): string => `a=fingerprint:sha-256 ${n}`;
const sdpOf = (lines: string[]): string => lines.join('\r\n') + '\r\n';

describe('round 5: the description reader', () => {
  const good = sdpOf([
    ...head,
    media,
    'c=IN IP4 0.0.0.0',
    fp('AA:BB'),
    'a=candidate:1 1 udp 1 10.0.0.1 9 typ host',
  ]);

  it('the plain description passes', () => {
    expect(readSdp(good).ok).toBe(true);
  });

  it('a bare line feed inside a line cannot smuggle in another media section', () => {
    const smuggled = sdpOf([...head, 'a=x\nm=video 9 UDP/TLS/RTP/SAVPF 96', media, fp('AA:BB')]);
    expect(readSdp(smuggled)).toEqual({ ok: false, reason: 'bad-sdp' });
    const smuggled2 = sdpOf([...head, 'a=x\nm=audio 9 UDP/TLS/RTP/SAVPF 111', media, fp('AA:BB')]);
    expect(readSdp(smuggled2).ok).toBe(false);
  });

  it('a bare carriage return inside a line is refused too', () => {
    expect(readSdp(sdpOf([...head, 'a=x\rm=video 9 RTP/AVP 0', media, fp('AA:BB')])).ok).toBe(
      false,
    );
  });

  it('a line feed cannot hide an unchecked fingerprint line', () => {
    expect(readSdp(sdpOf([...head, media, fp('AA:BB'), 'a=x\na=fingerprint:sha-256 zz'])).ok).toBe(
      false,
    );
  });

  it('the text reader refuses the same description', () => {
    const smuggled = sdpOf([...head, 'a=x\nm=video 9 RTP/AVP 0', media, fp('AA:BB')]);
    const body = Buffer.from(smuggled).toString('base64url');
    expect(readDirectText(APP, `${APP}-direct:1.offer.0123456789abcdef.${body}`)).toEqual({
      ok: false,
      reason: 'bad-sdp',
    });
    expect(
      writeDirectText(APP, { role: 'offer', session: '0123456789abcdef', sdp: smuggled }).ok,
    ).toBe(false);
  });

  it('two different fingerprints are refused, the same one repeated is fine', () => {
    expect(readSdp(sdpOf([...head, media, fp('AA:BB'), fp('CC:DD')])).ok).toBe(false);
    expect(readSdp(sdpOf([...head, fp('AA:BB'), media, fp('aa:bb')])).ok).toBe(true);
    expect(fingerprintsOf(sdpOf([...head, media, fp('aa:bb')]))).toEqual(['SHA-256 AA:BB']);
    expect(candidatesOfSdp(good)).toHaveLength(1);
  });
});

describe('round 5: the inbox is bounded by bytes', () => {
  async function connect(time: VirtualTime) {
    const mk = (role: 'caller' | 'callee') => {
      let peer!: FakePeer;
      const r = createDirect({
        appId: APP,
        role,
        session: role === 'caller' ? '0123456789abcdef' : undefined,
        createPeer: () => (peer = new FakePeer({})),
        timers: time,
        clock: time.clock,
      });
      if (!r.ok) throw new Error(r.reason);
      return { c: r.value as DirectConnection, peer };
    };
    const val = <T>(r: TransferResult<T, DirectReason>): T => {
      if (!r.ok) throw new Error(r.reason);
      return r.value;
    };
    const caller = mk('caller');
    const callee = mk('callee');
    const offer = val(await caller.c.makeOffer());
    const answer = val(await callee.c.acceptOffer(offer));
    val(await caller.c.acceptAnswer(answer));
    await caller.c.opened();
    await callee.c.opened();
    return { caller, callee };
  }

  it('unread messages cost at most inboxBytesMax, then the connection closes as overflow', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    const ch = caller.peer.channel as FakeChannel;
    const big = new Uint8Array(L.messageBytesMax); // 4 MiB each; 256 of them would be 1 GiB
    let delivered = 0;
    for (let i = 0; i < 256 && caller.c.closeReason() === undefined; i++) {
      const chunks = chunkMessage(i, big);
      if (!chunks.ok) throw new Error('chunk');
      for (const c of chunks.value) ch.emit('message', { data: c.slice().buffer });
      delivered += big.length;
    }
    await settle();
    expect(caller.c.closeReason()).toBe('overflow');
    expect(delivered).toBeLessThanOrEqual(L.inboxBytesMax + L.messageBytesMax);
  });
});
