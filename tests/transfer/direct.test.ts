import { describe, expect, it } from 'vitest';
import {
  TRANSFER_LIMITS as L,
  chunkMessage,
  createDirect,
  type DirectConnection,
  type DirectOptions,
  type DirectReason,
  type TransferResult,
} from '../../src/transfer/index.ts';
import { VirtualTime } from '../browser/fakes.ts';
import { FakeChannel, FakePeer, settle, type FakeOptions } from './direct-fakes.ts';
import { APP, bytes } from './helpers.ts';

const SESSION = '0123456789abcdef';

interface Side {
  c: DirectConnection;
  peer: FakePeer;
}

function make(
  role: 'caller' | 'callee',
  time: VirtualTime,
  fake: FakeOptions = {},
  extra: Partial<DirectOptions> = {},
): Side {
  let peer!: FakePeer;
  const r = createDirect({
    appId: APP,
    role,
    session: role === 'caller' ? SESSION : undefined,
    createPeer: () => (peer = new FakePeer(fake)),
    timers: time,
    clock: time.clock,
    ...extra,
  });
  if (!r.ok) throw new Error(r.reason);
  return { c: r.value, peer };
}

const val = <T>(r: TransferResult<T, DirectReason>): T => {
  if (!r.ok) throw new Error(r.reason);
  return r.value;
};

async function connect(
  time: VirtualTime,
  fake: FakeOptions = {},
): Promise<{ caller: Side; callee: Side }> {
  const caller = make('caller', time, fake);
  const callee = make('callee', time, fake);
  const offer = val(await caller.c.makeOffer());
  const answer = val(await callee.c.acceptOffer(offer));
  val(await caller.c.acceptAnswer(answer));
  expect(await caller.c.opened()).toEqual({ ok: true, value: null });
  expect(await callee.c.opened()).toEqual({ ok: true, value: null });
  return { caller, callee };
}

describe('the handshake through the adapter', () => {
  it('two peers exchange the texts, open the channel and talk both ways', async () => {
    const time = new VirtualTime();
    const { caller, callee } = await connect(time);
    expect(caller.c.status().phase).toBe('open');
    expect(callee.c.status().phase).toBe('open');
    expect(await caller.c.send(Uint8Array.of(1, 2, 3))).toEqual({ ok: true, value: null });
    expect(await callee.c.receive(1000)).toEqual({ ok: true, value: Uint8Array.of(1, 2, 3) });
    await callee.c.send(Uint8Array.of(9));
    expect(await caller.c.receive(1000)).toEqual({ ok: true, value: Uint8Array.of(9) });
  });

  it('a message that arrives before anybody reads is kept (the early ping of an earlier implementation)', async () => {
    const time = new VirtualTime();
    const { caller, callee } = await connect(time);
    // the callee writes at once; the caller reads much later
    await callee.c.send(Uint8Array.of(7));
    await callee.c.send(Uint8Array.of(8));
    await settle();
    expect(await caller.c.receive(10)).toEqual({ ok: true, value: Uint8Array.of(7) });
    expect(await caller.c.receive(10)).toEqual({ ok: true, value: Uint8Array.of(8) });
  });

  it('the callee listens for the channel before it applies the offer, and statistics read slowly do not lose a ping', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time);
    const callee = make('callee', time);
    callee.peer.statsDelayed = true;
    const answer = val(await callee.c.acceptOffer(val(await caller.c.makeOffer())));
    expect(callee.peer.count('datachannel')).toBe(1);
    val(await caller.c.acceptAnswer(answer));
    await caller.c.opened();
    await caller.c.send(Uint8Array.of(1));
    const slow = callee.c.path();
    expect(await callee.c.receive(100)).toEqual({ ok: true, value: Uint8Array.of(1) });
    expect(await slow).toBeDefined();
  });

  it('large messages are chunked and put together again, in order, also when sent at once', async () => {
    const time = new VirtualTime();
    const { caller, callee } = await connect(time);
    const a = bytes(100_000, 1);
    const b = bytes(40_000, 2);
    const c = new Uint8Array(0);
    await Promise.all([caller.c.send(a), caller.c.send(b), caller.c.send(c)]);
    expect(val(await callee.c.receive(100))).toEqual(a);
    expect(val(await callee.c.receive(100))).toEqual(b);
    expect(val(await callee.c.receive(100))).toEqual(c);
    const sent = (caller.peer.channel as FakeChannel).sent;
    expect(sent.every((x) => x.length <= L.chunkBytes)).toBe(true);
    // chunks of one message are never interleaved with another
    const ids = sent.map((x) => new DataView(x.buffer).getUint32(1));
    expect(ids).toEqual([...ids].sort((x, y) => x - y));
  });

  it('a message over the limit is refused before anything is sent', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    const before = (caller.peer.channel as FakeChannel).sent.length;
    expect(await caller.c.send(new Uint8Array(L.messageBytesMax + 1))).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect((caller.peer.channel as FakeChannel).sent.length).toBe(before);
    expect(await caller.c.send(new Uint8Array(L.messageBytesMax))).toEqual({
      ok: true,
      value: null,
    });
  });

  it('reads the path from the statistics', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    expect(await caller.c.path()).toMatchObject({
      local: { type: 'host', scope: 'local' },
      protocol: 'udp',
      rttMs: 12,
    });
  });
});

describe('texts that do not fit', () => {
  it('another app, a wrong role and a wrong session are refused and change nothing', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time);
    const callee = make('callee', time);
    const stranger = make('callee', time, {}, { appId: 'other' });
    const offer = val(await caller.c.makeOffer());
    expect(await stranger.c.acceptOffer(offer)).toEqual({ ok: false, reason: 'bad-marker' });
    // an offer given to the caller as if it were the answer
    expect(await caller.c.acceptAnswer(offer)).toEqual({ ok: false, reason: 'wrong-role' });
    expect(caller.c.status().phase).toBe('awaiting-answer');
    // an answer of another session
    const other = make('caller', time, {}, { session: 'fedcba9876543210' });
    const answerToOther = val(await callee.c.acceptOffer(val(await other.c.makeOffer())));
    expect(await caller.c.acceptAnswer(answerToOther)).toEqual({
      ok: false,
      reason: 'wrong-session',
    });
    expect(caller.c.status().phase).toBe('awaiting-answer');
    expect(await caller.c.acceptAnswer('junk')).toMatchObject({ ok: false });
    // the honest answer still works afterwards
    const callee2 = make('callee', time);
    const answer = val(await callee2.c.acceptOffer(offer));
    expect(await caller.c.acceptAnswer(answer)).toEqual({ ok: true, value: null });
    expect((await caller.c.opened()).ok).toBe(true);
  });

  it('the callee refuses an answer as its first text', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time);
    const callee = make('callee', time);
    const callee2 = make('callee', time);
    const answer = val(await callee2.c.acceptOffer(val(await caller.c.makeOffer())));
    expect(await callee.c.acceptOffer(answer)).toEqual({ ok: false, reason: 'wrong-role' });
    expect(callee.c.status().phase).toBe('awaiting-offer');
  });

  it('wrong role of the adapter gives bad-state', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time);
    const callee = make('callee', time);
    expect(await callee.c.makeOffer()).toEqual({ ok: false, reason: 'bad-state' });
    expect(await caller.c.acceptOffer('x')).toEqual({ ok: false, reason: 'bad-state' });
    expect(await callee.c.acceptAnswer('x')).toEqual({ ok: false, reason: 'bad-state' });
    expect(caller.c.wait()).toEqual({ ok: false, reason: 'bad-state' });
  });
});

describe('timeouts and failures', () => {
  it('the callee gives up waiting for an offer; the peer is closed and waiters hear the reason', async () => {
    const time = new VirtualTime();
    const callee = make('callee', time, {}, { handshake: { offerMs: 1000 } });
    expect(callee.c.wait().ok).toBe(true);
    const opened = callee.c.opened();
    const received = callee.c.receive(100_000);
    time.advanceTo(999);
    expect(callee.c.status().phase).toBe('awaiting-offer');
    time.advanceTo(1000);
    expect(await opened).toEqual({ ok: false, reason: 'offer-timeout' });
    expect(await received).toEqual({ ok: false, reason: 'closed' });
    expect(callee.c.status()).toMatchObject({ phase: 'failed', failure: 'offer-timeout' });
    expect(callee.peer.closedCount).toBeGreaterThan(0);
  });

  it('the caller gives up waiting for an answer', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time, {}, { handshake: { answerMs: 500 } });
    val(await caller.c.makeOffer());
    time.advanceTo(500);
    expect(caller.c.status()).toMatchObject({ phase: 'failed', failure: 'answer-timeout' });
    expect(await caller.c.acceptAnswer('x')).toMatchObject({ ok: false });
  });

  it('no connection after the texts ends as connect-timeout', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time, {}, { handshake: { connectMs: 700 } });
    const callee = make('callee', time);
    const answer = val(await callee.c.acceptOffer(val(await caller.c.makeOffer())));
    WORLD_DROP(caller);
    val(await caller.c.acceptAnswer(answer));
    time.advanceTo(time.now + 700);
    expect(caller.c.status()).toMatchObject({ phase: 'failed', failure: 'connect-timeout' });
  });

  it('candidates are awaited for gatherWaitMs, then the description is taken as it is', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time, { gatherState: 'gathering' });
    const offer = caller.c.makeOffer();
    await settle();
    expect(caller.c.status().phase).toBe('gathering');
    time.advanceTo(5_000);
    expect((await offer).ok).toBe(true);
    expect(caller.c.status().phase).toBe('awaiting-answer');
  });

  it('finished gathering is noticed before the wait is over', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time, { gatherState: 'gathering' });
    const offer = caller.c.makeOffer();
    await settle();
    caller.peer.finishGathering();
    expect((await offer).ok).toBe(true);
    expect(time.now).toBe(0);
  });

  it('a description without any candidate is a failure, not an unusable text', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time, { candidates: [] });
    expect(await caller.c.makeOffer()).toEqual({ ok: false, reason: 'no-candidates' });
    expect(caller.c.status()).toMatchObject({ phase: 'failed', failure: 'setup-failed' });
  });

  it('a failed ICE ends the handshake with ice-failed', async () => {
    const time = new VirtualTime();
    const caller = make('caller', time, { failIce: true });
    const callee = make('callee', time);
    val(
      await caller.c.acceptAnswer(val(await callee.c.acceptOffer(val(await caller.c.makeOffer())))),
    );
    expect(await caller.c.opened()).toEqual({ ok: false, reason: 'ice-failed' });
  });

  it('the other side closing ends an open connection as closed', async () => {
    const time = new VirtualTime();
    const { caller, callee } = await connect(time);
    const pending = caller.c.receive(60_000);
    callee.c.close();
    await settle();
    expect(await pending).toEqual({ ok: false, reason: 'closed' });
    expect(caller.c.status().phase).toBe('closed');
    expect(caller.c.closeReason()).toBe('peer-closed');
    expect(callee.c.closeReason()).toBe('cancelled');
    expect(await caller.c.send(Uint8Array.of(1))).toEqual({ ok: false, reason: 'not-open' });
  });

  it('close is safe twice and after a failure; late events change nothing', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    caller.c.close();
    caller.c.close();
    caller.peer.channel?.emit('open');
    caller.peer.emit('iceconnectionstatechange');
    expect(caller.c.status().phase).toBe('closed');
  });

  it('a receive that waits too long answers timeout and does not consume a later message', async () => {
    const time = new VirtualTime();
    const { caller, callee } = await connect(time);
    const r = caller.c.receive(50);
    time.advanceTo(time.now + 50);
    expect(await r).toEqual({ ok: false, reason: 'timeout' });
    await callee.c.send(Uint8Array.of(5));
    await settle();
    expect(await caller.c.receive(50)).toEqual({ ok: true, value: Uint8Array.of(5) });
  });
});

describe('what the other side may send', () => {
  it('a broken chunk closes the connection as a protocol violation', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    (caller.peer.channel as FakeChannel).emit('message', {
      data: Uint8Array.of(9, 9).buffer,
    });
    await settle();
    expect(caller.c.status().phase).toBe('closed');
    expect(caller.c.closeReason()).toBe('protocol');
  });

  it('a chunk out of order closes it too', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    const chunks = val(chunkMessage(1, new Uint8Array(40_000)));
    const ch = caller.peer.channel as FakeChannel;
    ch.emit('message', { data: (chunks[0] as Uint8Array).slice().buffer });
    ch.emit('message', { data: (chunks[2] as Uint8Array).slice().buffer });
    expect(caller.c.closeReason()).toBe('protocol');
  });

  it('text messages are ignored', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    (caller.peer.channel as FakeChannel).emit('message', { data: '{"t":"ping"}' });
    expect(caller.c.status().phase).toBe('open');
  });

  it('more unread messages than the inbox holds close the connection as overflow', async () => {
    const time = new VirtualTime();
    const { caller, callee } = await connect(time);
    for (let i = 0; i < L.inboxMax; i++) await callee.c.send(Uint8Array.of(i & 255));
    await settle();
    expect(caller.c.status().phase).toBe('open');
    await callee.c.send(Uint8Array.of(1));
    await settle();
    expect(caller.c.closeReason()).toBe('overflow');
  });
});

describe('sending into a slow link', () => {
  it('waits for the buffer to drain above the high-water mark, then goes on', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    const ch = caller.peer.channel as FakeChannel;
    ch.bufferedAmount = L.highWaterBytes + 1;
    let done = false;
    const sending = caller.c.send(Uint8Array.of(1)).then((r) => {
      done = true;
      return r;
    });
    await settle();
    expect(done).toBe(false);
    expect(ch.bufferedAmountLowThreshold).toBe(L.lowWaterBytes);
    ch.bufferedAmount = 0;
    ch.emit('bufferedamountlow');
    expect(await sending).toEqual({ ok: true, value: null });
  });

  it('gives up after sendTimeoutMs, and when the channel closes meanwhile', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    const ch = caller.peer.channel as FakeChannel;
    ch.bufferedAmount = L.highWaterBytes + 1;
    const sending = caller.c.send(Uint8Array.of(1));
    await settle();
    time.advanceTo(time.now + 60_000);
    expect(await sending).toEqual({ ok: false, reason: 'send-timeout' });
    const second = caller.c.send(Uint8Array.of(1));
    await settle();
    caller.c.close();
    expect((await second).ok).toBe(false);
  });

  it('drain waits until everything left the device (closing earlier drops what still waits)', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    const ch = caller.peer.channel as FakeChannel;
    ch.bufferedAmount = 5000;
    let drained = false;
    const d = caller.c.drain().then((r) => {
      drained = true;
      return r;
    });
    await settle();
    expect(drained).toBe(false);
    expect(ch.bufferedAmountLowThreshold).toBe(0);
    ch.bufferedAmount = 0;
    ch.emit('bufferedamountlow');
    expect(await d).toEqual({ ok: true, value: null });
    expect(await caller.c.drain()).toEqual({ ok: true, value: null });
  });

  it('a send that throws is reported as send-failed', async () => {
    const time = new VirtualTime();
    const { caller } = await connect(time);
    const ch = caller.peer.channel as FakeChannel;
    ch.send = () => {
      throw new Error('boom');
    };
    expect(await caller.c.send(Uint8Array.of(1))).toEqual({ ok: false, reason: 'send-failed' });
  });
});

describe('configuration', () => {
  const base = (): DirectOptions => {
    const time = new VirtualTime();
    return {
      appId: APP,
      role: 'caller',
      session: SESSION,
      createPeer: () => new FakePeer(),
      timers: time,
      clock: time.clock,
    };
  };
  it('refuses what cannot work, with codes', () => {
    expect(createDirect({ ...base(), appId: 'No' })).toEqual({ ok: false, reason: 'bad-app-id' });
    expect(createDirect({ ...base(), session: 'XYZ' })).toEqual({
      ok: false,
      reason: 'bad-session',
    });
    expect(createDirect({ ...base(), session: undefined })).toEqual({
      ok: false,
      reason: 'bad-session',
    });
    expect(createDirect({ ...base(), stunUrls: ['http://x'] })).toEqual({
      ok: false,
      reason: 'bad-stun',
    });
    expect(
      createDirect({
        ...base(),
        stunUrls: ['stun:a.b:3478', 'stun:c', 'stun:d', 'stun:e', 'stun:f'],
      }),
    ).toEqual({
      ok: false,
      reason: 'bad-stun',
    });
    expect(createDirect({ ...base(), handshake: { connectMs: 0 } })).toEqual({
      ok: false,
      reason: 'bad-config',
    });
    expect(createDirect({ ...base(), gatherWaitMs: 15_000 })).toEqual({
      ok: false,
      reason: 'bad-config',
    });
    expect(createDirect({ ...base(), role: 'x' as 'caller' })).toEqual({
      ok: false,
      reason: 'bad-config',
    });
    expect(
      createDirect({
        ...base(),
        createPeer: () => {
          throw new Error('no RTC');
        },
      }),
    ).toEqual({
      ok: false,
      reason: 'bad-config',
    });
    expect(createDirect(null as unknown as DirectOptions)).toEqual({
      ok: false,
      reason: 'bad-config',
    });
  });

  it('passes the STUN servers on and nothing else of the network', () => {
    let seen: unknown;
    const o = {
      ...base(),
      stunUrls: ['stun:stun.example.org:3478'],
      createPeer: (c: unknown) => ((seen = c), new FakePeer()),
    };
    expect(createDirect(o).ok).toBe(true);
    expect(seen).toEqual({ iceServers: [{ urls: ['stun:stun.example.org:3478'] }] });
    const o2 = { ...base(), createPeer: (c: unknown) => ((seen = c), new FakePeer()) };
    createDirect(o2);
    expect(seen).toEqual({ iceServers: [] });
  });
});

/** Makes the fake connection never come up (the answer is applied but nothing connects). */
function WORLD_DROP(side: Side): void {
  side.peer.setRemoteDescription = () => Promise.resolve();
}
