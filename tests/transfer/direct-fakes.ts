// A small in-memory pair of WebRTC-like peers: no network, no browser. The description a peer makes names
// its own id; applying the answer at the caller connects the two peers and opens their channels on the next
// microtask turns, as a real connection does after the texts were exchanged.
import type { DataChannelLike, DescriptionLike, PeerLike } from '../../src/transfer/index.ts';

type Listener = (event: unknown) => void;

class Target {
  private readonly listeners = new Map<string, Listener[]>();
  addEventListener(type: string, l: Listener): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), l]);
  }
  removeEventListener(type: string, l: Listener): void {
    this.listeners.set(
      type,
      (this.listeners.get(type) ?? []).filter((x) => x !== l),
    );
  }
  emit(type: string, event: unknown = {}): void {
    for (const l of this.listeners.get(type) ?? []) l(event);
  }
  count(type: string): number {
    return (this.listeners.get(type) ?? []).length;
  }
}

export class FakeChannel extends Target implements DataChannelLike {
  readyState = 'connecting';
  binaryType = 'blob';
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  peerChannel: FakeChannel | undefined;
  readonly sent: Uint8Array[] = [];
  /** When set, sent data is not delivered until `release` is called (a slow link). */
  hold = false;
  private held: Uint8Array[] = [];
  closed = false;

  send(data: Uint8Array): void {
    if (this.readyState !== 'open') throw new Error('InvalidStateError');
    this.sent.push(data.slice());
    if (this.hold) this.held.push(data.slice());
    else this.deliver(data.slice());
  }
  private deliver(data: Uint8Array): void {
    queueMicrotask(() => this.peerChannel?.emit('message', { data: data.buffer }));
  }
  release(): void {
    for (const d of this.held) this.deliver(d);
    this.held = [];
  }
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.readyState = 'closed';
    this.emit('close');
    const other = this.peerChannel;
    if (other && !other.closed) queueMicrotask(() => other.close());
  }
  open(): void {
    this.readyState = 'open';
    this.emit('open');
  }
}

export const WORLD = { peers: new Map<string, FakePeer>(), next: 1 };

export interface FakeOptions {
  /** The candidate line in the description; empty for none. */
  candidates?: string[];
  gatherState?: 'complete' | 'gathering';
  /** Fail the connection when the answer is applied. */
  failIce?: boolean;
}

export class FakePeer extends Target implements PeerLike {
  readonly id = `peer${WORLD.next++}`;
  localDescription: { sdp: string } | null = null;
  iceGatheringState = 'new';
  iceConnectionState = 'new';
  connectionState = 'new';
  channel: FakeChannel | undefined;
  closedCount = 0;
  remoteId: string | undefined;
  statsDelayed = false;

  constructor(readonly o: FakeOptions = {}) {
    super();
    WORLD.peers.set(this.id, this);
  }

  createDataChannel(): FakeChannel {
    this.channel = new FakeChannel();
    return this.channel;
  }

  private description(type: 'offer' | 'answer'): DescriptionLike {
    const candidates = this.o.candidates ?? [
      'a=candidate:1 1 udp 2122260223 192.168.1.20 54321 typ host',
      'a=candidate:2 1 udp 1686052607 203.0.113.9 54321 typ srflx raddr 192.168.1.20 rport 54321',
    ];
    const sdp = [
      'v=0',
      `o=- ${this.id} 2 IN IP4 127.0.0.1`,
      's=-',
      't=0 0',
      'a=group:BUNDLE 0',
      'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
      'c=IN IP4 0.0.0.0',
      'a=ice-ufrag:abcd',
      'a=ice-pwd:0123456789012345678901',
      `a=fingerprint:sha-256 ${Array.from({ length: 32 }, (_, i) => (i * 7 + 11).toString(16).toUpperCase().padStart(2, '0').slice(-2)).join(':')}`,
      `a=setup:${type === 'offer' ? 'actpass' : 'active'}`,
      'a=mid:0',
      'a=sctp-port:5000',
      ...candidates,
    ].join('\r\n');
    return { type, sdp: sdp + '\r\n' };
  }
  createOffer(): Promise<DescriptionLike> {
    return Promise.resolve(this.description('offer'));
  }
  createAnswer(): Promise<DescriptionLike> {
    return Promise.resolve(this.description('answer'));
  }
  setLocalDescription(d: DescriptionLike): Promise<void> {
    this.localDescription = { sdp: d.sdp ?? '' };
    const state = this.o.gatherState ?? 'complete';
    if (state === 'complete') {
      this.iceGatheringState = 'complete';
    } else this.iceGatheringState = 'gathering';
    return Promise.resolve();
  }
  /** Ends gathering (when the fake was told to stay in `gathering`). */
  finishGathering(): void {
    this.iceGatheringState = 'complete';
    this.emit('icegatheringstatechange');
  }
  setRemoteDescription(d: { type: 'offer' | 'answer'; sdp: string }): Promise<void> {
    const m = /^o=- (peer\d+) /m.exec(d.sdp);
    this.remoteId = m?.[1];
    if (d.type === 'answer') {
      const other = WORLD.peers.get(this.remoteId ?? '');
      if (this.o.failIce) {
        queueMicrotask(() => {
          this.iceConnectionState = 'failed';
          this.emit('iceconnectionstatechange');
        });
      } else if (other) this.connect(other);
    }
    return Promise.resolve();
  }

  /** The connection comes up: the callee gets its channel first, then both open. */
  private connect(callee: FakePeer): void {
    const mine = this.channel as FakeChannel;
    const theirs = new FakeChannel();
    mine.peerChannel = theirs;
    theirs.peerChannel = mine;
    queueMicrotask(() => {
      callee.emit('datachannel', { channel: theirs });
      // the callee's side is open first and may write at once, before the caller's `open` event
      theirs.open();
      queueMicrotask(() => {
        mine.open();
        this.iceConnectionState = callee.iceConnectionState = 'connected';
        this.connectionState = callee.connectionState = 'connected';
      });
    });
  }

  getStats(): Promise<{ forEach(cb: (e: Record<string, unknown>) => void): void }> {
    const entries: Record<string, unknown>[] = [
      { id: 'T', type: 'transport', selectedCandidatePairId: 'P' },
      {
        id: 'P',
        type: 'candidate-pair',
        localCandidateId: 'L',
        remoteCandidateId: 'R',
        currentRoundTripTime: 0.012,
      },
      {
        id: 'L',
        type: 'local-candidate',
        candidateType: 'host',
        address: '192.168.1.20',
        protocol: 'udp',
      },
      { id: 'R', type: 'remote-candidate', candidateType: 'host', address: '192.168.1.30' },
    ];
    const r = { forEach: (cb: (e: Record<string, unknown>) => void) => entries.forEach(cb) };
    return this.statsDelayed
      ? new Promise((resolve) => setTimeout(() => resolve(r), 20))
      : Promise.resolve(r);
  }

  close(): void {
    this.closedCount++;
    this.channel?.close();
  }
}

/** Lets pending microtasks (and the chain of them the fake connection uses) run. */
export async function settle(n = 20): Promise<void> {
  for (let i = 0; i < n; i++) await Promise.resolve();
}
