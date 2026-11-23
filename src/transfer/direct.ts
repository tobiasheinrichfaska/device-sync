// A thin adapter between the handshake state machine and a WebRTC-like peer. Nothing global is used: the
// peer factory, the timers and the clock are parameters, so a browser, a WebView and a test with a fake
// peer pair run the same code. The data channel carries opaque messages, chunked and put together with
// limits. Receiving starts the moment the channel exists (a message that arrives before anybody reads is
// kept in a bounded inbox, never lost: a ping that came while the other side still read its statistics
// was lost in an earlier implementation).
import type { TimerLike } from '../browser/listener.ts';
import { ChunkAssembler, chunkMessage, type ChunkReason } from './chunks.ts';
import { chosenPath, candidatesOfSdp, type ChosenPath } from './direct-network.ts';
import {
  HANDSHAKE_DEFAULTS,
  directStep,
  handshakeConfigProblem,
  initialState,
  type DirectEvent,
  type DirectFailure,
  type DirectState,
  type HandshakeConfig,
  type DirectRefusal,
} from './direct-handshake.ts';
import {
  readDirectText,
  readSdp,
  writeDirectText,
  type DirectRole,
  type TextReason,
} from './direct-text.ts';
import { domainBytes } from './check.ts';
import { TRANSFER_LIMITS as L, fail, pass, type TransferResult } from './limits.ts';

export interface EventTargetLike {
  addEventListener(type: string, listener: (event: unknown) => void): void;
  removeEventListener(type: string, listener: (event: unknown) => void): void;
}

/** `RTCDataChannel`, as far as it is used here. */
export interface DataChannelLike extends EventTargetLike {
  readonly readyState: string;
  binaryType: string;
  readonly bufferedAmount: number;
  bufferedAmountLowThreshold: number;
  send(data: Uint8Array<ArrayBuffer>): void;
  close(): void;
}

export interface DescriptionLike {
  /** The same words as `RTCSdpType`, so a real `RTCPeerConnection` fits `PeerLike` without a cast. */
  readonly type?: 'offer' | 'answer' | 'pranswer' | 'rollback';
  readonly sdp?: string;
}

/** `RTCPeerConnection`, as far as it is used here. */
export interface PeerLike extends EventTargetLike {
  readonly localDescription: { readonly sdp?: string } | null;
  readonly iceGatheringState: string;
  readonly iceConnectionState: string;
  readonly connectionState: string;
  createDataChannel(label: string, init?: { ordered?: boolean }): DataChannelLike;
  createOffer(): Promise<DescriptionLike>;
  createAnswer(): Promise<DescriptionLike>;
  setLocalDescription(description: DescriptionLike): Promise<void>;
  setRemoteDescription(description: { type: 'offer' | 'answer'; sdp: string }): Promise<void>;
  getStats(): Promise<{ forEach(callback: (entry: Record<string, unknown>) => void): void }>;
  close(): void;
}

export type DirectReason =
  | TextReason
  | DirectRefusal
  | DirectFailure
  | ChunkReason
  | 'bad-state'
  | 'no-candidates'
  | 'closed'
  | 'timeout'
  | 'not-open'
  | 'send-failed'
  | 'send-timeout';

export type DirectClosed = 'cancelled' | 'protocol' | 'overflow' | 'peer-closed';

export interface DirectOptions {
  readonly appId: string;
  readonly role: 'caller' | 'callee';
  /** Makes the peer; in a browser `(config) => new RTCPeerConnection(config)`. */
  readonly createPeer: (config: { iceServers: { urls: string[] }[] }) => PeerLike;
  /** STUN servers, `stun:host[:port]` or `stuns:host[:port]` (default none: the same network only). */
  readonly stunUrls?: readonly string[];
  readonly timers: TimerLike;
  /** Milliseconds on a clock that never jumps back (`performance.now`). */
  readonly clock: () => number;
  /** The caller's session id: 16 lower-case hex characters, drawn by the caller. */
  readonly session?: string | undefined;
  readonly handshake?: Partial<HandshakeConfig>;
  /** How long to wait for candidates before the description is taken as it is (default 5000). */
  readonly gatherWaitMs?: number;
  /** Longest wait for the send buffer to drain (default 60000). */
  readonly sendTimeoutMs?: number;
}

const STUN = /^stuns?:[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$/;

type Result<T> = TransferResult<T, DirectReason>;

interface Waiter {
  resolve: (r: Result<null>) => void;
}
interface Reader {
  resolve: (r: Result<Uint8Array>) => void;
  handle: unknown;
}

export class DirectConnection {
  private state: DirectState;
  private readonly peer: PeerLike;
  private readonly cfg: HandshakeConfig;
  private channel: DataChannelLike | undefined;
  private readonly assembler = new ChunkAssembler();
  private readonly inbox: Uint8Array[] = [];
  private inboxBytes = 0;
  private readers: Reader[] = [];
  private openWaiters: Waiter[] = [];
  private deadlineHandle: unknown;
  private nextId = 0;
  private sendChain: Promise<unknown> = Promise.resolve();
  private closedWhy: DirectClosed | undefined;
  private stepping = false;

  constructor(
    private readonly o: DirectOptions,
    peer: PeerLike,
    cfg: HandshakeConfig,
  ) {
    this.peer = peer;
    this.cfg = cfg;
    this.state = initialState(o.role);
    const onIce = (): void => {
      if (peer.iceConnectionState === 'failed' || peer.connectionState === 'failed')
        this.step({ t: 'ice-failed' });
    };
    peer.addEventListener('iceconnectionstatechange', onIce);
    peer.addEventListener('connectionstatechange', onIce);
  }

  status(): DirectState {
    return this.state;
  }

  /** Why the connection ended without a failure (cancelled, protocol violation, inbox overflow, peer left). */
  closeReason(): DirectClosed | undefined {
    return this.closedWhy;
  }

  private step(event: DirectEvent): Result<null> {
    if (this.stepping) return fail('bad-state');
    this.stepping = true;
    try {
      const before = this.state.phase;
      const r = directStep(this.state, event, this.cfg);
      this.state = r.state;
      if (r.refusal) return fail(r.refusal);
      if (this.state.phase !== before || event.t === 'tick') this.afterChange();
      return pass(null);
    } finally {
      this.stepping = false;
    }
  }

  private afterChange(): void {
    if (this.deadlineHandle !== undefined) this.o.timers.clear(this.deadlineHandle);
    this.deadlineHandle = undefined;
    const s = this.state;
    if (s.phase === 'failed' || s.phase === 'closed') {
      this.shutdown();
      return;
    }
    if (s.deadline !== undefined) {
      const ms = Math.max(0, s.deadline - this.o.clock());
      this.deadlineHandle = this.o.timers.set(
        () => this.step({ t: 'tick', now: this.o.clock() }),
        ms,
      );
    }
    if (s.phase === 'open') {
      const w = this.openWaiters;
      this.openWaiters = [];
      for (const x of w) x.resolve(pass(null));
    }
  }

  private shutdown(): void {
    for (const f of [() => this.channel?.close(), () => this.peer.close()]) {
      try {
        f();
      } catch {
        // closing twice or on a dead peer is fine
      }
    }
    const why: DirectReason = this.state.failure ?? 'closed';
    const w = this.openWaiters;
    this.openWaiters = [];
    for (const x of w) x.resolve(fail(why));
    const rs = this.readers;
    this.readers = [];
    for (const r of rs) {
      this.o.timers.clear(r.handle);
      r.resolve(fail('closed'));
    }
  }

  /** Ends the connection on purpose (or because the other side broke the rules). */
  close(why: DirectClosed = 'cancelled'): void {
    this.closedWhy ??= why;
    this.step({ t: 'cancel' });
  }

  private fromState(): DirectReason {
    return this.state.failure ?? 'closed';
  }

  private wire(channel: DataChannelLike): void {
    if (this.channel) return;
    this.channel = channel;
    channel.binaryType = 'arraybuffer';
    channel.addEventListener('message', (ev) => this.onMessage(ev));
    channel.addEventListener('open', () => this.channelOpened());
    channel.addEventListener('close', () => {
      this.closedWhy ??= 'peer-closed';
      this.step({ t: 'channel-closed' });
    });
    this.channelOpened();
  }

  /** A channel that opened before the handshake reached `connecting` is noticed when it does. */
  private channelOpened(): void {
    if (this.state.phase === 'connecting' && this.channel?.readyState === 'open')
      this.step({ t: 'channel-open', now: this.o.clock() });
  }

  private onMessage(ev: unknown): void {
    const data = (ev as { data?: unknown } | null)?.data;
    let bytes: Uint8Array | undefined;
    if (data instanceof ArrayBuffer) bytes = new Uint8Array(data);
    else if (ArrayBuffer.isView(data))
      bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (!bytes) return; // text messages are not part of this protocol
    const r = this.assembler.push(bytes);
    if (!r.ok) {
      this.close('protocol');
      return;
    }
    if (!r.value) return;
    const reader = this.readers.shift();
    if (reader) {
      this.o.timers.clear(reader.handle);
      reader.resolve(pass(r.value));
    } else if (
      this.inbox.length >= L.inboxMax ||
      this.inboxBytes + r.value.length > L.inboxBytesMax
    )
      this.close('overflow');
    else {
      this.inbox.push(r.value);
      this.inboxBytes += r.value.length;
    }
  }

  private gather(): Promise<string> {
    return new Promise((resolve) => {
      let handle: unknown;
      const done = (): void => {
        this.o.timers.clear(handle);
        this.peer.removeEventListener('icegatheringstatechange', check);
        resolve(this.peer.localDescription?.sdp ?? '');
      };
      const check = (): void => {
        if (this.peer.iceGatheringState === 'complete') done();
      };
      this.peer.addEventListener('icegatheringstatechange', check);
      handle = this.o.timers.set(done, this.o.gatherWaitMs ?? 5_000);
      check();
    });
  }

  /** Callee: starts waiting for an offer text (`offerMs`). Optional: `acceptOffer` starts by itself. */
  wait(): Result<null> {
    if (this.o.role !== 'callee') return fail('bad-state');
    return this.step({ t: 'begin', now: this.o.clock() });
  }

  /** Caller: the offer text to hand to the other device. */
  async makeOffer(): Promise<Result<string>> {
    if (this.o.role !== 'caller') return fail('bad-state');
    const b = this.step({ t: 'begin', now: this.o.clock(), session: this.o.session as string });
    if (!b.ok) return b;
    return this.describe('offer');
  }

  /** Callee: takes the offer text and makes the answer text. */
  async acceptOffer(text: string): Promise<Result<string>> {
    if (this.o.role !== 'callee') return fail('bad-state');
    if (this.state.phase === 'idle') this.step({ t: 'begin', now: this.o.clock() });
    const t = readDirectText(this.o.appId, text);
    if (!t.ok) return t;
    const r = this.step({ t: 'remote-text', now: this.o.clock(), text: t.value });
    if (!r.ok) return r;
    // Listen before anything else happens: the caller may open the channel at once.
    this.peer.addEventListener('datachannel', (ev) => {
      const ch = (ev as { channel?: DataChannelLike } | null)?.channel;
      if (ch) this.wire(ch);
    });
    try {
      await this.peer.setRemoteDescription({ type: 'offer', sdp: t.value.sdp });
      if (this.state.phase !== 'gathering') return fail(this.fromState());
      await this.peer.setLocalDescription(await this.peer.createAnswer());
    } catch {
      return this.setupFailed();
    }
    return this.describe('answer');
  }

  /** Caller: takes the answer text and starts connecting. */
  async acceptAnswer(text: string): Promise<Result<null>> {
    if (this.o.role !== 'caller') return fail('bad-state');
    const t = readDirectText(this.o.appId, text);
    if (!t.ok) return t;
    const r = this.step({ t: 'remote-text', now: this.o.clock(), text: t.value });
    if (!r.ok) return r;
    try {
      await this.peer.setRemoteDescription({ type: 'answer', sdp: t.value.sdp });
    } catch {
      this.step({ t: 'ice-failed' });
      return fail('ice-failed');
    }
    this.channelOpened();
    return pass(null);
  }

  private setupFailed(): Result<never> {
    this.step({ t: 'setup-failed' });
    return fail(this.state.failure ?? 'setup-failed');
  }

  private async describe(role: DirectRole): Promise<Result<string>> {
    try {
      if (role === 'offer') {
        this.wire(this.peer.createDataChannel('data', { ordered: true }));
        await this.peer.setLocalDescription(await this.peer.createOffer());
      }
    } catch {
      return this.setupFailed();
    }
    const sdp = await this.gather();
    if (this.state.phase !== 'gathering') return fail(this.fromState());
    const ok = readSdp(sdp);
    if (!ok.ok) {
      this.step({ t: 'setup-failed' });
      return ok;
    }
    if (candidatesOfSdp(sdp).length === 0) {
      this.step({ t: 'setup-failed' });
      return fail('no-candidates');
    }
    const text = writeDirectText(this.o.appId, {
      role,
      session: this.state.session as string,
      sdp,
    });
    if (!text.ok) {
      this.step({ t: 'setup-failed' });
      return text;
    }
    this.step({ t: 'local-text', now: this.o.clock() });
    this.channelOpened();
    return text;
  }

  /** Resolves when the channel is open, or with the reason the handshake ended. */
  opened(): Promise<Result<null>> {
    if (this.state.phase === 'open') return Promise.resolve(pass(null));
    if (this.state.phase === 'failed' || this.state.phase === 'closed')
      return Promise.resolve(fail(this.fromState()));
    return new Promise((resolve) => this.openWaiters.push({ resolve }));
  }

  /** The next message; waits up to `ms`. Messages that came earlier wait in the inbox. */
  receive(ms: number): Promise<Result<Uint8Array>> {
    const ready = this.inbox.shift();
    if (ready) {
      this.inboxBytes -= ready.length;
      return Promise.resolve(pass(ready));
    }
    if (this.state.phase === 'failed' || this.state.phase === 'closed')
      return Promise.resolve(fail('closed'));
    return new Promise((resolve) => {
      const reader: Reader = { resolve, handle: undefined };
      reader.handle = this.o.timers.set(() => {
        this.readers = this.readers.filter((r) => r !== reader);
        resolve(fail('timeout'));
      }, ms);
      this.readers.push(reader);
    });
  }

  /** Sends one message (up to `messageBytesMax`), chunked; sends are queued, never interleaved. */
  send(message: Uint8Array): Promise<Result<null>> {
    const run = this.sendChain.then(() => this.sendNow(message));
    this.sendChain = run.catch(() => undefined);
    return run;
  }

  private async sendNow(message: Uint8Array): Promise<Result<null>> {
    const ch = this.channel;
    if (this.state.phase !== 'open' || !ch) return fail('not-open');
    const id = this.nextId;
    const chunks = chunkMessage(id, message);
    if (!chunks.ok) return chunks;
    this.nextId = (id + 1) >>> 0;
    for (const chunk of chunks.value) {
      if (ch.bufferedAmount > L.highWaterBytes) {
        const w = await this.below(ch, L.lowWaterBytes);
        if (!w.ok) return w;
      }
      if (this.state.phase !== 'open') return fail(this.fromState());
      try {
        ch.send(chunk);
      } catch {
        return fail('send-failed');
      }
    }
    return pass(null);
  }

  private below(ch: DataChannelLike, threshold: number): Promise<Result<null>> {
    return new Promise((resolve) => {
      let handle: unknown;
      const finish = (r: Result<null>): void => {
        this.o.timers.clear(handle);
        ch.removeEventListener('bufferedamountlow', low);
        ch.removeEventListener('close', gone);
        resolve(r);
      };
      const low = (): void => finish(pass(null));
      const gone = (): void => finish(fail('closed'));
      ch.bufferedAmountLowThreshold = threshold;
      ch.addEventListener('bufferedamountlow', low);
      ch.addEventListener('close', gone);
      handle = this.o.timers.set(
        () => finish(fail('send-timeout')),
        this.o.sendTimeoutMs ?? 60_000,
      );
    });
  }

  /** Resolves once everything sent has left the device: closing earlier drops what still waits. */
  async drain(): Promise<Result<null>> {
    const ch = this.channel;
    if (!ch || ch.readyState !== 'open' || ch.bufferedAmount === 0) return pass(null);
    return this.below(ch, 0);
  }

  /** The way the connection took, read from the statistics (a code per end, no address). */
  async path(): Promise<ChosenPath | undefined> {
    try {
      const report = await this.peer.getStats();
      const entries: Record<string, unknown>[] = [];
      report.forEach((e) => {
        if (entries.length <= L.statsMax) entries.push(e);
      });
      return chosenPath(entries);
    } catch {
      return undefined;
    }
  }
}

export type DirectCreateReason = 'bad-app-id' | 'bad-config' | 'bad-session' | 'bad-stun';

export function createDirect(
  o: DirectOptions,
): TransferResult<DirectConnection, DirectCreateReason> {
  if (!o || typeof o !== 'object') return fail('bad-config');
  if (!domainBytes(o.appId, 'direct')) return fail('bad-app-id');
  if (o.role !== 'caller' && o.role !== 'callee') return fail('bad-config');
  if (
    typeof o.createPeer !== 'function' ||
    typeof o.clock !== 'function' ||
    typeof o.timers?.set !== 'function' ||
    typeof o.timers?.clear !== 'function'
  )
    return fail('bad-config');
  if (o.role === 'caller' && !(typeof o.session === 'string' && /^[0-9a-f]{16}$/.test(o.session)))
    return fail('bad-session');
  const stun = o.stunUrls ?? [];
  if (stun.length > 4 || !stun.every((u) => typeof u === 'string' && STUN.test(u)))
    return fail('bad-stun');
  const cfg: HandshakeConfig = { ...HANDSHAKE_DEFAULTS, ...o.handshake };
  const gatherWait = o.gatherWaitMs ?? 5_000;
  if (
    handshakeConfigProblem(cfg) ||
    !Number.isInteger(gatherWait) ||
    gatherWait < 1 ||
    gatherWait >= cfg.setupMs ||
    !Number.isInteger(o.sendTimeoutMs ?? 1) ||
    (o.sendTimeoutMs ?? 1) < 1
  )
    return fail('bad-config');
  let peer: PeerLike;
  try {
    peer = o.createPeer({ iceServers: stun.length > 0 ? [{ urls: [...stun] }] : [] });
  } catch {
    return fail('bad-config');
  }
  return pass(new DirectConnection(o, peer, cfg));
}
