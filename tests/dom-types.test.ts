// Compile-time guard (found by running the layers in a real browser, tests/real-browser/): the structural
// interfaces of the browser and transfer layers must accept the real DOM objects WITHOUT a cast, and what the
// layers hand back must fit the DOM calls that take it. `npm run typecheck` is the test; the cases below
// only keep the file honest at run time.
import { it } from 'vitest';
import type { ChannelLike, LockManagerLike } from '../src/browser/index.ts';
import { encodeToneMessage, TONE_PLANS, type PeerLike } from '../src/transfer/index.ts';
import { chunkMessage } from '../src/transfer/chunks.ts';

type Fits<A, B> = [A] extends [B] ? true : false;
const yes = <T extends true>(): T => true as T;

it('a real BroadcastChannel is a ChannelLike', () => {
  yes<Fits<BroadcastChannel, ChannelLike>>();
});

it('navigator.locks is a LockManagerLike', () => {
  yes<Fits<LockManager, LockManagerLike>>();
});

it('a real RTCPeerConnection is a PeerLike (data channel, descriptions, statistics)', () => {
  yes<Fits<RTCPeerConnection, PeerLike>>();
});

it('tone samples fit AudioBuffer.copyToChannel and chunks fit RTCDataChannel.send', () => {
  const plan = TONE_PLANS[0]!;
  const tone = encodeToneMessage('typeapp', Uint8Array.of(1), plan, 48_000);
  const chunks = chunkMessage(1, Uint8Array.of(1, 2, 3));
  if (!tone.ok || !chunks.ok) throw new Error('setup');
  yes<Fits<typeof tone.value, Parameters<AudioBuffer['copyToChannel']>[0]>>();
  yes<Fits<(typeof chunks.value)[number], Parameters<RTCDataChannel['send']>[0]>>();
});
