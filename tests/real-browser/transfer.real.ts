// Transfer layer in real Chromium: fountain frames, tones through real Web Audio (offline rendering and a
// real microphone stream from Chromium's fake capture device), the camera adapter on a real video
// element, and the direct connection over two real RTCPeerConnections.
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { encodeToneMessage, TONE_PLANS } from '../../src/transfer/tone.ts';
import {
  bundleLibrary,
  launch,
  openPage,
  startSite,
  type Browser,
  type Context,
  type Site,
} from './harness.ts';

const wavFile = (samples: Float32Array, rate: number): string => {
  const data = Buffer.alloc(44 + samples.length * 2);
  data.write('RIFF', 0);
  data.writeUInt32LE(36 + samples.length * 2, 4);
  data.write('WAVEfmt ', 8);
  data.writeUInt32LE(16, 16);
  data.writeUInt16LE(1, 20);
  data.writeUInt16LE(1, 22);
  data.writeUInt32LE(rate, 24);
  data.writeUInt32LE(rate * 2, 28);
  data.writeUInt16LE(2, 32);
  data.writeUInt16LE(16, 34);
  data.write('data', 36);
  data.writeUInt32LE(samples.length * 2, 40);
  samples.forEach((v, i) =>
    data.writeInt16LE(Math.round(Math.max(-1, Math.min(1, v)) * 32767), 44 + 2 * i),
  );
  const file = join(mkdtempSync(join(tmpdir(), 'ds-wav-')), 'tones.wav');
  writeFileSync(file, data);
  return file;
};

/** 1.5 s of silence, the message, 1 s of silence: the fake microphone plays it in a loop. */
const recording = (rate: number, plan: 'audible' | 'ultrasonic'): string => {
  const p = TONE_PLANS.find((x) => x.id === plan)!;
  const m = encodeToneMessage('realapp', Uint8Array.of(7, 8, 9, 250), p, rate);
  if (!m.ok) throw new Error(m.reason);
  const out = new Float32Array(Math.round(rate * 1.5) + m.value.length + rate);
  out.set(m.value, Math.round(rate * 1.5));
  return wavFile(out, rate);
};

let browser: Browser;
let context: Context;
let site: Site;
const wav = recording(48_000, 'audible');

beforeAll(async () => {
  site = await startSite(await bundleLibrary());
  browser = await launch([
    '--use-fake-device-for-media-stream',
    '--use-fake-ui-for-media-stream',
    `--use-file-for-fake-audio-capture=${wav}`,
    '--autoplay-policy=no-user-gesture-required',
    '--allow-loopback-in-peer-connection',
  ]);
  context = await browser.newContext({ permissions: ['microphone', 'camera'] });
});
afterAll(async () => {
  await browser?.close();
  await site?.close();
});

describe('fountain frames', () => {
  it('round-trips a payload through text frames in a shuffled, lossy, repeating stream', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const { createFountainSender, createFountainReceiver, frameToText } = window.ds;
      const payload = crypto.getRandomValues(new Uint8Array(5000));
      const s = createFountainSender({
        appId: 'realapp',
        payload,
        transferId: 0xdeadbeef,
        blockBytes: 200,
      });
      const rx = createFountainReceiver({ appId: 'realapp' });
      if (!s.ok || !rx.ok) throw new Error('setup');
      const texts: string[] = [];
      for (let i = 0; i < s.value.blocks * 2; i++) {
        const f = s.value.next();
        if (f.ok) texts.push(frameToText(f.value));
      }
      // drop every third frame, reverse the rest, show each twice (a camera reads a code repeatedly)
      const shown = texts
        .filter((_, i) => i % 3 !== 0)
        .reverse()
        .flatMap((t) => [t, t]);
      let outcome = '';
      for (const t of shown) {
        const x = rx.value.add(t);
        if (!x.ok) throw new Error(x.reason);
        outcome = x.value;
        if (outcome === 'done') break;
      }
      const got = rx.value.payload();
      return {
        outcome,
        same:
          got.ok &&
          got.value.length === payload.length &&
          got.value.every((b, i) => b === payload[i]),
      };
    });
    expect(r).toEqual({ outcome: 'done', same: true });
    await page.close();
  });
});

describe('tone messages through real Web Audio', () => {
  for (const plan of ['audible', 'ultrasonic'] as const) {
    it(`decodes the ${plan} plan after an OfflineAudioContext round trip with a filter and gain`, async () => {
      const page = await openPage(context, site);
      const r = await page.evaluate(async (planId: string) => {
        const { encodeToneMessage, decodeToneMessage, planById } = window.ds;
        const rate = 48_000;
        const p = planById(planId)!;
        const payload = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);
        const e = encodeToneMessage('realapp', payload, p, rate);
        if (!e.ok) return { reason: e.reason };
        const ctx = new OfflineAudioContext(1, e.value.length + rate / 2, rate);
        const buf = ctx.createBuffer(1, e.value.length, rate);
        buf.copyToChannel(e.value, 0);
        const src = ctx.createBufferSource();
        src.buffer = buf;
        const gain = ctx.createGain();
        gain.gain.value = 0.4;
        const filter = ctx.createBiquadFilter();
        filter.type = 'lowpass';
        filter.frequency.value = 21_000;
        src.connect(gain).connect(filter).connect(ctx.destination);
        src.start();
        const rendered = await ctx.startRendering();
        const out = rendered.getChannelData(0).slice();
        const d = decodeToneMessage('realapp', out, p, rate);
        const wrong = decodeToneMessage('otherapp', out, p, rate);
        return {
          ok: d.ok && d.value.length === 8 && d.value.every((b, i) => b === payload[i]),
          reason: d.ok ? '' : d.reason,
          wrong: wrong.ok ? 'decoded' : wrong.reason,
        };
      }, plan);
      expect(r).toEqual({ ok: true, reason: '', wrong: 'not-found' });
      await page.close();
    });
  }

  it('a real AudioContext plays the tones into a worklet and the streaming listener decodes them', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const { encodeToneMessage, createToneListener, planById } = window.ds;
      const ctx = new AudioContext();
      await ctx.resume();
      const rate = ctx.sampleRate;
      const p = planById('audible')!;
      const e = encodeToneMessage('realapp', Uint8Array.of(42, 43), p, rate);
      if (!e.ok) return { reason: e.reason };
      const code = `class C extends AudioWorkletProcessor { process(i) { const c = i[0][0]; if (c) this.port.postMessage(c.slice()); return true; } } registerProcessor('cap', C);`;
      await ctx.audioWorklet.addModule(
        URL.createObjectURL(new Blob([code], { type: 'text/javascript' })),
      );
      const node = new AudioWorkletNode(ctx, 'cap');
      const listener = createToneListener('realapp', p, rate);
      if (!listener.ok) return { reason: listener.reason };
      const found = new Promise<number[]>((resolve) => {
        node.port.onmessage = (ev: MessageEvent<Float32Array>) => {
          const x = listener.value.push(ev.data);
          if (x.ok) resolve([...x.value]);
        };
      });
      const buf = ctx.createBuffer(1, e.value.length, rate);
      buf.copyToChannel(e.value, 0);
      const src = ctx.createBufferSource();
      src.buffer = buf;
      src.connect(node);
      src.start();
      const timeout = new Promise<string>((res) => setTimeout(() => res('timeout'), 20_000));
      const got = await Promise.race([found, timeout]);
      await ctx.close();
      return { rate, got };
    });
    expect(r).toMatchObject({ got: [42, 43] });
    await page.close();
  });

  it('microphoneSource on a real getUserMedia stream (fake capture device) hears a played message', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const { microphoneSource, createToneListener, planById } = window.ds;
      const p = planById('audible')!;
      let ctx: AudioContext | undefined;
      const mic = microphoneSource({
        mediaDevices: navigator.mediaDevices,
        attach(stream, emit) {
          const c = new AudioContext();
          ctx = c;
          let live = true;
          let node: AudioWorkletNode | undefined;
          void (async () => {
            await c.resume();
            const code = `class C extends AudioWorkletProcessor { process(i) { const c = i[0][0]; if (c) this.port.postMessage(c.slice()); return true; } } registerProcessor('mic', C);`;
            await c.audioWorklet.addModule(
              URL.createObjectURL(new Blob([code], { type: 'text/javascript' })),
            );
            if (!live) return;
            node = new AudioWorkletNode(c, 'mic');
            node.port.onmessage = (ev: MessageEvent<Float32Array>) =>
              emit({ samples: ev.data, sampleRate: c.sampleRate });
            c.createMediaStreamSource(stream as MediaStream).connect(node);
          })();
          return () => {
            live = false;
            node?.disconnect();
            void c.close();
          };
        },
      });
      const listeners = new Map<number, ReturnType<typeof createToneListener>>();
      let buffers = 0;
      const found = new Promise<number[]>((resolve) => {
        void mic.start((samples, rate) => {
          buffers++;
          if (!listeners.has(rate)) listeners.set(rate, createToneListener('realapp', p, rate));
          const l = listeners.get(rate)!;
          if (!l.ok) return;
          const x = l.value.push(samples);
          if (x.ok) resolve([...x.value]);
        });
      });
      const got = await Promise.race([
        found,
        new Promise<string>((res) => setTimeout(() => res('timeout'), 25_000)),
      ]);
      mic.stop();
      return { got, buffers: buffers > 0, rate: ctx?.sampleRate };
    });
    expect(r).toMatchObject({ got: [7, 8, 9, 250], buffers: true });
    await page.close();
  }, 60_000);
});

describe('camera adapter on a real video element', () => {
  it('delivers valid frames from a fake camera and stops every real track', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const { cameraSource } = window.ds;
      const tracks: MediaStreamTrack[] = [];
      const video = document.createElement('video');
      const canvas = document.createElement('canvas');
      const cam = cameraSource({
        mediaDevices: navigator.mediaDevices,
        timers: { set: (fn, ms) => setTimeout(fn, ms), clear: (h) => clearTimeout(h as number) },
        intervalMs: 50,
        frameReader: (stream) => {
          const s = stream as MediaStream;
          tracks.push(...s.getTracks());
          video.srcObject = s;
          video.muted = true;
          void video.play();
          return {
            read: () => {
              if (video.videoWidth === 0) return undefined;
              canvas.width = video.videoWidth;
              canvas.height = video.videoHeight;
              const c = canvas.getContext('2d')!;
              c.drawImage(video, 0, 0);
              return c.getImageData(0, 0, canvas.width, canvas.height);
            },
            close: () => {
              video.srcObject = null;
            },
          };
        },
      });
      const frames: { w: number; h: number; lit: boolean }[] = [];
      const started = await cam.start((f) => {
        if (frames.length < 3)
          frames.push({ w: f.width, h: f.height, lit: f.data.some((b) => b > 0) });
      });
      const t0 = Date.now();
      while (frames.length < 3 && Date.now() - t0 < 15_000)
        await new Promise((r) => setTimeout(r, 50));
      const before = tracks.map((t) => t.readyState);
      cam.stop();
      cam.stop();
      return { started, frames, before, after: tracks.map((t) => t.readyState) };
    });
    expect(r.started).toEqual({ ok: true, value: null });
    expect(r.frames).toHaveLength(3);
    expect(
      r.frames.every((f: { w: number; h: number; lit: boolean }) => f.w > 0 && f.h > 0 && f.lit),
    ).toBe(true);
    expect(r.before.every((s: string) => s === 'live')).toBe(true);
    expect(r.after.length).toBeGreaterThan(0);
    expect(r.after.every((s: string) => s === 'ended')).toBe(true);
    await page.close();
  });

  it('maps a real refusal to a code (permission denied in a context without the grant)', async () => {
    const bare = await browser.newContext({ permissions: [] });
    const page = await openPage(bare, site);
    const r = await page.evaluate(async () => {
      const mic = window.ds.microphoneSource({
        mediaDevices: {
          // Chromium's fake UI auto-accepts, so ask a device that does not exist to get a real error object
          getUserMedia: () =>
            navigator.mediaDevices.getUserMedia({ audio: { deviceId: { exact: 'nope' } } }),
        },
        attach: () => () => undefined,
      });
      return mic.start(() => undefined);
    });
    expect(r.ok).toBe(false);
    expect(['not-found', 'denied']).toContain(r.reason);
    await bare.close();
  });
});

describe('direct connection over two real RTCPeerConnections in one page', () => {
  it('connects by exchanged texts, sends both ways incl. a chunked 1 MiB message, reads the path and closes', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const { createDirect } = window.ds;
      const timers = {
        set: (fn: () => void, ms: number) => setTimeout(fn, ms),
        clear: (h: unknown) => clearTimeout(h as number),
      };
      const base = {
        appId: 'realapp',
        createPeer: (c: object) => new RTCPeerConnection(c),
        timers,
        clock: () => performance.now(),
      };
      const a = createDirect({ ...base, role: 'caller', session: '0123456789abcdef' });
      const b = createDirect({ ...base, role: 'callee' });
      if (!a.ok || !b.ok) throw new Error('create');
      const offer = await a.value.makeOffer();
      if (!offer.ok) return { step: 'offer', reason: offer.reason };
      const answer = await b.value.acceptOffer(offer.value);
      if (!answer.ok) return { step: 'answer', reason: answer.reason };
      const acc = await a.value.acceptAnswer(answer.value);
      if (!acc.ok) return { step: 'accept', reason: acc.reason };
      const [oa, ob] = await Promise.all([a.value.opened(), b.value.opened()]);
      if (!oa.ok || !ob.ok) return { step: 'open', a: oa, b: ob };
      const bigPart = new Uint8Array(1024 * 1024);
      for (let i = 0; i < bigPart.length; i += 65536)
        bigPart.set(crypto.getRandomValues(new Uint8Array(65536)), i);
      const small = Uint8Array.of(1, 2, 3);
      // early messages: sent before anybody reads
      const s1 = await a.value.send(small);
      const s2 = await b.value.send(Uint8Array.of(9, 9));
      const s3 = await a.value.send(bigPart);
      const r1 = await b.value.receive(10_000);
      const r2 = await a.value.receive(10_000);
      const r3 = await b.value.receive(30_000);
      const path = await a.value.path();
      const offerKinds = {
        offer: offer.value.length,
        answer: answer.value.length,
      };
      a.value.close();
      const gone = await b.value.receive(10_000);
      return {
        step: 'done',
        sent: [s1.ok, s2.ok, s3.ok],
        r1: r1.ok ? [...r1.value] : r1,
        r2: r2.ok ? [...r2.value] : r2,
        big:
          r3.ok && r3.value.length === bigPart.length && r3.value.every((x, i) => x === bigPart[i]),
        path,
        offerKinds,
        gone,
        closeA: a.value.status().phase,
        closeB: b.value.closeReason(),
      };
    });
    expect(r).toMatchObject({
      step: 'done',
      sent: [true, true, true],
      r1: [1, 2, 3],
      r2: [9, 9],
      big: true,
    });
    await page.close();
  });
});

describe('direct connection when Chromium hides host addresses behind mDNS names', () => {
  it('still connects (no media grant, no loopback flag) and reads the path as mdns', async () => {
    const plain = await launch([]);
    const page = await openPage(await plain.newContext(), site);
    const r = await page.evaluate(async () => {
      const { createDirect, candidatesOfSdp, readDirectText } = window.ds;
      const timers = {
        set: (fn: () => void, ms: number) => setTimeout(fn, ms),
        clear: (h: unknown) => clearTimeout(h as number),
      };
      const base = {
        appId: 'realapp',
        createPeer: (c: object) => new RTCPeerConnection(c),
        timers,
        clock: () => performance.now(),
        // Chromium may not report the gathering as complete while the names are registered
        gatherWaitMs: 1_000,
      };
      const a = createDirect({ ...base, role: 'caller', session: '0123456789abcdef' });
      const b = createDirect({ ...base, role: 'callee' });
      if (!a.ok || !b.ok) throw new Error('create');
      const offer = await a.value.makeOffer();
      if (!offer.ok) return { step: 'offer', reason: offer.reason };
      const text = readDirectText('realapp', offer.value);
      const kinds = text.ok ? candidatesOfSdp(text.value.sdp).map((c) => c.family) : [];
      const answer = await b.value.acceptOffer(offer.value);
      if (!answer.ok) return { step: 'answer', reason: answer.reason };
      await a.value.acceptAnswer(answer.value);
      const [oa, ob] = await Promise.all([a.value.opened(), b.value.opened()]);
      const path = await a.value.path();
      a.value.close();
      return {
        oa,
        ob,
        kinds: [...new Set(kinds)],
        path: path && [path.local.family, path.remote.family],
      };
    });
    expect(r).toEqual({
      oa: { ok: true, value: null },
      ob: { ok: true, value: null },
      kinds: ['mdns'],
      path: ['mdns', 'mdns'],
    });
    await plain.close();
  });
});
