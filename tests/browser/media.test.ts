import { describe, expect, it } from 'vitest';
import {
  BROWSER_LIMITS,
  cameraSource,
  mediaErrorCode,
  microphoneSource,
  readCameraFrame,
  readSamples,
  stopStream,
  streamSource,
  type FrameReader,
  type MediaDevicesLike,
  type MediaStreamLike,
} from '../../src/browser/index.ts';
import { VirtualTime } from './fakes.ts';

class FakeStream implements MediaStreamLike {
  stops = [0, 0];
  throwOn = -1;
  getTracks() {
    return this.stops.map((_, i) => ({
      stop: () => {
        this.stops[i] = (this.stops[i] as number) + 1;
        if (i === this.throwOn) throw new Error('track refused to stop');
      },
    }));
  }
  get stopped(): boolean {
    return this.stops.every((n) => n >= 1);
  }
}

const domError = (name: string) =>
  Object.assign(new Error('text that must never be read'), { name });

function devices(
  behaviour: () => Promise<MediaStreamLike>,
): MediaDevicesLike & { calls: Array<Record<string, unknown>> } {
  const calls: Array<Record<string, unknown>> = [];
  return {
    calls,
    getUserMedia: (c) => {
      calls.push(c);
      return behaviour();
    },
  };
}

const goodFrame = { width: 2, height: 2, data: new Uint8ClampedArray(16) };
const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

describe('mediaErrorCode', () => {
  it('maps the names browsers use, reads nothing but the name', () => {
    const table: Array<[string, string]> = [
      ['NotAllowedError', 'denied'],
      ['SecurityError', 'denied'],
      ['PermissionDeniedError', 'denied'],
      ['NotFoundError', 'not-found'],
      ['DevicesNotFoundError', 'not-found'],
      ['OverconstrainedError', 'not-found'],
      ['NotReadableError', 'in-use'],
      ['TrackStartError', 'in-use'],
      ['AbortError', 'in-use'],
      ['TypeError', 'failed'],
      ['SomethingNew', 'failed'],
    ];
    for (const [name, code] of table) expect(mediaErrorCode(domError(name))).toBe(code);
    for (const x of [null, undefined, 'NotAllowedError', 5, {}, { name: 5 }])
      expect(mediaErrorCode(x)).toBe('failed');
  });
});

describe('streamSource', () => {
  it('unsupported: no media devices, or no getUserMedia', async () => {
    expect(
      await streamSource({
        mediaDevices: undefined,
        constraints: {},
        attach: () => () => {},
      }).start(() => {}),
    ).toEqual({
      ok: false,
      reason: 'unsupported',
    });
    const s = streamSource({ mediaDevices: {} as never, constraints: {}, attach: () => () => {} });
    expect(await s.start(() => {})).toEqual({ ok: false, reason: 'unsupported' });
  });

  it('permission errors become codes and no stream is left', async () => {
    for (const [name, code] of [
      ['NotAllowedError', 'denied'],
      ['NotFoundError', 'not-found'],
      ['NotReadableError', 'in-use'],
      ['Weird', 'failed'],
    ] as const) {
      const md = devices(() => Promise.reject(domError(name)));
      const s = streamSource({ mediaDevices: md, constraints: {}, attach: () => () => {} });
      expect(await s.start(() => {})).toEqual({ ok: false, reason: code });
    }
  });

  it('stop() stops every track, also when one refuses; twice is harmless', async () => {
    const stream = new FakeStream();
    stream.throwOn = 0;
    const s = streamSource({
      mediaDevices: devices(async () => stream),
      constraints: {},
      attach: () => () => {},
    });
    expect((await s.start(() => {})).ok).toBe(true);
    s.stop();
    expect(stream.stops).toEqual([1, 1]);
    s.stop();
    expect(stream.stops).toEqual([1, 1]);
  });

  it('attach throws: the tracks are stopped and the code is `failed`', async () => {
    const stream = new FakeStream();
    const s = streamSource({
      mediaDevices: devices(async () => stream),
      constraints: {},
      attach: () => {
        throw new Error('no canvas');
      },
    });
    expect(await s.start(() => {})).toEqual({ ok: false, reason: 'failed' });
    expect(stream.stops).toEqual([1, 1]);
  });

  it('stop() while the permission prompt is open: the stream that arrives is stopped at once', async () => {
    const stream = new FakeStream();
    let grant!: (s: MediaStreamLike) => void;
    const s = streamSource({
      mediaDevices: devices(() => new Promise((r) => (grant = r))),
      constraints: {},
      attach: () => () => {},
    });
    const started = s.start(() => {});
    s.stop();
    grant(stream);
    expect(await started).toEqual({ ok: false, reason: 'stopped' });
    expect(stream.stops).toEqual([1, 1]);
  });

  it('stop() while the prompt is open and the user then refuses: `stopped` or the error, nothing leaks', async () => {
    let refuse!: (e: unknown) => void;
    const s = streamSource({
      mediaDevices: devices(() => new Promise((_, r) => (refuse = r))),
      constraints: {},
      attach: () => () => {},
    });
    const started = s.start(() => {});
    s.stop();
    refuse(domError('NotAllowedError'));
    expect(await started).toEqual({ ok: false, reason: 'denied' });
  });

  it('starting twice, or after stop, is refused and does not ask for a second stream', async () => {
    const md = devices(async () => new FakeStream());
    const s = streamSource({ mediaDevices: md, constraints: {}, attach: () => () => {} });
    await s.start(() => {});
    expect(await s.start(() => {})).toEqual({ ok: false, reason: 'bad-config' });
    s.stop();
    expect(await s.start(() => {})).toEqual({ ok: false, reason: 'bad-config' });
    expect(md.calls.length).toBe(1);
  });

  it('the undo of attach runs on stop, and before the tracks stop', async () => {
    const order: string[] = [];
    const stream = new FakeStream();
    const track = stream.getTracks;
    stream.getTracks = function (this: FakeStream) {
      order.push('tracks');
      return track.call(this);
    };
    const s = streamSource({
      mediaDevices: devices(async () => stream),
      constraints: {},
      attach: () => () => order.push('undo'),
    });
    await s.start(() => {});
    s.stop();
    expect(order).toEqual(['undo', 'tracks']);
  });
});

describe('stopStream', () => {
  it('survives undefined and a stream that throws', () => {
    expect(() => stopStream(undefined)).not.toThrow();
    expect(() =>
      stopStream({
        getTracks: () => {
          throw new Error('x');
        },
      }),
    ).not.toThrow();
  });
});

describe('cameraSource', () => {
  function setup(frames: unknown[]) {
    const time = new VirtualTime();
    const stream = new FakeStream();
    const md = devices(async () => stream);
    let closed = 0;
    let n = 0;
    const reader: FrameReader = {
      read: () => frames[n++ % frames.length],
      close: () => void closed++,
    };
    const cam = cameraSource({
      mediaDevices: md,
      frameReader: () => reader,
      timers: time,
      intervalMs: 100,
    });
    return { time, stream, md, cam, closed: () => closed };
  }

  it('asks for the rear camera without audio and delivers frames at the interval', async () => {
    const { time, md, cam, stream } = setup([goodFrame]);
    const got: unknown[] = [];
    expect((await cam.start((f) => got.push(f))).ok).toBe(true);
    expect(md.calls).toEqual([{ video: { facingMode: 'environment' }, audio: false }]);
    time.advanceTo(1000);
    expect(got.length).toBe(10);
    cam.stop();
    time.advanceTo(5000);
    expect(got.length).toBe(10);
    expect(stream.stops).toEqual([1, 1]);
  });

  it('drops frames the strict reader refuses and keeps going', async () => {
    const { time, cam } = setup([
      undefined,
      { width: 2, height: 2, data: new Uint8ClampedArray(3) },
      goodFrame,
    ]);
    const got: unknown[] = [];
    await cam.start((f) => got.push(f));
    time.advanceTo(1000);
    expect(got.length).toBe(3); // every third of ten reads
  });

  it('the interval is at least 10 ms', async () => {
    const time = new VirtualTime();
    const cam = cameraSource({
      mediaDevices: devices(async () => new FakeStream()),
      frameReader: () => ({ read: () => goodFrame, close: () => {} }),
      timers: time,
      intervalMs: 1,
    });
    let n = 0;
    await cam.start(() => n++);
    time.advanceTo(1000);
    expect(n).toBe(100);
    cam.stop();
  });

  it('closes the reader and stops tracks on stop; a reader that cannot be made stops the tracks', async () => {
    const a = setup([goodFrame]);
    await a.cam.start(() => {});
    a.cam.stop();
    expect(a.closed()).toBe(1);

    const stream = new FakeStream();
    const cam = cameraSource({
      mediaDevices: devices(async () => stream),
      frameReader: () => {
        throw new Error('no video element');
      },
      timers: new VirtualTime(),
    });
    expect(await cam.start(() => {})).toEqual({ ok: false, reason: 'failed' });
    expect(stream.stops).toEqual([1, 1]);
  });

  it('a frame callback that stops the camera from inside does not schedule another read', async () => {
    const { time, cam } = setup([goodFrame]);
    let n = 0;
    await cam.start(() => {
      n++;
      cam.stop();
    });
    time.advanceTo(2000);
    expect(n).toBe(1);
  });
});

describe('microphoneSource', () => {
  it('delivers valid buffers only, asks for audio only, stops the tracks on stop', async () => {
    const stream = new FakeStream();
    const md = devices(async () => stream);
    let emit!: (b: { samples: Float32Array; sampleRate: number }) => void;
    const mic = microphoneSource({
      mediaDevices: md,
      attach: (_s, e) => {
        emit = e;
        return () => {};
      },
    });
    const got: number[] = [];
    await mic.start((s, rate) => got.push(s.length + rate));
    expect(md.calls).toEqual([{ audio: true, video: false }]);
    emit({ samples: new Float32Array(4), sampleRate: 48_000 });
    emit({ samples: new Float32Array([2]), sampleRate: 48_000 }); // out of range
    emit({ samples: new Float32Array(4), sampleRate: 5 }); // bad rate
    emit(undefined as never);
    expect(got).toEqual([48_004]);
    mic.stop();
    expect(stream.stops).toEqual([1, 1]);
  });

  it('denied is `denied`', async () => {
    const mic = microphoneSource({
      mediaDevices: devices(() => Promise.reject(domError('NotAllowedError'))),
      attach: () => () => {},
    });
    expect(await mic.start(() => {})).toEqual({ ok: false, reason: 'denied' });
    await flush();
  });
});

describe('strict readers', () => {
  it('readCameraFrame: whole dimensions, 4 bytes per pixel, limit', () => {
    expect(readCameraFrame(goodFrame)).toEqual(goodFrame);
    const side = BROWSER_LIMITS.frameSideMax;
    expect(
      readCameraFrame({ width: side, height: 1, data: new Uint8ClampedArray(side * 4) }),
    ).toBeDefined();
    for (const bad of [
      null,
      5,
      {},
      { width: 2, height: 2, data: new Uint8ClampedArray(15) },
      { width: 2, height: 2, data: new Uint8ClampedArray(17) },
      { width: 2, height: 2, data: new Uint8Array(16) },
      { width: 2, height: 2, data: [0] },
      { width: 0, height: 1, data: new Uint8ClampedArray(0) },
      { width: 1.5, height: 2, data: new Uint8ClampedArray(12) },
      { width: -1, height: 1, data: new Uint8ClampedArray(4) },
      { width: side + 1, height: 1, data: new Uint8ClampedArray((side + 1) * 4) },
      { width: '2', height: 2, data: new Uint8ClampedArray(16) },
    ])
      expect(readCameraFrame(bad), JSON.stringify(bad)).toBeUndefined();
  });

  it('readSamples: finite values in [-1, 1], 1 to samplesMax long, rate 8000 to 192000', () => {
    const ok = new Float32Array([0, 1, -1, 0.5]);
    expect(readSamples(ok, 44_100)).toBe(ok);
    expect(readSamples(ok, 8_000)).toBe(ok);
    expect(readSamples(ok, 192_000)).toBe(ok);
    expect(readSamples(ok, 7_999)).toBeUndefined();
    expect(readSamples(ok, 192_001)).toBeUndefined();
    expect(readSamples(ok, 44_100.5)).toBeUndefined();
    expect(readSamples(ok, '44100')).toBeUndefined();
    expect(readSamples(new Float32Array(0), 44_100)).toBeUndefined();
    expect(readSamples(new Float32Array([Number.NaN]), 44_100)).toBeUndefined();
    expect(readSamples(new Float32Array([Number.POSITIVE_INFINITY]), 44_100)).toBeUndefined();
    expect(readSamples(new Float32Array([1.0001]), 44_100)).toBeUndefined();
    expect(readSamples(new Float64Array(4), 44_100)).toBeUndefined();
    expect(readSamples([0, 0], 44_100)).toBeUndefined();
    expect(readSamples(new Float32Array(BROWSER_LIMITS.samplesMax + 1), 44_100)).toBeUndefined();
    expect(readSamples(new Float32Array(BROWSER_LIMITS.samplesMax), 44_100)).toBeDefined();
  });
});
