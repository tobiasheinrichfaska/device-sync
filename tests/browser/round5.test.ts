// Round 5 review of the browser layer: a frame reader or a frame handler that throws must not end the
// polling silently.
import { describe, expect, it } from 'vitest';
import { cameraSource, type MediaStreamLike } from '../../src/browser/index.ts';
import { VirtualTime } from './fakes.ts';

const stream: MediaStreamLike = { getTracks: () => [{ stop: () => {} }] };
const goodFrame = { width: 2, height: 2, data: new Uint8ClampedArray(16) };

function run(time: VirtualTime): void {
  for (let t = 100; t <= 1000; t += 100) {
    try {
      time.advanceTo(t);
    } catch {
      // the error surfaces to whoever drives the timers; the loop must go on
    }
  }
}

describe('round 5: the camera loop', () => {
  it('a reader that throws once does not stop the frames', async () => {
    const time = new VirtualTime();
    let n = 0;
    const cam = cameraSource({
      mediaDevices: { getUserMedia: async () => stream },
      frameReader: () => ({
        read: () => {
          n += 1;
          if (n === 3) throw new Error('video element not ready');
          return goodFrame;
        },
        close: () => {},
      }),
      timers: time,
      intervalMs: 100,
    });
    const got: unknown[] = [];
    await cam.start((f) => got.push(f));
    run(time);
    expect(got.length).toBe(9);
    cam.stop();
  });

  it('a frame handler that throws once does not stop the frames either', async () => {
    const time = new VirtualTime();
    const cam = cameraSource({
      mediaDevices: { getUserMedia: async () => stream },
      frameReader: () => ({ read: () => goodFrame, close: () => {} }),
      timers: time,
      intervalMs: 100,
    });
    let calls = 0;
    await cam.start(() => {
      calls += 1;
      if (calls === 2) throw new Error('app bug');
    });
    run(time);
    expect(calls).toBe(10);
    cam.stop();
  });
});
