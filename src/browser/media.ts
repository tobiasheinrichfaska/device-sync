// Camera and audio behind narrow interfaces. Nothing here codes or decodes a QR code or a tone: the later
// transfer layer takes a `CameraSource` / `AudioSource` / `AudioSink` and the two strict readers below.
import { BROWSER_LIMITS, fail, pass, type BrowserResult } from './limits.ts';
import { errorName } from './idb.ts';
import type { TimerLike } from './listener.ts';

export type MediaReason =
  'denied' | 'not-found' | 'in-use' | 'unsupported' | 'failed' | 'stopped' | 'bad-config';

export type MediaResult<T> = BrowserResult<T, MediaReason>;

/** A camera frame: what `ImageData` has (RGBA, four bytes per pixel). */
export interface FrameLike {
  readonly width: number;
  readonly height: number;
  readonly data: Uint8ClampedArray;
}

export interface CameraSource {
  /** Asks for the camera and calls `onFrame` with frames until `stop`. */
  start(onFrame: (frame: FrameLike) => void): Promise<MediaResult<null>>;
  /** Stops every track of the stream. Safe at any time and twice; a pending `start` ends as `stopped`. */
  stop(): void;
}

export interface AudioSource {
  start(onSamples: (samples: Float32Array, sampleRate: number) => void): Promise<MediaResult<null>>;
  stop(): void;
}

export interface AudioSink {
  /** Plays mono samples in [-1, 1]; resolves when they are played. */
  play(samples: Float32Array, sampleRate: number): Promise<MediaResult<null>>;
  stop(): void;
}

export interface TrackLike {
  stop(): void;
}
export interface MediaStreamLike {
  getTracks(): readonly TrackLike[];
}
/** `navigator.mediaDevices`, as far as it is used here. */
export interface MediaDevicesLike {
  getUserMedia(constraints: Record<string, unknown>): Promise<MediaStreamLike>;
}

/** Maps the error `getUserMedia` rejects with (by its name only, never its text) to a code. */
export function mediaErrorCode(e: unknown): 'denied' | 'not-found' | 'in-use' | 'failed' {
  switch (errorName(e)) {
    case 'NotAllowedError':
    case 'SecurityError':
    case 'PermissionDeniedError':
      return 'denied';
    case 'NotFoundError':
    case 'DevicesNotFoundError':
    case 'OverconstrainedError':
      return 'not-found';
    case 'NotReadableError':
    case 'TrackStartError':
    case 'AbortError':
      return 'in-use';
    default:
      return 'failed';
  }
}

/** Stops every track; one that throws does not keep the others running. */
export function stopStream(stream: MediaStreamLike | undefined): void {
  let tracks: readonly TrackLike[] = [];
  try {
    tracks = stream?.getTracks() ?? [];
  } catch {
    return;
  }
  for (const t of tracks) {
    try {
      t.stop();
    } catch {
      // keep stopping the rest
    }
  }
}

/** What a source does with a granted stream; returns what undoes it. May throw. */
export type Attach<T> = (stream: MediaStreamLike, emit: (value: T) => void) => () => void;

export interface StreamSourceOptions<T> {
  readonly mediaDevices: MediaDevicesLike | undefined;
  readonly constraints: Record<string, unknown>;
  readonly attach: Attach<T>;
}

/**
 * The shared adapter: asks for a stream, hands it to `attach`, and always stops all tracks on `stop`, on a
 * failing `attach` and when `stop` comes before the stream does.
 */
export function streamSource<T>(o: StreamSourceOptions<T>): {
  start(emit: (value: T) => void): Promise<MediaResult<null>>;
  stop(): void;
} {
  let state: 'idle' | 'starting' | 'running' | 'stopped' = 'idle';
  let stream: MediaStreamLike | undefined;
  let detach: (() => void) | undefined;
  const stop = (): void => {
    const was = state;
    state = 'stopped';
    if (was === 'running' || was === 'starting') {
      try {
        detach?.();
      } catch {
        // the tracks are stopped below in any case
      }
      detach = undefined;
      stopStream(stream);
      stream = undefined;
    }
  };
  return {
    stop,
    async start(emit) {
      if (state !== 'idle') return fail('bad-config');
      const md = o.mediaDevices;
      if (!md || typeof md.getUserMedia !== 'function') return fail('unsupported');
      state = 'starting';
      let got: MediaStreamLike;
      try {
        got = await md.getUserMedia(o.constraints);
      } catch (e) {
        if (state === 'starting') state = 'stopped';
        return fail(mediaErrorCode(e));
      }
      if (state !== 'starting') {
        // stop() came first: the stream arrived too late to be used.
        stopStream(got);
        return fail('stopped');
      }
      stream = got;
      try {
        detach = o.attach(got, emit);
      } catch {
        stop();
        return fail('failed');
      }
      state = 'running';
      return pass(null);
    },
  };
}

/** Reads frames from a stream; `read` returns the next frame or undefined. */
export interface FrameReader {
  read(): unknown;
  close(): void;
}

export interface CameraSourceOptions {
  readonly mediaDevices: MediaDevicesLike | undefined;
  /** Makes the reader for a granted stream (a video element and a canvas in a browser). */
  readonly frameReader: (stream: MediaStreamLike) => FrameReader;
  readonly timers: TimerLike;
  /** Between two frames (default 100, at least 10). */
  readonly intervalMs?: number;
  /** `user` or `environment` (default `environment`). */
  readonly facingMode?: 'user' | 'environment';
}

/** A camera that polls a frame reader. Frames that `readCameraFrame` refuses are dropped. */
export function cameraSource(o: CameraSourceOptions): CameraSource {
  const interval = Math.max(BROWSER_LIMITS.frameIntervalMinMs, Math.floor(o.intervalMs ?? 100));
  const inner = streamSource<FrameLike>({
    mediaDevices: o.mediaDevices,
    constraints: { video: { facingMode: o.facingMode ?? 'environment' }, audio: false },
    attach(stream, emit) {
      const reader = o.frameReader(stream);
      let handle: unknown;
      let live = true;
      const next = (): void => {
        if (!live) return;
        try {
          const frame = readCameraFrame(reader.read());
          if (frame) emit(frame);
        } finally {
          // A reader or a handler that throws must not end the polling for good.
          if (live) handle = o.timers.set(next, interval);
        }
      };
      handle = o.timers.set(next, interval);
      return () => {
        live = false;
        o.timers.clear(handle);
        reader.close();
      };
    },
  });
  return { start: (onFrame) => inner.start(onFrame), stop: inner.stop };
}

export interface MicrophoneSourceOptions {
  readonly mediaDevices: MediaDevicesLike | undefined;
  /** Connects the stream to an audio graph; `emit` takes buffers of samples; returns the undo. */
  readonly attach: Attach<{ samples: Float32Array; sampleRate: number }>;
}

export function microphoneSource(o: MicrophoneSourceOptions): AudioSource {
  const inner = streamSource({
    mediaDevices: o.mediaDevices,
    constraints: { audio: true, video: false },
    attach: o.attach,
  });
  return {
    start: (onSamples) =>
      inner.start((b) => {
        const s = readSamples(b?.samples, b?.sampleRate);
        if (s) onSamples(s, b.sampleRate);
      }),
    stop: inner.stop,
  };
}

/** Strict reader of a frame: whole dimensions within the limit and exactly four bytes per pixel. */
export function readCameraFrame(x: unknown): FrameLike | undefined {
  if (typeof x !== 'object' || x === null) return undefined;
  const { width, height, data } = x as { width?: unknown; height?: unknown; data?: unknown };
  const side = (n: unknown): n is number =>
    Number.isInteger(n) && (n as number) >= 1 && (n as number) <= BROWSER_LIMITS.frameSideMax;
  if (!side(width) || !side(height) || !(data instanceof Uint8ClampedArray)) return undefined;
  if (data.length !== width * height * 4) return undefined;
  return { width, height, data };
}

/** Strict reader of audio samples: 1 to `samplesMax` finite values in [-1, 1], rate 8000 to 192000 Hz. */
export function readSamples(x: unknown, sampleRate: unknown): Float32Array | undefined {
  if (!(x instanceof Float32Array) || x.length < 1 || x.length > BROWSER_LIMITS.samplesMax)
    return undefined;
  if (
    !Number.isInteger(sampleRate) ||
    (sampleRate as number) < 8_000 ||
    (sampleRate as number) > 192_000
  )
    return undefined;
  for (let i = 0; i < x.length; i++) {
    const v = x[i] as number;
    if (!Number.isFinite(v) || v < -1 || v > 1) return undefined;
  }
  return x;
}
