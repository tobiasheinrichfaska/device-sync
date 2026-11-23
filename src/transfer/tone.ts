// Short messages as audio tones. A byte is three tones: a start tone, the high nibble, and the low nibble
// shifted so a tone never repeats the one before it; each tone has soft edges against clicks. Detection
// measures the Goertzel power of every tone frequency in a Hann-windowed analysis frame. A message is
// `length | payload | check` (the check is 16 bits of a CRC-32 over the app's domain marker, length and
// payload), sent `plan.repeats` times. Pure: samples in and out (Float32Array), the sample rate and the
// plan are parameters, the plans are data so the band can change without touching the code.
import { BROWSER_LIMITS } from '../browser/limits.ts';
import { crc32, domainBytes } from './check.ts';
import { TRANSFER_LIMITS as L, fail, pass, type TransferResult } from './limits.ts';

export interface TonePlan {
  readonly id: 'ultrasonic' | 'audible';
  readonly baseHz: number;
  readonly stepHz: number;
  readonly toneMs: number;
  /** Silence between repetitions of the whole message. */
  readonly gapMs: number;
  readonly fadeMs: number;
  readonly repeats: number;
  readonly amplitude: number;
  /** Best tone power divided by the median of the others must reach this. */
  readonly minSnr: number;
  /** Absolute floor against silence. */
  readonly minPower: number;
}

/** 0-15 high nibble, 0-16 shifted low nibble, 17 start. */
export const TONE_COUNT = 18;
export const START_TONE = 17;

export const TONE_PLANS: readonly TonePlan[] = [
  {
    id: 'ultrasonic',
    baseHz: 17_500,
    stepHz: 110,
    toneMs: 90,
    gapMs: 150,
    fadeMs: 8,
    repeats: 2,
    amplitude: 0.5,
    minSnr: 8,
    minPower: 1e-10,
  },
  {
    id: 'audible',
    baseHz: 1_500,
    stepHz: 110,
    toneMs: 90,
    gapMs: 150,
    fadeMs: 8,
    repeats: 2,
    amplitude: 0.3,
    minSnr: 8,
    minPower: 1e-10,
  },
];

export function planById(id: string): TonePlan | undefined {
  return TONE_PLANS.find((p) => p.id === id);
}

export type ToneReason =
  'bad-app-id' | 'bad-payload' | 'bad-byte' | 'bad-rate' | 'bad-samples' | 'not-found';

export function toneHz(plan: TonePlan, tone: number): number {
  return plan.baseHz + tone * plan.stepHz;
}

/** The rate must be an integer in 8000..192000 Hz and the top tone below 0.45 of it (room for the filter). */
export function rateFits(plan: TonePlan, sampleRate: unknown): sampleRate is number {
  return (
    Number.isInteger(sampleRate) &&
    (sampleRate as number) >= 8_000 &&
    (sampleRate as number) <= 192_000 &&
    toneHz(plan, TONE_COUNT - 1) < 0.45 * (sampleRate as number)
  );
}

export function byteTones(byte: number): [number, number, number] {
  const hi = (byte >> 4) & 0xf;
  const lo = byte & 0xf;
  return [START_TONE, hi, (hi + 1 + lo) % 17];
}

export function durationMs(plan: TonePlan, messageBytes = 1): number {
  const once = messageBytes * 3 * plan.toneMs;
  return plan.repeats * once + (plan.repeats - 1) * plan.gapMs;
}

/** Renders bytes as tones, the whole run `plan.repeats` times with a gap between. */
function render(
  bytes: readonly number[],
  plan: TonePlan,
  sampleRate: number,
): Float32Array<ArrayBuffer> {
  const toneLen = Math.round((plan.toneMs / 1000) * sampleRate);
  const gapLen = Math.round((plan.gapMs / 1000) * sampleRate);
  const fade = Math.max(1, Math.round((plan.fadeMs / 1000) * sampleRate));
  const once = bytes.length * 3 * toneLen;
  const out = new Float32Array(plan.repeats * once + (plan.repeats - 1) * gapLen);
  for (let r = 0; r < plan.repeats; r++) {
    const offset = r * (once + gapLen);
    bytes.forEach((byte, b) => {
      byteTones(byte).forEach((tone, k) => {
        const omega = (2 * Math.PI * toneHz(plan, tone)) / sampleRate;
        const start = offset + (b * 3 + k) * toneLen;
        for (let i = 0; i < toneLen; i++) {
          const envelope = Math.min(1, i / fade, (toneLen - 1 - i) / fade);
          out[start + i] = plan.amplitude * envelope * Math.sin(omega * i);
        }
      });
    });
  }
  return out;
}

/** One byte as tones (the acknowledgement of the earlier implementation). */
export function synthesizeByte(
  byte: number,
  plan: TonePlan,
  sampleRate: number,
): TransferResult<Float32Array<ArrayBuffer>, ToneReason> {
  if (!Number.isInteger(byte) || byte < 0 || byte > 255) return fail('bad-byte');
  if (!rateFits(plan, sampleRate)) return fail('bad-rate');
  return pass(render([byte], plan, sampleRate));
}

function checkOf(domain: Uint8Array, body: Uint8Array): [number, number] {
  const c = crc32([domain, body]) & 0xffff;
  return [c >> 8, c & 0xff];
}

/** `length | payload | check` as bytes. */
export function messageBytes(
  appId: string,
  payload: Uint8Array,
): TransferResult<Uint8Array, ToneReason> {
  const domain = domainBytes(appId, 'tone');
  if (!domain) return fail('bad-app-id');
  if (!(payload instanceof Uint8Array) || payload.length < 1 || payload.length > L.toneMessageMax)
    return fail('bad-payload');
  const body = new Uint8Array(1 + payload.length);
  body[0] = payload.length;
  body.set(payload, 1);
  const [a, b] = checkOf(domain, body);
  const out = new Uint8Array(body.length + L.toneCheckBytes);
  out.set(body);
  out[body.length] = a;
  out[body.length + 1] = b;
  return pass(out);
}

/** A short message (1 to `toneMessageMax` octets) as samples. */
export function encodeToneMessage(
  appId: string,
  payload: Uint8Array,
  plan: TonePlan,
  sampleRate: number,
): TransferResult<Float32Array<ArrayBuffer>, ToneReason> {
  const m = messageBytes(appId, payload);
  if (!m.ok) return m;
  if (!rateFits(plan, sampleRate)) return fail('bad-rate');
  return pass(render([...m.value], plan, sampleRate));
}

export function goertzelPower(samples: ArrayLike<number>, sampleRate: number, hz: number): number {
  const coeff = 2 * Math.cos((2 * Math.PI * hz) / sampleRate);
  let s1 = 0;
  let s2 = 0;
  for (let i = 0; i < samples.length; i++) {
    const s0 = (samples[i] ?? 0) + coeff * s1 - s2;
    s2 = s1;
    s1 = s0;
  }
  const n = Math.max(1, samples.length);
  return (s1 * s1 + s2 * s2 - coeff * s1 * s2) / (n * n);
}

/** Power of every tone frequency in one Hann-windowed frame. */
export function levels(samples: ArrayLike<number>, sampleRate: number, plan: TonePlan): number[] {
  const n = samples.length;
  const windowed = new Float32Array(n);
  for (let i = 0; i < n; i++)
    windowed[i] =
      (samples[i] ?? 0) * (0.5 - 0.5 * Math.cos((2 * Math.PI * i) / Math.max(1, n - 1)));
  return Array.from({ length: TONE_COUNT }, (_, tone) =>
    goertzelPower(windowed, sampleRate, toneHz(plan, tone)),
  );
}

/** The tone clearly present in this frame, or null. */
export function classify(
  samples: ArrayLike<number>,
  sampleRate: number,
  plan: TonePlan,
): number | null {
  const power = levels(samples, sampleRate, plan);
  let best = 0;
  power.forEach((p, i) => {
    if (p > (power[best] ?? 0)) best = i;
  });
  const top = power[best] ?? 0;
  const others = power.filter((_, i) => i !== best).sort((a, b) => a - b);
  const median = others[Math.floor(others.length / 2)] ?? 0;
  if (!(top >= plan.minPower) || top < plan.minSnr * median) return null;
  return best;
}

/** Analysis frame length: about 21 ms whatever the rate, so the bins stay narrower than a tone step. */
export const frameSizeFor = (sampleRate: number): number => Math.round(sampleRate / 46.875);

/** Symbols of consecutive analysis frames. */
export function analyze(
  samples: Float32Array,
  sampleRate: number,
  plan: TonePlan,
  frameSize = frameSizeFor(sampleRate),
  hop = frameSize >> 1,
): (number | null)[] {
  const symbols: (number | null)[] = [];
  for (let start = 0; start + frameSize <= samples.length; start += hop)
    symbols.push(classify(samples.subarray(start, start + frameSize), sampleRate, plan));
  return symbols;
}

/** Bytes found in a symbol stream; a tone counts once it held for `minRun` frames. */
export function decodeTones(symbols: readonly (number | null)[], minRun = 2): number[] {
  const tokens: number[] = [];
  let current: number | null = null;
  let run = 0;
  const flush = (): void => {
    // Adjacent tones never repeat by construction, so a tone split by a dip counts once.
    if (current !== null && run >= minRun && tokens[tokens.length - 1] !== current)
      tokens.push(current);
  };
  for (const symbol of symbols) {
    if (symbol === current) {
      run++;
      continue;
    }
    flush();
    current = symbol;
    run = 1;
  }
  flush();
  const bytes: number[] = [];
  for (let i = 0; i + 2 < tokens.length; i++) {
    if (tokens[i] !== START_TONE) continue;
    const hi = tokens[i + 1] ?? -1;
    const shifted = tokens[i + 2] ?? -1;
    if (hi < 0 || hi > 15 || shifted < 0 || shifted > 16) continue;
    const lo = (shifted - hi - 1 + 34) % 17;
    if (lo > 15) continue;
    bytes.push(hi * 16 + lo);
    i += 2;
  }
  return bytes;
}

/** The first message in a byte stream whose length and check hold, or undefined. */
export function findMessage(appId: string, bytes: readonly number[]): Uint8Array | undefined {
  const domain = domainBytes(appId, 'tone');
  if (!domain) return undefined;
  for (let i = 0; i < bytes.length; i++) {
    const len = bytes[i] as number;
    if (len < 1 || len > L.toneMessageMax || i + 1 + len + L.toneCheckBytes > bytes.length)
      continue;
    const body = Uint8Array.from(bytes.slice(i, i + 1 + len));
    const [a, b] = checkOf(domain, body);
    if (bytes[i + 1 + len] === a && bytes[i + 2 + len] === b) return body.slice(1);
  }
  return undefined;
}

function samplesOk(samples: unknown): samples is Float32Array {
  if (!(samples instanceof Float32Array)) return false;
  if (samples.length < 1 || samples.length > BROWSER_LIMITS.samplesMax) return false;
  for (let i = 0; i < samples.length; i++) if (!Number.isFinite(samples[i])) return false;
  return true;
}

/** Decodes a recording that holds one message. Offset, clipping and noise are tolerated by the detector. */
export function decodeToneMessage(
  appId: string,
  samples: Float32Array,
  plan: TonePlan,
  sampleRate: number,
): TransferResult<Uint8Array, ToneReason> {
  if (!domainBytes(appId, 'tone')) return fail('bad-app-id');
  if (!rateFits(plan, sampleRate)) return fail('bad-rate');
  if (!samplesOk(samples)) return fail('bad-samples');
  const found = findMessage(appId, decodeTones(analyze(samples, sampleRate, plan)));
  return found ? pass(found) : fail('not-found');
}

export interface ToneListener {
  /** Feeds the next buffer of the microphone; returns the first message once its check holds. */
  push(samples: Float32Array): TransferResult<Uint8Array, ToneReason>;
  reset(): void;
}

/**
 * Streaming decoder for `AudioSource`: keeps the unanalysed tail, classifies each finished frame once and
 * looks for a message in the bounded symbol list. After a message was found the symbols are dropped (a
 * repeat of the same message would be found again: the app stops listening).
 */
export function createToneListener(
  appId: string,
  plan: TonePlan,
  sampleRate: number,
): TransferResult<ToneListener, ToneReason> {
  if (!domainBytes(appId, 'tone')) return fail('bad-app-id');
  if (!rateFits(plan, sampleRate)) return fail('bad-rate');
  const size = frameSizeFor(sampleRate);
  const hop = size >> 1;
  let tail = new Float32Array(0);
  let symbols: (number | null)[] = [];
  return pass({
    reset() {
      tail = new Float32Array(0);
      symbols = [];
    },
    push(samples) {
      if (!samplesOk(samples)) return fail('bad-samples');
      const buf = new Float32Array(tail.length + samples.length);
      buf.set(tail);
      buf.set(samples, tail.length);
      let at = 0;
      let added = false;
      while (at + size <= buf.length) {
        symbols.push(classify(buf.subarray(at, at + size), sampleRate, plan));
        added = true;
        at += hop;
      }
      tail = buf.slice(at);
      if (symbols.length > L.toneSymbolsMax) symbols = symbols.slice(-L.toneSymbolsMax);
      if (!added) return fail('not-found');
      const found = findMessage(appId, decodeTones(symbols));
      if (!found) return fail('not-found');
      symbols = [];
      return pass(found);
    },
  });
}
