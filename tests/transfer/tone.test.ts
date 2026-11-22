import { describe, expect, it } from 'vitest';
import {
  START_TONE,
  TONE_COUNT,
  TONE_PLANS,
  TRANSFER_LIMITS as L,
  analyze,
  byteTones,
  classify,
  createToneListener,
  decodeToneMessage,
  decodeTones,
  durationMs,
  encodeToneMessage,
  findMessage,
  levels,
  messageBytes,
  planById,
  rateFits,
  synthesizeByte,
  toneHz,
  type TonePlan,
} from '../../src/transfer/index.ts';
import { crc32 } from '../../src/transfer/check.ts';
import { APP, bytes, rng } from './helpers.ts';

const ultra = planById('ultrasonic') as TonePlan;
const audible = planById('audible') as TonePlan;
const SAMPLE_BYTES = [0x00, 0x01, 0x11, 0x7e, 0xab, 0xf0, 0xff];

/** Deterministic white noise in [-amplitude, amplitude]. */
function noise(length: number, amplitude: number, seed = 1): Float32Array {
  let state = seed;
  return Float32Array.from({ length }, () => {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    return ((state / 4294967296) * 2 - 1) * amplitude;
  });
}
const mix = (a: Float32Array, b: Float32Array): Float32Array => a.map((v, i) => v + (b[i] ?? 0));
const ok = <T>(r: { ok: boolean; value?: T; reason?: string }): T => {
  if (!r.ok) throw new Error(r.reason);
  return r.value as T;
};

describe('tone plans (cases of the earlier implementation)', () => {
  it('stay below the Nyquist frequency of 44.1 kHz', () => {
    for (const plan of TONE_PLANS) expect(toneHz(plan, TONE_COUNT - 1)).toBeLessThan(22050);
  });
  it('give a short single-byte acknowledgement', () => {
    expect(durationMs(ultra)).toBeLessThan(800);
  });
  it('rates: the ultrasonic plan needs at least 44.1 kHz, the audible one works from 8 kHz up', () => {
    expect(rateFits(ultra, 44_100)).toBe(true);
    expect(rateFits(ultra, 32_000)).toBe(false);
    expect(rateFits(audible, 8_000)).toBe(true);
    expect(rateFits(audible, 7_999)).toBe(false);
    expect(rateFits(audible, 192_001)).toBe(false);
    expect(rateFits(audible, 48_000.5)).toBe(false);
    expect(rateFits(audible, '48000')).toBe(false);
  });
});

describe('byteTones', () => {
  it('never repeats a tone directly, for every byte', () => {
    for (let byte = 0; byte < 256; byte++) {
      const [start, hi, lo] = byteTones(byte);
      expect(start).toBe(START_TONE);
      expect(hi).not.toBe(start);
      expect(lo).not.toBe(hi);
      expect(lo).not.toBe(START_TONE);
    }
  });
});

describe('detection of one byte', () => {
  for (const sampleRate of [48000, 44100]) {
    it(`decodes sample bytes of both plans at ${sampleRate} Hz`, () => {
      for (const plan of [ultra, audible])
        for (const byte of SAMPLE_BYTES) {
          const samples = ok(synthesizeByte(byte, plan, sampleRate));
          expect(decodeTones(analyze(samples, sampleRate, plan))).toEqual([byte, byte]);
        }
    });
  }

  it('every byte value is decoded (audible plan)', () => {
    for (let byte = 0; byte < 256; byte++) {
      const samples = ok(synthesizeByte(byte, audible, 48000));
      expect(decodeTones(analyze(samples, 48000, audible))[0]).toBe(byte);
    }
  });

  it('still decodes under strong noise', () => {
    const signal = ok(synthesizeByte(0xab, ultra, 48000));
    const noisy = mix(signal, noise(signal.length, 0.5));
    expect(decodeTones(analyze(noisy, 48000, ultra))).toContain(0xab);
  });

  it('finds nothing in silence or in noise alone', () => {
    expect(decodeTones(analyze(new Float32Array(48000), 48000, ultra))).toEqual([]);
    expect(decodeTones(analyze(noise(48000, 0.5), 48000, ultra))).toEqual([]);
  });

  it('does not hear the audible plan when listening for ultrasound', () => {
    const samples = ok(synthesizeByte(0x42, audible, 48000));
    expect(decodeTones(analyze(samples, 48000, ultra))).toEqual([]);
  });

  it('measures one level per tone, highest at the played tone', () => {
    const frame = ok(synthesizeByte(0x00, ultra, 48000)).subarray(0, 1024);
    const power = levels(frame, 48000, ultra);
    expect(power).toHaveLength(TONE_COUNT);
    expect(power.indexOf(Math.max(...power))).toBe(START_TONE);
    expect(classify(frame, 48000, ultra)).toBe(START_TONE);
  });

  it('refuses a byte out of range and a rate that cannot carry the plan', () => {
    expect(synthesizeByte(256, ultra, 48000)).toEqual({ ok: false, reason: 'bad-byte' });
    expect(synthesizeByte(-1, ultra, 48000)).toEqual({ ok: false, reason: 'bad-byte' });
    expect(synthesizeByte(1.5, ultra, 48000)).toEqual({ ok: false, reason: 'bad-byte' });
    expect(synthesizeByte(1, ultra, 32000)).toEqual({ ok: false, reason: 'bad-rate' });
  });
});

describe('decodeTones (cases of the earlier implementation)', () => {
  it('counts a tone split by a short dip only once', () => {
    const [start, hi, lo] = byteTones(0x5c);
    expect(decodeTones([start, start, null, start, start, hi, hi, hi, lo, lo, lo])).toEqual([0x5c]);
  });
  it('ignores a tone shorter than the minimum run', () => {
    const [start, hi, lo] = byteTones(0x5c);
    expect(decodeTones([start, start, hi, lo, lo])).toEqual([]);
  });
  it('ignores an invalid low tone', () => {
    expect(decodeTones([START_TONE, START_TONE, 3, 3, null, 3, 3])).toEqual([]);
  });
});

describe('messages', () => {
  const MSG = Uint8Array.from([1, 2, 3, 250, 0, 77]);

  for (const [name, plan, rate] of [
    ['ultrasonic 48000', ultra, 48000],
    ['ultrasonic 44100', ultra, 44100],
    ['audible 48000', audible, 48000],
    ['audible 16000', audible, 16000],
  ] as const)
    it(`round-trip: ${name}`, () => {
      const samples = ok(encodeToneMessage(APP, MSG, plan, rate));
      expect(decodeToneMessage(APP, samples, plan, rate)).toEqual({ ok: true, value: MSG });
    });

  it('every payload length from 1 to the limit, with different content', () => {
    const r = rng(3);
    for (let n = 1; n <= L.toneMessageMax; n++) {
      const payload = bytes(n, 100 + n);
      const samples = ok(encodeToneMessage(APP, payload, audible, 48000));
      expect(decodeToneMessage(APP, samples, audible, 48000)).toEqual({ ok: true, value: payload });
    }
    expect(r()).toBeGreaterThan(-1);
  });

  it('the message is sent twice, so a first copy hit by a burst of noise still decodes the second', () => {
    const samples = ok(encodeToneMessage(APP, MSG, audible, 48000));
    const damaged = samples.slice();
    // wipe the middle of the first copy (about the length of 3 tones) with loud noise
    const hit = noise(8000, 1, 9);
    damaged.set(hit, 30_000);
    expect(decodeToneMessage(APP, damaged, audible, 48000)).toEqual({ ok: true, value: MSG });
  });

  it('survives noise, a DC offset, clipping and a quiet signal', () => {
    const clean = ok(encodeToneMessage(APP, MSG, audible, 48000));
    const cases: [string, Float32Array][] = [
      ['noise 0.3', mix(clean, noise(clean.length, 0.3, 4))],
      ['offset 0.4', clean.map((v) => v + 0.4)],
      ['clipped', clean.map((v) => Math.max(-0.1, Math.min(0.1, v * 4)))],
      ['quiet 0.02', clean.map((v) => v * 0.07)],
    ];
    for (const [name, samples] of cases)
      expect(decodeToneMessage(APP, samples, audible, 48000), name).toEqual({
        ok: true,
        value: MSG,
      });
  });

  it('a message in the middle of other sound and silence is found', () => {
    const clean = ok(encodeToneMessage(APP, MSG, audible, 48000));
    const out = new Float32Array(48000 + clean.length + 48000);
    out.set(noise(out.length, 0.05, 2));
    out.set(
      clean.map((v, i) => v + (out[48000 + i] ?? 0)),
      48000,
    );
    expect(decodeToneMessage(APP, out, audible, 48000)).toEqual({ ok: true, value: MSG });
  });

  it('another app does not read it, and a changed byte is not accepted', () => {
    const bytesOf = ok(messageBytes(APP, MSG));
    expect(findMessage(APP, [...bytesOf])).toEqual(MSG);
    expect(findMessage('other', [...bytesOf])).toBeUndefined();
    for (let i = 0; i < bytesOf.length; i++) {
      const b = [...bytesOf];
      b[i] = (b[i] as number) ^ 0x10;
      expect(findMessage(APP, b), `byte ${i}`).toBeUndefined();
    }
    // the same check value with another length byte is not a message either
    expect(findMessage(APP, [...bytesOf.slice(0, -1)])).toBeUndefined();
  });

  it('finds a message after junk bytes, and only one with an honest length', () => {
    const m = [...ok(messageBytes(APP, Uint8Array.from([9, 9])))];
    expect(findMessage(APP, [200, 0, 3, ...m])).toEqual(Uint8Array.from([9, 9]));
    expect(findMessage(APP, [])).toBeUndefined();
    expect(findMessage(APP, [0, 0, 0, 0])).toBeUndefined();
    expect(findMessage(APP, [L.toneMessageMax + 1, ...new Array(30).fill(0)])).toBeUndefined();
  });

  it('a message longer than the limit is not accepted even with a correct check', () => {
    const body = Uint8Array.from([
      L.toneMessageMax + 1,
      ...new Array(L.toneMessageMax + 1).fill(7),
    ]);
    const c = crc32([new TextEncoder().encode(), body]) & 0xffff;
    expect(findMessage(APP, [...body, c >> 8, c & 0xff])).toBeUndefined();
    const ok16 = Uint8Array.from([L.toneMessageMax, ...new Array(L.toneMessageMax).fill(7)]);
    const c2 = crc32([new TextEncoder().encode(), ok16]) & 0xffff;
    expect(findMessage(APP, [...ok16, c2 >> 8, c2 & 0xff])).toEqual(ok16.slice(1));
  });

  it('refuses bad input with codes', () => {
    expect(encodeToneMessage(APP, new Uint8Array(0), ultra, 48000)).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
    expect(encodeToneMessage(APP, new Uint8Array(L.toneMessageMax + 1), ultra, 48000)).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
    expect(encodeToneMessage('Bad', MSG, ultra, 48000)).toEqual({
      ok: false,
      reason: 'bad-app-id',
    });
    expect(encodeToneMessage(APP, MSG, ultra, 22050)).toEqual({ ok: false, reason: 'bad-rate' });
    expect(decodeToneMessage(APP, new Float32Array(0), ultra, 48000)).toEqual({
      ok: false,
      reason: 'bad-samples',
    });
    expect(decodeToneMessage(APP, Float32Array.of(NaN, 0), ultra, 48000)).toEqual({
      ok: false,
      reason: 'bad-samples',
    });
    expect(decodeToneMessage(APP, [1, 2] as unknown as Float32Array, ultra, 48000)).toEqual({
      ok: false,
      reason: 'bad-samples',
    });
    expect(decodeToneMessage(APP, new Float32Array(48000), ultra, 48000)).toEqual({
      ok: false,
      reason: 'not-found',
    });
  });

  it('noise and the other plan never give a message (300 seeded noise buffers)', () => {
    for (let i = 0; i < 300; i++) {
      const buf = noise(24_000, 0.1 + (i % 10) / 10, 1000 + i);
      expect(decodeToneMessage(APP, buf, audible, 48000).ok, `noise ${i}`).toBe(false);
    }
    const a = ok(encodeToneMessage(APP, Uint8Array.of(1, 2), audible, 48000));
    expect(decodeToneMessage(APP, a, ultra, 48000).ok).toBe(false);
  });
});

describe('streaming listener', () => {
  it('finds the message from microphone-sized buffers of any size', () => {
    const MSG = Uint8Array.from([5, 6, 7]);
    const clean = ok(encodeToneMessage(APP, MSG, audible, 48000));
    for (const chunk of [128, 1000, 2048, 4096, 7777]) {
      const l = ok(createToneListener(APP, audible, 48000));
      let found: Uint8Array | undefined;
      const lead = new Float32Array(10_000);
      const all = new Float32Array(lead.length + clean.length + 20_000);
      all.set(clean, lead.length);
      for (let at = 0; at < all.length && !found; at += chunk) {
        const r = l.push(all.slice(at, at + chunk));
        if (r.ok) found = r.value;
      }
      expect(found, `chunk ${chunk}`).toEqual(MSG);
    }
  });

  it('gives the same as the one-shot decoder and reports not-found for silence and noise', () => {
    const l = ok(createToneListener(APP, audible, 48000));
    expect(l.push(new Float32Array(5000))).toEqual({ ok: false, reason: 'not-found' });
    expect(l.push(noise(50_000, 0.5, 3))).toEqual({ ok: false, reason: 'not-found' });
    expect(l.push(new Float32Array(0))).toEqual({ ok: false, reason: 'bad-samples' });
    expect(l.push(Float32Array.of(Infinity))).toEqual({ ok: false, reason: 'bad-samples' });
  });

  it('a long stream keeps the memory bounded (symbols are capped) and still decodes later', () => {
    const MSG = Uint8Array.from([1]);
    const l = ok(createToneListener(APP, audible, 48000));
    for (let i = 0; i < 60; i++) l.push(noise(48_000, 0.3, i + 1)); // 60 s of noise
    const clean = ok(encodeToneMessage(APP, MSG, audible, 48000));
    let found: Uint8Array | undefined;
    for (let at = 0; at < clean.length + 5000 && !found; at += 2048) {
      const r = l.push(
        clean.slice(at, at + 2048).length ? clean.slice(at, at + 2048) : new Float32Array(2048),
      );
      if (r.ok) found = r.value;
    }
    expect(found).toEqual(MSG);
  });

  it('refuses a bad configuration', () => {
    expect(createToneListener('Bad', audible, 48000)).toEqual({ ok: false, reason: 'bad-app-id' });
    expect(createToneListener(APP, ultra, 32000)).toEqual({ ok: false, reason: 'bad-rate' });
  });
});
