import { describe, expect, it } from 'vitest';
import {
  FRAMING_LIMITS,
  FrameAssembler,
  RELAY_LIMITS,
  frameMark,
  readFrame,
  splitPayload,
  type FramingLimits,
} from '../../src/relay/index.ts';
import { mulberry32 } from './helpers.ts';

const SENDER = `geraet-${'ab12'.repeat(8)}`;
const OTHER = `geraet-${'cd34'.repeat(8)}`;
const ID = '0123456789abcdef';
const ID2 = 'fedcba9876543210';

function payload(n: number, seed = 1): Uint8Array {
  const rng = mulberry32(seed);
  return Uint8Array.from({ length: n }, () => Math.floor(rng() * 256));
}

function frames(bytes: Uint8Array, id = ID, limits: FramingLimits = FRAMING_LIMITS): Uint8Array[] {
  const r = splitPayload('alpha', bytes, id, limits);
  if (!r.ok) throw new Error(r.reason);
  return [...r.frames];
}

const small: FramingLimits = { ...FRAMING_LIMITS, partBytes: 10 };

describe('framing: split and read', () => {
  it('round trip of payloads from 1 byte to several parts, in any order', () => {
    for (const n of [1, 9, 10, 11, 25, 100, 40_000, 40_001, 120_000]) {
      const data = payload(n, n);
      const fs = frames(data);
      expect(fs.length).toBe(Math.ceil(n / FRAMING_LIMITS.partBytes));
      for (const f of fs) expect(f.length).toBeLessThanOrEqual(RELAY_LIMITS.maxContentBytes);
      const a = new FrameAssembler('alpha');
      const order = [...fs.keys()].sort((x, y) => ((x * 7919) % 13) - ((y * 7919) % 13) || x - y);
      let done;
      for (const i of order) {
        const r = a.accept(SENDER, fs[i] as Uint8Array, 1000);
        if (r.kind === 'complete') done = r;
      }
      expect(done?.kind).toBe('complete');
      expect([...(done as { payload: Uint8Array }).payload]).toEqual([...data]);
      expect(a.bufferedBytes).toBe(0);
      expect(a.transferCount).toBe(0);
    }
  });

  it('limits at the boundary: parts, payload size, empty, bad id, bad app', () => {
    const maxParts = { ...FRAMING_LIMITS, partBytes: 10, maxParts: 5, maxPayloadBytes: 1000 };
    expect(splitPayload('alpha', payload(50), ID, maxParts).ok).toBe(true);
    expect(splitPayload('alpha', payload(51), ID, maxParts)).toEqual({
      ok: false,
      reason: 'too-large',
    });
    const maxBytes = { ...FRAMING_LIMITS, partBytes: 10, maxParts: 500, maxPayloadBytes: 100 };
    expect(splitPayload('alpha', payload(100), ID, maxBytes).ok).toBe(true);
    expect(splitPayload('alpha', payload(101), ID, maxBytes)).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect(splitPayload('alpha', new Uint8Array(0), ID)).toEqual({ ok: false, reason: 'empty' });
    expect(splitPayload('alpha', payload(5), 'XYZ')).toEqual({ ok: false, reason: 'bad-id' });
    expect(splitPayload('alpha', payload(5), ID.toUpperCase())).toEqual({
      ok: false,
      reason: 'bad-id',
    });
    expect(splitPayload('Alpha', payload(5), ID)).toEqual({ ok: false, reason: 'bad-app' });
    // a part size that cannot fit one relay message
    expect(
      splitPayload('alpha', payload(70_000), ID, { ...FRAMING_LIMITS, partBytes: 60_000 }),
    ).toEqual({
      ok: false,
      reason: 'bad-limits',
    });
    // the largest default payload splits within the part count
    expect(splitPayload('alpha', new Uint8Array(FRAMING_LIMITS.maxPayloadBytes), ID).ok).toBe(true);
    expect(FRAMING_LIMITS.maxParts * FRAMING_LIMITS.partBytes).toBeGreaterThanOrEqual(
      FRAMING_LIMITS.maxPayloadBytes,
    );
  });

  it('the frame is one spelling and the marker names the app', () => {
    expect(frameMark('alpha')).toBe('alpha-frame:1');
    expect(frameMark('Alpha')).toBeUndefined();
    const f = frames(payload(5))[0] as Uint8Array;
    const text = new TextDecoder().decode(f);
    expect(text).toMatch(
      /^\{"m":"alpha-frame:1","t":"part","id":"0123456789abcdef","i":0,"n":1,"d":"[A-Za-z0-9_-]+"\}$/,
    );
    expect(readFrame('alpha', f)).toMatchObject({ id: ID, index: 0, count: 1 });
    expect(readFrame('beta', f)).toBeUndefined(); // another app's marker
    const respelled = new TextEncoder().encode(text.replace('"t":"part",', '"t":"part", '));
    expect(readFrame('alpha', respelled)).toBeUndefined();
    const reordered = new TextEncoder().encode(text.replace(/"i":0,"n":1/, '"n":1,"i":0'));
    expect(readFrame('alpha', reordered)).toBeUndefined();
    const padded = new TextEncoder().encode(text.replace(/"d":"([^"]+)"/, '"d":"$1="'));
    expect(readFrame('alpha', padded)).toBeUndefined();
  });

  it('readFrame refuses index/count outside the limits and oversized frames', () => {
    const mk = (i: number, n: number, d = 'AQID'): Uint8Array =>
      new TextEncoder().encode(
        `{"m":"alpha-frame:1","t":"part","id":"${ID}","i":${i},"n":${n},"d":"${d}"}`,
      );
    expect(readFrame('alpha', mk(0, 1))).toBeDefined();
    expect(readFrame('alpha', mk(1, 1))).toBeUndefined();
    expect(readFrame('alpha', mk(-1, 2))).toBeUndefined();
    expect(readFrame('alpha', mk(0, 0))).toBeUndefined();
    expect(readFrame('alpha', mk(0, FRAMING_LIMITS.maxParts))).toBeDefined();
    expect(readFrame('alpha', mk(0, FRAMING_LIMITS.maxParts + 1))).toBeUndefined();
    expect(readFrame('alpha', mk(0, 1, ''))).toBeUndefined();
    expect(readFrame('alpha', new Uint8Array(RELAY_LIMITS.maxContentBytes + 1))).toBeUndefined();
    expect(readFrame('alpha', 'text')).toBeUndefined();
    expect(readFrame('alpha', new Uint8Array([0xff, 0xfe]))).toBeUndefined();
  });
});

describe('framing: reassembly', () => {
  it('an identical duplicate is ignored and counted once, a conflicting duplicate is refused and the first stays', () => {
    const data = payload(35);
    const fs = frames(data, ID, small);
    expect(fs.length).toBe(4);
    const a = new FrameAssembler('alpha', small);
    expect(a.accept(SENDER, fs[0] as Uint8Array, 0).kind).toBe('pending');
    const held = a.bufferedBytes;
    expect(a.accept(SENDER, fs[0] as Uint8Array, 1).kind).toBe('duplicate');
    expect(a.accept(SENDER, fs[0] as Uint8Array, 2).kind).toBe('duplicate');
    expect(a.bufferedBytes).toBe(held);
    // the same part with other bytes
    const evil = frames(payload(35, 9), ID, small)[0] as Uint8Array;
    expect(a.accept(SENDER, evil, 3)).toEqual({ kind: 'refused', reason: 'conflicting-duplicate' });
    expect(a.bufferedBytes).toBe(held);
    for (const i of [1, 2]) expect(a.accept(SENDER, fs[i] as Uint8Array, 4).kind).toBe('pending');
    const done = a.accept(SENDER, fs[3] as Uint8Array, 5);
    expect(done.kind).toBe('complete');
    expect([...(done as { payload: Uint8Array }).payload]).toEqual([...data]); // the first part stayed
  });

  it('a duplicate of the last part does not complete a payload twice', () => {
    const fs = frames(payload(25), ID, small);
    const a = new FrameAssembler('alpha', small);
    a.accept(SENDER, fs[0] as Uint8Array, 0);
    a.accept(SENDER, fs[1] as Uint8Array, 0);
    expect(a.accept(SENDER, fs[2] as Uint8Array, 0).kind).toBe('complete');
    // the payload is gone; the same frame now starts a new transfer (it is not a duplicate of anything)
    expect(a.accept(SENDER, fs[2] as Uint8Array, 0).kind).toBe('pending');
  });

  it('the same id from two senders stays apart', () => {
    const d1 = payload(25, 1);
    const d2 = payload(25, 2);
    const f1 = frames(d1, ID, small);
    const f2 = frames(d2, ID, small);
    const a = new FrameAssembler('alpha', small);
    const outs: Uint8Array[] = [];
    for (let i = 0; i < 3; i += 1) {
      for (const [who, f] of [
        [SENDER, f1],
        [OTHER, f2],
      ] as const) {
        const r = a.accept(who, f[i] as Uint8Array, 0);
        if (r.kind === 'complete') outs.push(r.payload);
      }
    }
    expect(outs.map((o) => [...o])).toEqual([[...d1], [...d2]]);
  });

  it('a part with another count, a part of another app, bad sender and bad time are refused and change nothing', () => {
    const a = new FrameAssembler('alpha', small);
    const fs = frames(payload(25), ID, small);
    a.accept(SENDER, fs[0] as Uint8Array, 0);
    const held = a.bufferedBytes;
    const other = frames(payload(40), ID, small)[1] as Uint8Array; // same id, count 4
    expect(a.accept(SENDER, other, 0)).toEqual({ kind: 'refused', reason: 'count-mismatch' });
    const beta = splitPayload('beta', payload(5), ID);
    expect(beta.ok && a.accept(SENDER, beta.frames[0] as Uint8Array, 0)).toEqual({
      kind: 'refused',
      reason: 'malformed',
    });
    expect(a.accept('nobody', fs[1] as Uint8Array, 0)).toEqual({
      kind: 'refused',
      reason: 'bad-sender',
    });
    expect(a.accept(SENDER, fs[1] as Uint8Array, Number.NaN)).toEqual({
      kind: 'refused',
      reason: 'bad-time',
    });
    expect(a.accept(SENDER, new Uint8Array([1, 2, 3]), 0)).toEqual({
      kind: 'refused',
      reason: 'malformed',
    });
    expect(a.bufferedBytes).toBe(held);
    expect(a.transferCount).toBe(1);
  });

  it('a missing part: the transfer waits, and is dropped after holdMs, not before', () => {
    const lim = { ...small, holdMs: 1000 };
    const fs = frames(payload(25), ID, lim);
    const a = new FrameAssembler('alpha', lim);
    a.accept(SENDER, fs[0] as Uint8Array, 5000);
    a.accept(SENDER, fs[1] as Uint8Array, 5500);
    expect(a.sweep(5999)).toEqual([]);
    expect(a.transferCount).toBe(1);
    expect(a.sweep(6000)).toEqual([{ from: SENDER, id: ID }]);
    expect(a.transferCount).toBe(0);
    expect(a.bufferedBytes).toBe(0);
    // the late last part starts a fresh incomplete transfer, it does not complete the old one
    expect(a.accept(SENDER, fs[2] as Uint8Array, 6500).kind).toBe('pending');
    // a clock that goes back drops nothing
    expect(a.sweep(0)).toEqual([]);
  });

  it('time passing inside accept drops an expired transfer first', () => {
    const lim = { ...small, holdMs: 1000 };
    const fs = frames(payload(25), ID, lim);
    const a = new FrameAssembler('alpha', lim);
    a.accept(SENDER, fs[0] as Uint8Array, 0);
    a.accept(SENDER, fs[1] as Uint8Array, 2000); // the first part is older than holdMs: a new transfer
    expect(a.transferCount).toBe(1);
    expect(a.accept(SENDER, fs[2] as Uint8Array, 2001).kind).toBe('pending');
  });

  it('oversized payloads are refused by the running sum, the state stays', () => {
    const lim: FramingLimits = { ...small, maxPayloadBytes: 25, maxParts: 200 };
    const parts = [0, 1, 2].map((i) =>
      new TextEncoder().encode(
        `{"m":"alpha-frame:1","t":"part","id":"${ID}","i":${i},"n":3,"d":"${Buffer.alloc(10, i + 1).toString('base64url')}"}`,
      ),
    );
    const a = new FrameAssembler('alpha', lim);
    expect(a.accept(SENDER, parts[0] as Uint8Array, 0).kind).toBe('pending');
    expect(a.accept(SENDER, parts[1] as Uint8Array, 0).kind).toBe('pending');
    expect(a.accept(SENDER, parts[2] as Uint8Array, 0)).toEqual({
      kind: 'refused',
      reason: 'too-large',
    });
    expect(a.bufferedBytes).toBe(20);
  });

  it('a fifth incomplete transfer from one sender pushes out the oldest', () => {
    const a = new FrameAssembler('alpha', small);
    const ids = [
      '0000000000000001',
      '0000000000000002',
      '0000000000000003',
      '0000000000000004',
      '0000000000000005',
    ];
    for (const [i, id] of ids.entries())
      a.accept(SENDER, frames(payload(25), id, small)[0] as Uint8Array, i);
    expect(a.transferCount).toBe(4);
    // the first transfer is gone: its second part starts a new one instead of completing anything
    const first = frames(payload(25), ids[0] as string, small);
    expect(a.accept(SENDER, first[1] as Uint8Array, 10).kind).toBe('pending');
    expect(a.transferCount).toBe(4);
    expect(a.bufferedBytes).toBe(4 * 10);
  });

  it('too many senders and a full buffer are refused, state unchanged', () => {
    const lim: FramingLimits = { ...small, maxSenders: 2, maxBufferedBytes: 30 };
    const a = new FrameAssembler('alpha', lim);
    const sender = (n: number): string => `geraet-${n.toString(16).padStart(32, '0')}`;
    expect(a.accept(sender(1), frames(payload(25), ID, lim)[0] as Uint8Array, 0).kind).toBe(
      'pending',
    );
    expect(a.accept(sender(2), frames(payload(25), ID, lim)[0] as Uint8Array, 0).kind).toBe(
      'pending',
    );
    expect(a.accept(sender(3), frames(payload(25), ID, lim)[0] as Uint8Array, 0)).toEqual({
      kind: 'refused',
      reason: 'too-many-senders',
    });
    expect(a.accept(sender(1), frames(payload(25), ID2, lim)[0] as Uint8Array, 0).kind).toBe(
      'pending',
    ); // 30 bytes
    expect(
      a.accept(sender(1), frames(payload(25), '1111111111111111', lim)[0] as Uint8Array, 0),
    ).toEqual({ kind: 'refused', reason: 'buffer-full' });
    expect(a.bufferedBytes).toBe(30);
    expect(a.transferCount).toBe(3);
  });

  it('memory and work stay bounded under a flood of random frames from many senders', () => {
    const lim: FramingLimits = { ...FRAMING_LIMITS, partBytes: 2000, maxBufferedBytes: 200_000 };
    const a = new FrameAssembler('alpha', lim);
    const rng = mulberry32(5);
    const part = payload(lim.partBytes, 3);
    for (let i = 0; i < 4000; i += 1) {
      const id = Math.floor(rng() * 2 ** 32)
        .toString(16)
        .padStart(16, '0');
      const sender = `geraet-${Math.floor(rng() * 200)
        .toString(16)
        .padStart(32, '0')}`;
      const frame = new TextEncoder().encode(
        `{"m":"alpha-frame:1","t":"part","id":"${id}","i":0,"n":200,"d":"${Buffer.from(part).toString('base64url')}"}`,
      );
      a.accept(sender, frame, i);
      expect(a.bufferedBytes).toBeLessThanOrEqual(lim.maxBufferedBytes);
      expect(a.transferCount).toBeLessThanOrEqual(lim.maxSenders * lim.maxTransfersPerSender);
    }
  });

  it('never throws on random input', () => {
    const rng = mulberry32(77);
    const a = new FrameAssembler('alpha', small);
    const good = frames(payload(25), ID, small);
    for (let i = 0; i < 3500; i += 1) {
      const base = [...(good[Math.floor(rng() * good.length)] as Uint8Array)];
      const mode = i % 3;
      let bytes: Uint8Array;
      if (mode === 0)
        bytes = Uint8Array.from(base.map((b) => (rng() < 0.05 ? Math.floor(rng() * 256) : b)));
      else if (mode === 1) bytes = Uint8Array.from(base.slice(0, Math.floor(rng() * base.length)));
      else
        bytes = Uint8Array.from({ length: Math.floor(rng() * 200) }, () => Math.floor(rng() * 256));
      expect(() => a.accept(rng() < 0.9 ? SENDER : 'x', bytes, i)).not.toThrow();
      expect(() => readFrame('alpha', bytes, small)).not.toThrow();
    }
  });
});
