import { describe, expect, it } from 'vitest';
import {
  TRANSFER_LIMITS as L,
  blocksFor,
  createFountainReceiver,
  createFountainSender,
  frameFromText,
  frameToText,
  mixOf,
  parseFrame,
  type FountainReceiver,
  type FountainSender,
} from '../../src/transfer/index.ts';
import { crc32 } from '../../src/transfer/check.ts';
import { APP, bytes, rng } from './helpers.ts';

const ID = 0xabcdef01;

function sender(payload: Uint8Array, blockBytes: number, id = ID, appId = APP): FountainSender {
  const r = createFountainSender({ appId, payload, transferId: id, blockBytes });
  if (!r.ok) throw new Error(r.reason);
  return r.value;
}
function receiver(appId = APP, switchOnOther = false): FountainReceiver {
  const r = createFountainReceiver({ appId, switchOnOther });
  if (!r.ok) throw new Error(r.reason);
  return r.value;
}
const frame = (s: FountainSender, seq: number): Uint8Array => {
  const f = s.frame(seq);
  if (!f.ok) throw new Error(f.reason);
  return f.value;
};

/** Feeds frames in the given order until the receiver is complete; the number used. */
function feed(rx: FountainReceiver, s: FountainSender, seqs: Iterable<number>): number {
  let used = 0;
  for (const seq of seqs) {
    rx.add(frame(s, seq));
    used++;
    if (rx.status().complete) break;
  }
  return used;
}
function* from(start: number): Generator<number> {
  for (let n = start; ; n++) yield n;
}

const PAYLOAD = bytes(5000, 7);
const BLOCK = 400;
const K = blocksFor(PAYLOAD.length, BLOCK);

describe('frames with reserve (cases of the earlier implementation)', () => {
  it('a perfect scan needs exactly K frames and the first K carry the blocks as they are', () => {
    const s = sender(PAYLOAD, BLOCK);
    const rx = receiver();
    expect(feed(rx, s, from(0))).toBe(K);
    expect(rx.payload()).toEqual({ ok: true, value: PAYLOAD });
    expect(frame(s, 0)).toHaveLength(L.frameHeaderBytes + BLOCK + L.frameCheckBytes);
    expect(frame(s, 1).subarray(L.frameHeaderBytes, L.frameHeaderBytes + BLOCK)).toEqual(
      PAYLOAD.subarray(BLOCK, 2 * BLOCK),
    );
  });

  it('a missed frame costs only a few later frames, not a whole round', () => {
    const s = sender(PAYLOAD, BLOCK);
    const rx = receiver();
    feed(
      rx,
      s,
      Array.from({ length: K }, (_, i) => i).filter((i) => i !== 3),
    );
    expect(rx.status().complete).toBe(false);
    expect(feed(rx, s, from(K))).toBeLessThanOrEqual(5);
    expect(rx.payload()).toEqual({ ok: true, value: PAYLOAD });
  });

  it('rebuilds from mixed frames alone with about K + 2 frames', () => {
    const overheads = Array.from({ length: 25 }, (_, t) => {
      const s = sender(PAYLOAD, BLOCK, 1000 + t);
      const rx = receiver();
      const used = feed(rx, s, from(K));
      expect(rx.payload()).toEqual({ ok: true, value: PAYLOAD });
      return used - K;
    });
    expect(overheads.reduce((a, b) => a + b, 0) / overheads.length).toBeLessThan(3);
    expect(Math.max(...overheads)).toBeLessThan(10);
  });

  it('counts a frame read again apart from a frame without new information', () => {
    const s = sender(PAYLOAD, BLOCK);
    const rx = receiver();
    expect(rx.add(frame(s, 0))).toEqual({ ok: true, value: 'new' });
    expect(rx.add(frame(s, 0))).toEqual({ ok: true, value: 'repeat' });
    expect(rx.status()).toMatchObject({ rank: 1, redundant: 0, repeats: 1 });
    feed(
      rx,
      s,
      Array.from({ length: K }, (_, i) => i).filter((i) => i !== 0 && i !== 3),
    );
    const without3 = Array.from({ length: 200 }, (_, i) => K + i).find((seq) =>
      ((mixOf(ID, seq, K)[0] as number) >>> 3) & 1 ? false : true,
    ) as number;
    expect(rx.add(frame(s, without3))).toEqual({ ok: true, value: 'redundant' });
    expect(rx.status()).toMatchObject({ rank: K - 1, redundant: 1, repeats: 1 });
  });

  it('mixes the same blocks on both sides and never none', () => {
    expect(mixOf(ID, K + 5, K)).toEqual(mixOf(ID, K + 5, K));
    const bits = (w: Uint32Array): number =>
      [...w].reduce((n, x) => n + x.toString(2).replaceAll('0', '').length, 0);
    expect(bits(mixOf(ID, 2, K))).toBe(1);
    for (let seq = K; seq < K + 300; seq++) expect(bits(mixOf(ID, seq, K))).toBeGreaterThan(0);
    // the mix never reaches past the last block
    for (let seq = K; seq < K + 50; seq++) {
      const w = mixOf(ID, seq, 37);
      expect((w[1] as number) >>> 5).toBe(0);
    }
  });

  it('refuses foreign frames and damaged ones, without changing its progress', () => {
    const s = sender(PAYLOAD, BLOCK);
    const rx = receiver();
    expect(
      rx.add(new TextEncoder().encode('https://example.org/a/long/enough/url/to/be/a/frame')),
    ).toMatchObject({
      ok: false,
    });
    const old = frame(s, 1);
    old[0] = 1 + 1; // another version
    expect(rx.add(old)).toEqual({ ok: false, reason: 'bad-version' });
    const lying = frame(s, 1);
    new DataView(lying.buffer).setUint16(9, K + 3);
    expect(parseFrame(APP, lying)).toEqual({ ok: false, reason: 'bad-check' });
    expect(rx.status().rank).toBe(0);
  });

  it('a frame of another transfer is ignored, or starts over when asked to', () => {
    const s = sender(PAYLOAD, BLOCK);
    const other = sender(bytes(500, 1), BLOCK, 42);
    const stay = receiver();
    feed(stay, s, [0, 1, 2]);
    expect(stay.add(frame(other, 0))).toEqual({ ok: true, value: 'other-transfer' });
    expect(stay.status()).toMatchObject({ transferId: ID, rank: 3 });
    const sw = receiver(APP, true);
    feed(sw, s, [0, 1, 2]);
    sw.add(frame(other, 0));
    expect(sw.status()).toMatchObject({ transferId: 42, rank: 1 });
  });

  it('carries an empty payload in one block and refuses a block size below one', () => {
    const rx = receiver();
    rx.add(frame(sender(new Uint8Array(0), BLOCK, 1), 0));
    expect(rx.payload()).toEqual({ ok: true, value: new Uint8Array(0) });
    expect(
      createFountainSender({ appId: APP, payload: PAYLOAD, transferId: 1, blockBytes: 0 }),
    ).toEqual({
      ok: false,
      reason: 'bad-block-size',
    });
  });
});

describe('the integrity check', () => {
  it('a frame with a valid frame check but a changed data byte is caught by the payload check, and the transfer restarts', () => {
    const s = sender(PAYLOAD, BLOCK);
    const rx = receiver();
    // Build a frame that passes the frame check (the check is no secret) but lies in its data.
    const bad = frame(s, 2);
    bad[L.frameHeaderBytes + 5] = (bad[L.frameHeaderBytes + 5] as number) ^ 1;
    const end = bad.length - L.frameCheckBytes;
    // recompute the frame check with the same marker rule through a sender of the same app
    const forged = recheck(bad, end);
    expect(parseFrame(APP, forged).ok).toBe(true);
    const outcomes: string[] = [];
    for (let seq = 0; seq < K; seq++) {
      const r = rx.add(seq === 2 ? forged : frame(s, seq));
      outcomes.push(r.ok ? r.value : r.reason);
    }
    expect(outcomes.at(-1)).toBe('check-failed');
    expect(rx.status()).toMatchObject({ complete: false, rank: 0, checkFailures: 1 });
    expect(rx.payload()).toEqual({ ok: false, reason: 'incomplete' });
    // collecting again from honest frames succeeds
    feed(rx, s, from(0));
    expect(rx.payload()).toEqual({ ok: true, value: PAYLOAD });
  });

  it('non-zero padding after the payload is refused even when the payload check could pass', () => {
    // A 5-byte payload in blocks of 4: the second block has 3 padding bytes.
    const p = bytes(5, 3);
    const s = sender(p, 4);
    const rx = receiver();
    rx.add(frame(s, 0));
    const f1 = frame(s, 1);
    f1[L.frameHeaderBytes + 3] = 0xff; // padding byte
    const r = rx.add(recheck(f1, f1.length - L.frameCheckBytes));
    expect(r).toEqual({ ok: true, value: 'check-failed' });
  });

  it('frames of another app are refused', () => {
    const s = sender(PAYLOAD, BLOCK, ID, 'other');
    expect(receiver().add(frame(s, 0))).toEqual({ ok: false, reason: 'bad-check' });
  });
});

/** Recomputes the frame check of a (tampered) frame the way an attacker could. */
function recheck(f: Uint8Array, end: number): Uint8Array {
  const out = f.slice();
  const crc = crcWithDomain(out.subarray(0, end));
  new DataView(out.buffer).setUint32(end, crc);
  return out;
}

function crcWithDomain(body: Uint8Array): number {
  return crc32([new TextEncoder().encode(`${APP}-qr:1`), body]);
}

describe('schedules: loss, reorder, duplicates (seeded)', () => {
  it('property: any received set that decodes yields exactly the payload (300 schedules)', () => {
    for (let t = 0; t < 300; t++) {
      const r = rng(900 + t);
      const size = Math.floor(r() * 3000);
      const blockBytes = Math.max(1 + Math.floor(r() * 300), Math.ceil(size / 1_000));
      const payload = bytes(size, 50 + t);
      const s = sender(payload, blockBytes, Math.floor(r() * 4294967296));
      const rx = receiver();
      const loss = r() * 0.7;
      let sent = 0;
      for (let seq = 0; sent < 4000 && !rx.status().complete; seq++) {
        sent++;
        if (r() < loss) continue; // lost
        const f = frame(s, seq);
        rx.add(f);
        if (r() < 0.3) rx.add(f); // duplicate
        if (r() < 0.2) rx.add(frame(s, Math.floor(r() * (seq + 1)))); // an old one again, out of order
      }
      expect(rx.status().complete, `schedule ${t}`).toBe(true);
      expect(rx.payload()).toEqual({ ok: true, value: payload });
    }
  });

  it('reordered frames: a shuffle of the first 2K frames always completes with the exact payload', () => {
    for (let t = 0; t < 40; t++) {
      const r = rng(77 + t);
      const s = sender(PAYLOAD, BLOCK, 5 + t);
      const seqs = Array.from({ length: 2 * K }, (_, i) => i);
      for (let i = seqs.length - 1; i > 0; i--) {
        const j = Math.floor(r() * (i + 1));
        [seqs[i], seqs[j]] = [seqs[j] as number, seqs[i] as number];
      }
      const rx = receiver();
      feed(rx, s, seqs);
      expect(rx.payload()).toEqual({ ok: true, value: PAYLOAD });
    }
  });

  it('a partial set never yields a payload', () => {
    const s = sender(PAYLOAD, BLOCK);
    const rx = receiver();
    feed(
      rx,
      s,
      Array.from({ length: K - 1 }, (_, i) => i),
    );
    expect(rx.payload()).toEqual({ ok: false, reason: 'incomplete' });
  });
});

describe('tamper and fuzz of frames', () => {
  const s = sender(bytes(900, 4), 100);
  const good = frame(s, 3);

  it('every single-bit change of a frame is refused', () => {
    for (let i = 0; i < good.length; i++)
      for (let b = 0; b < 8; b++) {
        const f = good.slice();
        f[i] = (f[i] as number) ^ (1 << b);
        expect(parseFrame(APP, f).ok, `byte ${i} bit ${b}`).toBe(false);
      }
  });

  it('truncations and extensions are refused', () => {
    for (let n = 0; n < good.length; n++)
      expect(parseFrame(APP, good.subarray(0, n)).ok).toBe(false);
    const longer = new Uint8Array(good.length + 1);
    longer.set(good);
    expect(parseFrame(APP, longer).ok).toBe(false);
  });

  it('2000 seeded random inputs never throw and never parse', () => {
    const r = rng(5);
    for (let i = 0; i < 2000; i++) {
      const f = bytes(Math.floor(r() * 200), i);
      if (r() < 0.5 && f.length > 0) f[0] = 1;
      expect(parseFrame(APP, f).ok).toBe(false);
    }
  });

  it('non-array input and bad app ids give codes', () => {
    expect(parseFrame(APP, 'text' as unknown).ok).toBe(false);
    expect(parseFrame(APP, null).ok).toBe(false);
    expect(parseFrame('Bad Id', good)).toEqual({ ok: false, reason: 'bad-app-id' });
    expect(createFountainReceiver({ appId: 'x' })).toEqual({ ok: false, reason: 'bad-app-id' });
  });

  it('forged headers with a matching check are refused for their numbers', () => {
    const forge = (patch: (v: DataView) => void): Uint8Array => {
      const f = good.slice();
      patch(new DataView(f.buffer));
      return recheck(f, f.length - 4);
    };
    expect(
      parseFrame(
        APP,
        forge((v) => v.setUint16(9, 0)),
      ),
    ).toEqual({ ok: false, reason: 'bad-blocks' });
    expect(
      parseFrame(
        APP,
        forge((v) => v.setUint16(9, 1025)),
      ),
    ).toEqual({ ok: false, reason: 'bad-blocks' });
    expect(
      parseFrame(
        APP,
        forge((v) => v.setUint32(11, L.payloadMax + 1)),
      ),
    ).toEqual({
      ok: false,
      reason: 'bad-blocks',
    });
    expect(
      parseFrame(
        APP,
        forge((v) => v.setUint32(5, L.seqMax + 1)),
      ),
    ).toEqual({
      ok: false,
      reason: 'bad-blocks',
    });
    expect(
      parseFrame(
        APP,
        forge((v) => v.setUint32(11, 901)),
      ).ok,
    ).toBe(false); // blocks no longer fit the length
    expect(
      parseFrame(
        APP,
        forge(() => undefined),
      ).ok,
    ).toBe(true);
  });
});

describe('boundaries and limits', () => {
  it('a payload length over the limit is refused although blocks and block size would fit it', () => {
    const f = new Uint8Array(L.frameBytesMax);
    const v = new DataView(f.buffer);
    f[0] = 1;
    v.setUint16(9, 1_024);
    v.setUint32(11, L.payloadMax + 1); // 1024 blocks of 2048 would hold 2 MiB
    const end = f.length - 4;
    v.setUint32(end, crcWithDomain(f.subarray(0, end)));
    expect(parseFrame(APP, f)).toEqual({ ok: false, reason: 'bad-blocks' });
    v.setUint32(11, L.payloadMax);
    v.setUint32(end, crcWithDomain(f.subarray(0, end)));
    expect(parseFrame(APP, f).ok).toBe(true);
  });

  it('the largest number of blocks with one-octet blocks round-trips', () => {
    const p = bytes(L.blocksMax, 11);
    const s = sender(p, 1);
    expect(s.blocks).toBe(L.blocksMax);
    const rx = receiver();
    expect(feed(rx, s, from(0))).toBe(L.blocksMax);
    expect(rx.payload()).toEqual({ ok: true, value: p });
  });

  it('the largest payload with the largest-useful block size round-trips (elimination at full size)', () => {
    const p = bytes(L.payloadMax, 12);
    const s = sender(p, 1_024);
    expect(s.blocks).toBe(1_024);
    const rx = receiver();
    // a lossy start: skip every 7th systematic frame, the mixed ones fill in
    const seqs = [...Array.from({ length: 1_024 }, (_, i) => i).filter((i) => i % 7 !== 0)];
    for (let q = 1_024; q < 1_400; q++) seqs.push(q);
    feed(rx, s, seqs);
    expect(rx.payload()).toEqual({ ok: true, value: p });
  }, 60_000);

  it('refuses what is over the limits', () => {
    const mk = (payload: Uint8Array, blockBytes: number, transferId = 1) =>
      createFountainSender({ appId: APP, payload, transferId, blockBytes });
    expect(mk(new Uint8Array(L.payloadMax + 1), 2_048)).toEqual({ ok: false, reason: 'too-large' });
    expect(mk(new Uint8Array(L.payloadMax), 1_023)).toEqual({ ok: false, reason: 'too-large' });
    expect(mk(new Uint8Array(10), L.blockBytesMax + 1)).toEqual({
      ok: false,
      reason: 'bad-block-size',
    });
    expect(mk(new Uint8Array(10), 1.5)).toEqual({ ok: false, reason: 'bad-block-size' });
    expect(mk(new Uint8Array(10), 4, -1)).toEqual({ ok: false, reason: 'bad-transfer-id' });
    expect(mk(new Uint8Array(10), 4, 2 ** 32)).toEqual({ ok: false, reason: 'bad-transfer-id' });
    expect(mk('x' as unknown as Uint8Array, 4)).toEqual({ ok: false, reason: 'bad-payload' });
    const s = sender(bytes(10, 1), 4);
    expect(s.frame(L.seqMax + 1)).toEqual({ ok: false, reason: 'bad-seq' });
    expect(s.frame(-1)).toEqual({ ok: false, reason: 'bad-seq' });
    expect(s.frame(L.seqMax).ok).toBe(true);
  });

  it('the largest frame is within the stated octet and character limits', () => {
    const s = sender(bytes(10_000, 1), L.blockBytesMax);
    const f = frame(s, 0);
    expect(f.length).toBe(L.frameBytesMax);
    expect(frameToText(f).length).toBeLessThanOrEqual(L.frameCharsMax);
    expect(frameToText(f).length).toBe(L.frameCharsMax);
  });

  it('next() walks the sequence from 0 and a copy of the payload is taken', () => {
    const p = bytes(100, 2);
    const s = sender(p, 10);
    p.fill(0);
    const a = s.next();
    expect(a.ok && a.value).toEqual(frame(s, 0));
    const b = s.next();
    expect(b.ok && b.value).toEqual(frame(s, 1));
    const rx = receiver();
    for (let i = 0; i < 10; i++) {
      const f = s.frame(i);
      if (f.ok) rx.add(f.value);
    }
    expect(rx.payload().ok).toBe(true);
  });

  it('the receiver refuses frames beyond its frame budget', () => {
    const s = sender(bytes(400, 9), 1);
    const r = createFountainReceiver({ appId: APP, framesMax: 50 });
    if (!r.ok) throw new Error(r.reason);
    // 400 one-octet blocks cannot be complete after 50 frames: the 51st is refused
    let last: unknown;
    for (let seq = 0; seq < 51; seq++) last = r.value.add(frame(s, seq));
    expect(last).toEqual({ ok: false, reason: 'too-many-frames' });
    expect(r.value.status().rank).toBe(50);
    expect(createFountainReceiver({ appId: APP, framesMax: L.framesMax + 1 }).ok).toBe(false);
  });
});

describe('text form', () => {
  it('round-trips and reads one spelling only', () => {
    const f = frame(sender(bytes(30, 1), 10), 4);
    const text = frameToText(f);
    expect(frameFromText(text)).toEqual({ ok: true, value: f });
    expect(receiver().add(text).ok).toBe(true);
    expect(frameFromText(text + '=').ok).toBe(false);
    expect(frameFromText(text.replace(/[A-Za-z]/, '+')).ok).toBe(false);
    expect(frameFromText('').ok).toBe(false);
    expect(frameFromText('x'.repeat(L.frameCharsMax + 1)).ok).toBe(false);
    expect(frameFromText(5 as unknown).ok).toBe(false);
    // a non-canonical final character decodes to the same bytes but is refused
    const last = text.at(-1) as string;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    if (text.length % 4 !== 0) {
      const alt = alphabet[(alphabet.indexOf(last) + 1) % 64] as string;
      expect(frameFromText(text.slice(0, -1) + alt).ok).toBe(false);
    }
  });
});
