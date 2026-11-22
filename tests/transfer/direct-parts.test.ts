// The pure parts of the direct connection: texts, handshake machine, chunks, network reading.
import { describe, expect, it } from 'vitest';
import {
  ChunkAssembler,
  HANDSHAKE_DEFAULTS,
  TRANSFER_LIMITS as L,
  addressKind,
  candidatesOfSdp,
  chosenPath,
  chunkMessage,
  directStep,
  fingerprintsOf,
  handshakeConfigProblem,
  initialState,
  parseCandidate,
  pathKind,
  readChunk,
  readDirectText,
  readSdp,
  reachability,
  writeDirectText,
  type DirectEvent,
  type DirectState,
  type DirectText,
} from '../../src/transfer/index.ts';
import { FakePeer } from './direct-fakes.ts';
import { APP, bytes, rng } from './helpers.ts';

const SESSION = '0123456789abcdef';
const SDP = [
  'v=0',
  'o=- 1 2 IN IP4 127.0.0.1',
  's=-',
  't=0 0',
  'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
  'c=IN IP4 0.0.0.0',
  'a=fingerprint:sha-256 AA:BB:CC:DD',
  'a=candidate:1 1 udp 2122260223 192.168.1.20 54321 typ host',
  '',
].join('\r\n');
const offer: DirectText = { role: 'offer', session: SESSION, sdp: SDP };

describe('texts', () => {
  it('round-trip and carry the marker of the app', () => {
    const t = writeDirectText(APP, offer);
    expect(t.ok && t.value.startsWith('demo-direct:1.offer.0123456789abcdef.')).toBe(true);
    expect(readDirectText(APP, t.ok ? t.value : '')).toEqual({ ok: true, value: offer });
    const a = writeDirectText(APP, { ...offer, role: 'answer' });
    expect(readDirectText(APP, a.ok ? a.value : '')).toEqual({
      ok: true,
      value: { ...offer, role: 'answer' },
    });
  });

  it('another app does not read it', () => {
    const t = writeDirectText(APP, offer);
    expect(readDirectText('other', t.ok ? t.value : '')).toEqual({
      ok: false,
      reason: 'bad-marker',
    });
    expect(readDirectText('No!', 'x')).toEqual({ ok: false, reason: 'bad-app-id' });
    expect(writeDirectText('No!', offer)).toEqual({ ok: false, reason: 'bad-app-id' });
  });

  it('refuses every damaged spelling with a code', () => {
    const good = writeDirectText(APP, offer);
    const text = good.ok ? good.value : '';
    const [m, role, session, body] = text.split('.') as [string, string, string, string];
    const cases: [string, string][] = [
      ['five parts', `${text}.x`],
      ['three parts', `${m}.${role}.${session}`],
      ['role', `${m}.Offer.${session}.${body}`],
      ['role word', `${m}.both.${session}.${body}`],
      [
        'session upper-case',
        `${m}.${role}.${session.toUpperCase().replace(/[0-9]/g, 'A')}.${body}`,
      ],
      ['session short', `${m}.${role}.0123.${body}`],
      ['padding', `${m}.${role}.${session}.${body}=`],
      ['not base64url', `${m}.${role}.${session}.${body.slice(0, 4)}+${body.slice(5)}`],
      ['empty body', `${m}.${role}.${session}.`],
      ['trailing space', `${text} `],
      ['leading space', ` ${text}`],
    ];
    for (const [name, c] of cases) expect(readDirectText(APP, c).ok, name).toBe(false);
    expect(readDirectText(APP, 5)).toEqual({ ok: false, reason: 'not-text' });
    expect(readDirectText(APP, 'x'.repeat(L.textCharsMax + 1))).toEqual({
      ok: false,
      reason: 'too-long',
    });
  });

  it('an SDP is a data channel and nothing else', () => {
    expect(readSdp(SDP).ok).toBe(true);
    const bad = (s: string): boolean => readSdp(s).ok;
    expect(
      bad(SDP.replace('m=application 9 UDP/DTLS/SCTP webrtc-datachannel', 'm=video 9 RTP/AVP 96')),
    ).toBe(false);
    expect(bad(SDP.replace('m=application', 'm=audio'))).toBe(false);
    expect(bad(SDP.replace('a=fingerprint:sha-256 AA:BB:CC:DD\r\n', ''))).toBe(false);
    expect(bad(SDP.replace('sha-256 AA:BB:CC:DD', 'md5 AA'))).toBe(false);
    expect(bad(SDP.replace('sha-256 AA:BB:CC:DD', 'sha-256 AA:BB:ZZ'))).toBe(false);
    expect(bad(SDP + 'm=application 9 UDP/DTLS/SCTP x\r\n')).toBe(false); // two media sections
    expect(bad(SDP.replace('v=0', 'v=1'))).toBe(false);
    expect(bad(SDP.replace(/\r\n/g, '\n'))).toBe(false);
    expect(bad(SDP.slice(0, -2))).toBe(false); // no final CRLF
    expect(bad(SDP + 'garbage\r\n')).toBe(false);
    expect(bad(SDP + 'a=xé\r\n')).toBe(false);
    expect(bad(SDP + 'a=' + 'x'.repeat(L.sdpLineCharsMax) + '\r\n')).toBe(false);
    expect(bad(SDP + 'a=x\r\n'.repeat(L.sdpLinesMax))).toBe(false);
    expect(bad(SDP + 'a=' + 'x'.repeat(L.sdpCharsMax) + '\r\n')).toBe(false);
    expect(bad(SDP + 'a=x\u0000\r\n')).toBe(false);
    expect(bad(SDP.replace('s=-', 's=é'))).toBe(false);
    expect(readSdp(7 as unknown).ok).toBe(false);
    expect(readSdp('').ok).toBe(false);
  });

  it('a description made by the fake peer passes, a real-looking line mix passes', () => {
    const sdp = (
      new FakePeer() as unknown as { description(t: string): { sdp: string } }
    ).description('offer').sdp;
    expect(readSdp(sdp).ok).toBe(true);
    expect(fingerprintsOf(sdp)).toHaveLength(1);
    expect(fingerprintsOf(SDP)).toEqual(['SHA-256 AA:BB:CC:DD']);
  });

  it('the longest allowed description still fits the text limit', () => {
    const filler = 'a=x' + 'y'.repeat(L.sdpLineCharsMax - 4) + '\r\n';
    let sdp = SDP;
    while (
      sdp.length + filler.length <= L.sdpCharsMax &&
      sdp.split('\r\n').length < L.sdpLinesMax - 1
    )
      sdp += filler;
    expect(readSdp(sdp).ok).toBe(true);
    expect(writeDirectText(APP, { ...offer, sdp }).ok).toBe(true);
  });

  it('2000 seeded mutations of a good text never throw and never read as the original', () => {
    const good = writeDirectText(APP, offer);
    const text = good.ok ? good.value : '';
    const r = rng(21);
    for (let i = 0; i < 2000; i++) {
      const at = Math.floor(r() * text.length);
      const ch = String.fromCharCode(32 + Math.floor(r() * 95));
      if (ch === text[at]) continue;
      const res = readDirectText(APP, text.slice(0, at) + ch + text.slice(at + 1));
      if (res.ok) expect(res.value).not.toEqual(offer);
    }
  });

  it('refuses a writer given a bad role, session or description', () => {
    expect(writeDirectText(APP, { ...offer, role: 'x' as 'offer' })).toEqual({
      ok: false,
      reason: 'bad-role',
    });
    expect(writeDirectText(APP, { ...offer, session: 'nope' })).toEqual({
      ok: false,
      reason: 'bad-session',
    });
    expect(writeDirectText(APP, { ...offer, sdp: 'v=0\r\n' })).toEqual({
      ok: false,
      reason: 'bad-sdp',
    });
  });
});

describe('chunks', () => {
  const DATA = L.chunkBytes - L.chunkHeaderBytes;

  it('round-trip at every boundary size', () => {
    for (const n of [0, 1, DATA - 1, DATA, DATA + 1, 2 * DATA, 2 * DATA + 1, L.messageBytesMax]) {
      const m = bytes(n, n);
      const chunks = chunkMessage(5, m);
      expect(chunks.ok, `${n}`).toBe(true);
      const a = new ChunkAssembler();
      let out: Uint8Array | undefined;
      for (const c of chunks.ok ? chunks.value : []) {
        expect(c.length).toBeLessThanOrEqual(L.chunkBytes);
        const r = a.push(c);
        if (r.ok && r.value) out = r.value;
      }
      expect(out !== undefined && Buffer.from(out).equals(Buffer.from(m))).toBe(true);
      expect(a.pending()).toBe(false);
    }
  });

  it('refuses a message over the limit, a bad id and a non-array', () => {
    expect(chunkMessage(0, new Uint8Array(L.messageBytesMax + 1))).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect(chunkMessage(-1, new Uint8Array(1))).toEqual({ ok: false, reason: 'bad-id' });
    expect(chunkMessage(2 ** 32, new Uint8Array(1))).toEqual({ ok: false, reason: 'bad-id' });
    expect(chunkMessage(0, 'x' as unknown as Uint8Array)).toEqual({
      ok: false,
      reason: 'bad-message',
    });
  });

  it('the reader is strict about every header field and the sizes', () => {
    const chunks = chunkMessage(9, bytes(3 * DATA, 1));
    const list = chunks.ok ? chunks.value : [];
    const mut = (c: Uint8Array, f: (v: DataView) => void): Uint8Array => {
      const x = c.slice();
      f(new DataView(x.buffer));
      return x;
    };
    const first = list[0] as Uint8Array;
    const last = list[2] as Uint8Array;
    expect(readChunk(first).ok).toBe(true);
    expect(readChunk(mut(first, (v) => v.setUint8(0, 2))).ok).toBe(false);
    expect(readChunk(mut(first, (v) => v.setUint16(7, 0))).ok).toBe(false);
    expect(readChunk(mut(first, (v) => v.setUint16(5, 3))).ok).toBe(false); // index >= count
    expect(readChunk(mut(first, (v) => v.setUint16(7, 65535))).ok).toBe(false);
    expect(readChunk(first.subarray(0, first.length - 1)).ok).toBe(false); // a non-last chunk must be full
    expect(readChunk(first.subarray(0, 8)).ok).toBe(false);
    expect(readChunk(new Uint8Array(L.chunkBytes + 1)).ok).toBe(false);
    expect(readChunk(last.subarray(0, L.chunkHeaderBytes)).ok).toBe(false); // empty last chunk of a long message
    expect(readChunk('x').ok).toBe(false);
    expect(readChunk(null).ok).toBe(false);
  });

  it('the assembler takes chunks in order only, and one message at a time', () => {
    const chunks = chunkMessage(1, bytes(3 * DATA, 4));
    const [c0, c1, c2] = (chunks.ok ? chunks.value : []) as [Uint8Array, Uint8Array, Uint8Array];
    const other = chunkMessage(2, bytes(3 * DATA, 5));
    const [o0, o1] = (other.ok ? other.value : []) as [Uint8Array, Uint8Array];
    let a = new ChunkAssembler();
    expect(a.push(c1)).toEqual({ ok: false, reason: 'out-of-order' }); // nothing started
    expect(a.push(c0)).toEqual({ ok: true, value: undefined });
    expect(a.push(c2)).toEqual({ ok: false, reason: 'out-of-order' }); // skipped one
    expect(a.pending()).toBe(false);
    a = new ChunkAssembler();
    a.push(c0);
    expect(a.push(c0)).toEqual({ ok: true, value: undefined }); // a new start drops the half
    a.push(c1);
    expect(a.push(c2).ok).toBe(true);
    a = new ChunkAssembler();
    a.push(c0);
    expect(a.push(o1)).toEqual({ ok: false, reason: 'mismatch' }); // another message in the middle
    a.push(c0);
    a.push(o0.slice()); // restart with the other
    expect(a.push(o1)).toEqual({ ok: true, value: undefined });
    expect(a.push(c1)).toEqual({ ok: false, reason: 'mismatch' });
    expect(a.push(new Uint8Array(3))).toEqual({ ok: false, reason: 'bad-chunk' });
    expect(a.pending()).toBe(false);
  });

  it('the total is bounded even when the headers lie about nothing', () => {
    // a message of the maximum size passes; the count limit is what keeps a longer one out
    const maxCount = Math.ceil(L.messageBytesMax / DATA);
    const c = chunkMessage(1, new Uint8Array(1)).ok
      ? new Uint8Array(L.chunkHeaderBytes + DATA)
      : new Uint8Array();
    const v = new DataView(c.buffer);
    v.setUint8(0, 1);
    v.setUint16(7, maxCount + 1);
    expect(readChunk(c).ok).toBe(false);
    v.setUint16(7, maxCount);
    expect(readChunk(c).ok).toBe(true);
  });

  it('a message that grows past the limit through full chunks is refused', () => {
    const maxCount = Math.ceil(L.messageBytesMax / DATA);
    const a = new ChunkAssembler();
    let last: unknown;
    for (let i = 0; i < maxCount; i++) {
      const c = new Uint8Array(L.chunkHeaderBytes + DATA);
      const v = new DataView(c.buffer);
      v.setUint8(0, 1);
      v.setUint16(5, i);
      v.setUint16(7, maxCount);
      last = a.push(c);
    }
    expect(last).toEqual({ ok: false, reason: 'too-large' });
    expect(a.pending()).toBe(false);
  });

  it('1500 seeded random inputs never throw and never reassemble', () => {
    const r = rng(8);
    const a = new ChunkAssembler();
    for (let i = 0; i < 1500; i++) {
      const b = bytes(Math.floor(r() * 40), i);
      if (b.length) b[0] = r() < 0.5 ? 1 : (b[0] ?? 0);
      const res = a.push(b);
      expect(res.ok && res.value !== undefined).toBe(false);
    }
  });
});

describe('the handshake machine', () => {
  const C = HANDSHAKE_DEFAULTS;
  const run = (s: DirectState, events: DirectEvent[]): DirectState =>
    events.reduce((st, e) => directStep(st, e, C).state, s);
  const answer: DirectText = { ...offer, role: 'answer' };

  it('caller: begin, local text, answer, open', () => {
    let s = initialState('caller');
    let r = directStep(s, { t: 'begin', now: 0, session: SESSION }, C);
    expect(r.actions).toEqual(['create-offer']);
    expect(r.state).toMatchObject({ phase: 'gathering', session: SESSION, deadline: C.setupMs });
    s = r.state;
    r = directStep(s, { t: 'local-text', now: 100 }, C);
    expect(r.state).toMatchObject({ phase: 'awaiting-answer', deadline: 100 + C.answerMs });
    r = directStep(r.state, { t: 'remote-text', now: 200, text: answer }, C);
    expect(r.actions).toEqual(['apply-answer']);
    expect(r.state).toMatchObject({ phase: 'connecting', deadline: 200 + C.connectMs });
    r = directStep(r.state, { t: 'channel-open', now: 300 }, C);
    expect(r.state).toMatchObject({ phase: 'open', deadline: undefined });
  });

  it('callee: begin, offer, local text, open', () => {
    let r = directStep(initialState('callee'), { t: 'begin', now: 0 }, C);
    expect(r.state).toMatchObject({ phase: 'awaiting-offer', deadline: C.offerMs });
    r = directStep(r.state, { t: 'remote-text', now: 5, text: offer }, C);
    expect(r.actions).toEqual(['apply-offer']);
    expect(r.state).toMatchObject({ phase: 'gathering', session: SESSION });
    r = directStep(r.state, { t: 'local-text', now: 9 }, C);
    expect(r.state).toMatchObject({ phase: 'connecting', deadline: 9 + C.connectMs });
    r = directStep(r.state, { t: 'channel-open', now: 11 }, C);
    expect(r.state.phase).toBe('open');
  });

  it('every phase times out with its own code, exactly at the deadline', () => {
    const cases: [DirectEvent[], string, number, 'caller' | 'callee'][] = [
      [[{ t: 'begin', now: 0 }], 'offer-timeout', C.offerMs, 'callee'],
      [[{ t: 'begin', now: 0, session: SESSION }], 'gather-timeout', C.setupMs, 'caller'],
      [
        [
          { t: 'begin', now: 0, session: SESSION },
          { t: 'local-text', now: 0 },
        ],
        'answer-timeout',
        C.answerMs,
        'caller',
      ],
      [
        [
          { t: 'begin', now: 0, session: SESSION },
          { t: 'local-text', now: 0 },
          { t: 'remote-text', now: 0, text: answer },
        ],
        'connect-timeout',
        C.connectMs,
        'caller',
      ],
    ];
    for (const [events, code, ms, role] of cases) {
      const s = run(initialState(role), events);
      expect(directStep(s, { t: 'tick', now: ms - 1 }, C).state.phase).not.toBe('failed');
      const r = directStep(s, { t: 'tick', now: ms }, C);
      expect(r.state).toMatchObject({ phase: 'failed', failure: code });
      expect(r.actions).toEqual(['close']);
    }
  });

  it('refusals leave the state as it was', () => {
    const s = run(initialState('caller'), [
      { t: 'begin', now: 0, session: SESSION },
      { t: 'local-text', now: 0 },
    ]);
    expect(directStep(s, { t: 'remote-text', now: 1, text: offer }, C)).toMatchObject({
      refusal: 'wrong-role',
      state: s,
    });
    expect(
      directStep(
        s,
        { t: 'remote-text', now: 1, text: { ...answer, session: 'fedcba9876543210' } },
        C,
      ),
    ).toMatchObject({ refusal: 'wrong-session', state: s });
    expect(directStep(s, { t: 'channel-open', now: 1 }, C)).toMatchObject({
      refusal: 'unexpected',
      state: s,
    });
    expect(directStep(s, { t: 'begin', now: 1, session: SESSION }, C)).toMatchObject({
      refusal: 'unexpected',
    });
    expect(
      directStep(initialState('caller'), { t: 'begin', now: 0, session: 'zz' }, C),
    ).toMatchObject({
      refusal: 'bad-session',
    });
    expect(directStep(initialState('caller'), { t: 'local-text', now: 0 }, C).refusal).toBe(
      'unexpected',
    );
    const callee = run(initialState('callee'), [{ t: 'begin', now: 0 }]);
    expect(directStep(callee, { t: 'remote-text', now: 1, text: answer }, C).refusal).toBe(
      'wrong-role',
    );
  });

  it('failure events and cancel', () => {
    const connecting = run(initialState('caller'), [
      { t: 'begin', now: 0, session: SESSION },
      { t: 'local-text', now: 0 },
      { t: 'remote-text', now: 0, text: answer },
    ]);
    expect(directStep(connecting, { t: 'ice-failed' }, C).state).toMatchObject({
      failure: 'ice-failed',
    });
    expect(directStep(connecting, { t: 'channel-closed' }, C).state).toMatchObject({
      failure: 'channel-closed',
    });
    expect(directStep(connecting, { t: 'cancel' }, C).state.phase).toBe('closed');
    const gathering = run(initialState('caller'), [{ t: 'begin', now: 0, session: SESSION }]);
    expect(directStep(gathering, { t: 'setup-failed' }, C).state).toMatchObject({
      failure: 'setup-failed',
    });
    expect(directStep(gathering, { t: 'ice-failed' }, C).refusal).toBe('unexpected');
    const open = directStep(connecting, { t: 'channel-open', now: 1 }, C).state;
    expect(directStep(open, { t: 'channel-closed' }, C).state.phase).toBe('closed');
    expect(directStep(open, { t: 'ice-failed' }, C).state.failure).toBe('ice-failed');
    expect(directStep(open, { t: 'tick', now: 10 ** 9 }, C).state.phase).toBe('open');
  });

  it('terminal states ignore everything', () => {
    const dead = directStep(
      run(initialState('callee'), [{ t: 'begin', now: 0 }]),
      { t: 'tick', now: C.offerMs },
      C,
    ).state;
    const evs: DirectEvent[] = [
      { t: 'begin', now: 0 },
      { t: 'remote-text', now: 0, text: offer },
      { t: 'local-text', now: 0 },
      { t: 'channel-open', now: 0 },
      { t: 'tick', now: 0 },
      { t: 'cancel' },
    ];
    for (const e of evs) expect(directStep(dead, e, C)).toEqual({ state: dead, actions: [] });
  });

  it('property: 3000 seeded random event sequences never throw, never leave a terminal state and keep deadlines ahead', () => {
    const r = rng(77);
    const texts = [offer, answer, { ...answer, session: 'fedcba9876543210' }];
    for (let run = 0; run < 3000; run++) {
      let s = initialState(r() < 0.5 ? 'caller' : 'callee');
      let now = 0;
      let terminal = false;
      for (let i = 0; i < 12; i++) {
        now += Math.floor(r() * 50_000);
        const k = Math.floor(r() * 9);
        const e: DirectEvent =
          k === 0
            ? { t: 'begin', now, ...(r() < 0.7 ? { session: SESSION } : {}) }
            : k === 1
              ? { t: 'remote-text', now, text: texts[Math.floor(r() * 3)] as DirectText }
              : k === 2
                ? { t: 'local-text', now }
                : k === 3
                  ? { t: 'channel-open', now }
                  : k === 4
                    ? { t: 'tick', now }
                    : k === 5
                      ? { t: 'ice-failed' }
                      : k === 6
                        ? { t: 'channel-closed' }
                        : k === 7
                          ? { t: 'setup-failed' }
                          : { t: 'cancel' };
        const step = directStep(s, e, C);
        if (terminal) expect(step.state).toBe(s);
        if (step.refusal) expect(step.state).toBe(s);
        s = step.state;
        if (s.phase === 'failed') expect(s.failure).toBeDefined();
        if (
          s.phase === 'open' ||
          s.phase === 'closed' ||
          s.phase === 'failed' ||
          s.phase === 'idle'
        )
          expect(s.deadline).toBeUndefined();
        else expect(s.deadline).toBeGreaterThanOrEqual(0);
        if (s.phase === 'failed' || s.phase === 'closed') terminal = true;
      }
    }
  });

  it('the configuration is checked', () => {
    expect(handshakeConfigProblem(C)).toBeUndefined();
    for (const k of ['offerMs', 'setupMs', 'answerMs', 'connectMs'] as const) {
      expect(handshakeConfigProblem({ ...C, [k]: 0 })).toBe('bad-config');
      expect(handshakeConfigProblem({ ...C, [k]: 3_600_001 })).toBe('bad-config');
      expect(handshakeConfigProblem({ ...C, [k]: 1.5 })).toBe('bad-config');
    }
  });
});

describe('network reading', () => {
  it('classifies addresses', () => {
    expect(addressKind('192.168.1.5')).toEqual({ family: 'ipv4', scope: 'local' });
    expect(addressKind('100.64.1.1')).toEqual({ family: 'ipv4', scope: 'local' });
    expect(addressKind('100.128.0.1')).toEqual({ family: 'ipv4', scope: 'public' });
    expect(addressKind('203.0.113.9')).toEqual({ family: 'ipv4', scope: 'public' });
    expect(addressKind('172.31.0.1')).toEqual({ family: 'ipv4', scope: 'local' });
    expect(addressKind('172.32.0.1')).toEqual({ family: 'ipv4', scope: 'public' });
    expect(addressKind('fe80::1')).toEqual({ family: 'ipv6', scope: 'local' });
    expect(addressKind('2001:db8::1')).toEqual({ family: 'ipv6', scope: 'public' });
    expect(addressKind('abc-def.local')).toEqual({ family: 'mdns', scope: 'local' });
    expect(addressKind('999.1.1.1')).toBeUndefined();
    expect(addressKind('example.org')).toBeUndefined();
    expect(addressKind('x'.repeat(200))).toBeUndefined();
  });

  it('reads candidate lines and keeps no address', () => {
    const c = parseCandidate(
      'a=candidate:1 1 UDP 2122 203.0.113.9 54321 typ srflx raddr 10.0.0.1 rport 1',
    );
    expect(c).toEqual({ type: 'srflx', protocol: 'udp', family: 'ipv4', scope: 'public' });
    expect(JSON.stringify(c)).not.toContain('203');
    expect(parseCandidate('candidate:1 1 tcp 1 10.0.0.1 9 typ host tcptype active')).toMatchObject({
      protocol: 'tcp',
    });
    expect(parseCandidate('a=candidate:1 1 udp 1 nonsense 9 typ host')).toBeUndefined();
    expect(parseCandidate('a=candidate:1 1 udp 1 10.0.0.1 9 typ weird')).toBeUndefined();
    expect(parseCandidate('x'.repeat(L.sdpLineCharsMax + 1))).toBeUndefined();
    expect(candidatesOfSdp(SDP)).toHaveLength(1);
    expect(candidatesOfSdp(7 as unknown as string)).toEqual([]);
  });

  it('reachability as codes', () => {
    const k = (type: string, family: string, scope: string) =>
      ({ type, protocol: 'udp', family, scope }) as never;
    expect(reachability([])).toEqual(['none']);
    expect(reachability([k('host', 'ipv4', 'local')])).toEqual(['local']);
    expect(
      reachability([
        k('srflx', 'ipv4', 'public'),
        k('host', 'ipv6', 'public'),
        k('relay', 'ipv4', 'public'),
      ]),
    ).toEqual(['ipv4-stun', 'ipv6-public-host', 'relay']);
  });

  it('names the way a connection took', () => {
    const end = (type: string, scope?: string, family?: string) =>
      ({ type, scope, family }) as never;
    expect(pathKind({ local: end('relay'), remote: end('host', 'local') })).toBe('relay');
    expect(pathKind({ local: end('host', 'local'), remote: end('host', 'local') })).toBe(
      'same-network',
    );
    expect(pathKind({ local: end('srflx', 'public'), remote: end('host', 'local') })).toBe(
      'translated',
    );
    expect(pathKind({ local: end('prflx', 'public', 'ipv4'), remote: end('host', 'public') })).toBe(
      'translated',
    );
    expect(pathKind({ local: end('prflx', 'public', 'ipv6'), remote: end('host', 'public') })).toBe(
      'public',
    );
    expect(pathKind({ local: end('host'), remote: end('host') })).toBe('unclear');
  });

  it('chosenPath from statistics, with and without the transport entry, and refuses odd input', () => {
    const entries = [
      {
        id: 'P',
        type: 'candidate-pair',
        nominated: true,
        state: 'succeeded',
        localCandidateId: 'L',
        remoteCandidateId: 'R',
        currentRoundTripTime: 0.0304,
      },
      { id: 'L', candidateType: 'host', address: '10.0.0.2', protocol: 'tcp' },
      { id: 'R', candidateType: 'srflx', ip: '203.0.113.5' },
    ];
    expect(chosenPath(entries)).toEqual({
      local: { type: 'host', family: 'ipv4', scope: 'local' },
      remote: { type: 'srflx', family: 'ipv4', scope: 'public' },
      protocol: 'tcp',
      rttMs: 30,
    });
    const hidden = [
      { id: 'T', type: 'transport', selectedCandidatePairId: 'P' },
      {
        id: 'P',
        type: 'candidate-pair',
        localCandidateId: 'L',
        remoteCandidateId: 'R',
        currentRoundTripTime: -1,
      },
      { id: 'L', candidateType: 'host' },
      { id: 'R', candidateType: 'host', address: 'abc.local' },
    ];
    expect(chosenPath(hidden)).toEqual({
      local: { type: 'host', family: 'mdns', scope: 'local' },
      remote: { type: 'host', family: 'mdns', scope: 'local' },
    });
    expect(chosenPath([])).toBeUndefined();
    expect(chosenPath([null as never, 5 as never, { id: 'x' }])).toBeUndefined();
    expect(chosenPath(new Array(L.statsMax + 1).fill({ id: 'x' }))).toBeUndefined();
    expect(chosenPath('x' as never)).toBeUndefined();
    expect(
      chosenPath([
        {
          id: 'P',
          type: 'candidate-pair',
          nominated: true,
          state: 'succeeded',
          localCandidateId: 'L',
          remoteCandidateId: 'R',
        },
        { id: 'L', candidateType: 'bogus' },
        { id: 'R', candidateType: 'host' },
      ]),
    ).toBeUndefined();
  });
});
