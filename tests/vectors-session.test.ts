// Runs the committed session and file vectors (tests/vectors/session.json, file.json) against the
// code AND against an independent derivation written from docs/wire-format.md with node:crypto only.
// The vectors are meant for other implementations too. All keys in them are throw-away keys.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  encodeHello,
  openFile,
  openSession,
  parseHello,
  parseSealedMessage,
  readFileHeader,
  type EncryptedSession,
} from '../src/core/index.ts';
import {
  dh,
  jwkToPoint,
  nonce,
  refFile,
  refOpen,
  refSeal,
  refSession,
  type PrivateJwk,
} from './core/reference.ts';
import { pairFromJwk } from './core/secure-helpers.ts';

const load = <T>(name: string): T =>
  JSON.parse(readFileSync(new URL(`./vectors/${name}.json`, import.meta.url), 'utf8')) as T;

interface Device {
  device: string;
  staticPrivateJwk: PrivateJwk;
  staticPoint: string;
  ephemeralPrivateJwk: PrivateJwk;
}
interface SessionVectors {
  appId: string;
  devices: { a: Device; b: Device };
  hellos: { a: string; b: string };
  lo: 'a' | 'b';
  transcript: string;
  saltHex: string;
  secrets: { ee: string; loEphemeralHiStatic: string; loStaticHiEphemeral: string; ss: string };
  ikmHex: string;
  keysBySender: Record<string, string>;
  messages: {
    from: 'a' | 'b';
    n: number;
    plaintextHex: string;
    aad: string;
    nonceHex: string;
    wire: string;
  }[];
  mustRefuse: { name: string; to: 'a' | 'b'; wire: string }[];
}
interface FileVectors {
  appId: string;
  sender: { device: string; staticPoint: string };
  recipient: { device: string; staticPrivateJwk: PrivateJwk; staticPoint: string };
  file: string;
  headerText: string;
  saltHex: string;
  ikmHex: string;
  keyHex: string;
  nonceHex: string;
  plaintextHex: string;
}

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const session = load<SessionVectors>('session');
const file = load<FileVectors>('file');

describe('vectors: the session', () => {
  const side = (d: Device, other: Device) => ({
    device: d.device,
    staticPriv: d.staticPrivateJwk,
    staticDh: d.staticPoint,
    ephPriv: d.ephemeralPrivateJwk,
    ephPoint: jwkToPoint(d.ephemeralPrivateJwk),
    other,
  });
  const a = side(session.devices.a, session.devices.b);
  const b = side(session.devices.b, session.devices.a);

  it('the points are the private keys', () => {
    for (const d of [session.devices.a, session.devices.b]) {
      expect(jwkToPoint(d.staticPrivateJwk)).toBe(d.staticPoint);
    }
  });

  it('the hellos are the documented texts', () => {
    const helloOf = (s: typeof a) => ({ device: s.device, eph: s.ephPoint });
    expect(session.hellos.a).toBe(encodeHello(session.appId, helloOf(a)));
    expect(session.hellos.b).toBe(encodeHello(session.appId, helloOf(b)));
    expect(session.hellos.a).toBe(
      `{"m":"demo-hello:2","device":"${a.device}","eph":"${a.ephPoint}"}`,
    );
    expect(parseHello(session.appId, session.hellos.a)).toEqual(helloOf(a));
  });

  it('the transcript, the four secrets, the salt and the keys follow from the documented rules', () => {
    const viewA = refSession(
      session.appId,
      a,
      { device: b.device, staticDh: b.staticDh, ephPoint: b.ephPoint },
      {},
    );
    const viewB = refSession(
      session.appId,
      b,
      { device: a.device, staticDh: a.staticDh, ephPoint: a.ephPoint },
      {},
    );
    expect(viewA.transcript).toBe(session.transcript);
    expect(viewB.transcript).toBe(session.transcript);
    expect(hex(viewA.salt)).toBe(session.saltHex);
    // the four secrets, named by who is smaller (UTF-8 byte order of the device ids)
    const lo = a.device < b.device ? a : b;
    const hi = lo === a ? b : a;
    expect(session.lo).toBe(lo === a ? 'a' : 'b');
    expect(hex(dh(lo.ephPriv, hi.ephPoint))).toBe(session.secrets.ee);
    expect(hex(dh(lo.ephPriv, hi.staticDh))).toBe(session.secrets.loEphemeralHiStatic);
    expect(hex(dh(lo.staticPriv, hi.ephPoint))).toBe(session.secrets.loStaticHiEphemeral);
    expect(hex(dh(lo.staticPriv, hi.staticDh))).toBe(session.secrets.ss);
    const ikm =
      session.secrets.ee +
      session.secrets.loEphemeralHiStatic +
      session.secrets.loStaticHiEphemeral +
      session.secrets.ss;
    expect(ikm).toBe(session.ikmHex);
    expect(hex(viewA.ikm)).toBe(session.ikmHex);
    expect(hex(viewB.ikm)).toBe(session.ikmHex);
    for (const id of [a.device, b.device]) {
      expect(hex(viewA.keyOf(id))).toBe(session.keysBySender[id]);
    }
    expect(session.keysBySender[a.device]).not.toBe(session.keysBySender[b.device]);
  });

  it('every message decrypts with the independent derivation, bytes and texts as documented', () => {
    for (const m of session.messages) {
      const sender = m.from === 'a' ? a : b;
      const receiver = m.from === 'a' ? b : a;
      const key = Buffer.from(session.keysBySender[sender.device] as string, 'hex');
      expect(m.aad).toBe(
        `demo-msg:2|${sender.device.length}:${sender.device}|${receiver.device.length}:${receiver.device}|${m.n}`,
      );
      expect(m.nonceHex).toBe(hex(nonce(m.n)));
      const parsed = parseSealedMessage(session.appId, m.wire);
      expect(parsed?.n).toBe(m.n);
      const plain = refOpen(key, nonce(m.n), m.aad, parsed?.ct as Uint8Array);
      expect(plain && hex(plain)).toBe(m.plaintextHex);
      // sealing is deterministic (the nonce is the counter), so the reference makes the same text
      const made = refSeal(
        session.appId,
        key,
        sender.device,
        receiver.device,
        m.n,
        Buffer.from(m.plaintextHex, 'hex'),
      );
      expect(made.text).toBe(m.wire);
    }
  });

  async function open(s: typeof a, peer: typeof b): Promise<EncryptedSession> {
    const r = await openSession({
      appId: session.appId,
      own: { device: s.device, agreement: await pairFromJwk(s.staticPriv) },
      peer: { device: peer.device, dh: peer.staticDh },
      ephemeral: await pairFromJwk(s.ephPriv),
      ownHello: { device: s.device, eph: s.ephPoint },
      peerHello: { device: peer.device, eph: peer.ephPoint },
    });
    if (!r.ok) throw new Error(r.reason);
    return r.session;
  }

  it('the library opens every message in order and seals the very same texts', async () => {
    const sa = await open(a, b);
    const sb = await open(b, a);
    for (const m of session.messages) {
      const [sender, receiver] = m.from === 'a' ? [sa, sb] : [sb, sa];
      const r = await receiver.open(m.wire);
      expect(r.ok && hex(r.plaintext), `message ${m.from}${m.n}`).toBe(m.plaintextHex);
      const sealed = await sender.seal(Buffer.from(m.plaintextHex, 'hex'));
      expect(sealed.ok && sealed.text).toBe(m.wire);
    }
  });

  it('every message the vectors list as refused is refused', async () => {
    for (const r of session.mustRefuse) {
      const s = r.to === 'a' ? await open(a, b) : await open(b, a);
      const result = await s.open(r.wire);
      expect(result.ok, r.name).toBe(false);
    }
  });
});

describe('vectors: the encrypted file', () => {
  const sender = { device: file.sender.device, dh: file.sender.staticPoint };
  const recipient = file.recipient;

  it('the file is the documented compact JSON; its header is read', () => {
    const f = JSON.parse(file.file) as Record<string, string>;
    expect(Object.keys(f)).toEqual(['m', 'from', 'to', 'eph', 'iv', 'ct']);
    expect(file.file).toBe(
      `{"m":"demo-file:2","from":${JSON.stringify(f.from)},"to":${JSON.stringify(f.to)},"eph":"${f.eph}","iv":"${f.iv}","ct":"${f.ct}"}`,
    );
    expect(readFileHeader(file.appId, new TextEncoder().encode(file.file))).toEqual({
      from: sender.device,
      to: recipient.device,
    });
  });

  it('the header text, the salt, the secrets and the key follow from the documented rules', () => {
    const f = JSON.parse(file.file) as Record<string, string>;
    const k = refFile(
      file.appId,
      {
        from: sender.device,
        to: recipient.device,
        fromDh: sender.dh,
        toDh: recipient.staticPoint,
        eph: f.eph as string,
      },
      { toPriv: recipient.staticPrivateJwk },
    );
    expect(k.header).toBe(file.headerText);
    expect(hex(k.salt)).toBe(file.saltHex);
    expect(hex(k.ikm)).toBe(file.ikmHex);
    expect(hex(k.key)).toBe(file.keyHex);
    expect(Buffer.from(f.iv as string, 'base64url').toString('hex')).toBe(file.nonceHex);
    const plain = refOpen(
      k.key,
      Buffer.from(f.iv as string, 'base64url'),
      k.header,
      Buffer.from(f.ct as string, 'base64url'),
    );
    expect(plain && hex(plain)).toBe(file.plaintextHex);
  });

  it('the library opens it, and refuses it for every wrong party', async () => {
    const bytes = new TextEncoder().encode(file.file);
    const own = {
      device: recipient.device,
      agreement: await pairFromJwk(recipient.staticPrivateJwk),
    };
    const ok = await openFile({ appId: file.appId, own, from: sender, file: bytes });
    expect(ok.ok && hex(ok.payload)).toBe(file.plaintextHex);
    expect(
      await openFile({
        appId: file.appId,
        own,
        from: { ...sender, dh: recipient.staticPoint },
        file: bytes,
      }),
    ).toEqual({
      ok: false,
      reason: 'cannot-open',
    });
    expect(
      await openFile({
        appId: file.appId,
        own,
        from: { device: 'someone-else', dh: sender.dh },
        file: bytes,
      }),
    ).toEqual({
      ok: false,
      reason: 'wrong-sender',
    });
    expect(await openFile({ appId: 'other', own, from: sender, file: bytes })).toEqual({
      ok: false,
      reason: 'not-a-file',
    });
    const flipped = new TextEncoder().encode(
      file.file.replace(/"ct":"(.)/, (_m, c: string) => `"ct":"${c === 'A' ? 'B' : 'A'}`),
    );
    expect(await openFile({ appId: file.appId, own, from: sender, file: flipped })).toEqual({
      ok: false,
      reason: 'cannot-open',
    });
  });
});
