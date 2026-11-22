// The texts two devices exchange to open a WebRTC data channel without a server of their own: an offer and
// an answer, each a session description (SDP) with every ICE candidate in it (no trickle). The texts travel
// by any channel (QR codes, a relay, a message). Strict readers: one spelling, bounded, a data channel only.
import { base64url, fromBase64url } from '../core/encoding.ts';
import { domainBytes } from './check.ts';
import { marker } from '../core/markers.ts';
import { TRANSFER_LIMITS as L, fail, pass, type TransferResult } from './limits.ts';

export type DirectRole = 'offer' | 'answer';

export interface DirectText {
  readonly role: DirectRole;
  /** 16 lower-case hex characters the caller drew; the answer repeats it. */
  readonly session: string;
  readonly sdp: string;
}

export type TextReason =
  | 'bad-app-id'
  | 'not-text'
  | 'too-long'
  | 'bad-marker'
  | 'bad-format'
  | 'bad-role'
  | 'bad-session'
  | 'bad-sdp';

const SESSION = /^[0-9a-f]{16}$/;
const FINGERPRINT = /^a=fingerprint:sha-(256|384|512) [0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+$/;

/**
 * Strict check of a description: printable ASCII with CRLF line ends, bounded, `v=0` first, exactly one
 * media section and that one is `application` (a data channel: nothing can ask for a camera or a microphone),
 * DTLS fingerprint lines of the usual shape that all name one value, and no bare CR or LF inside a line.
 */
export function readSdp(sdp: unknown): TransferResult<string, 'bad-sdp'> {
  if (typeof sdp !== 'string' || sdp.length < 5 || sdp.length > L.sdpCharsMax)
    return fail('bad-sdp');
  if (!/^[\x20-\x7e\r\n]+$/.test(sdp) || !sdp.endsWith('\r\n')) return fail('bad-sdp');
  const lines = sdp.slice(0, -2).split('\r\n');
  if (lines.length > L.sdpLinesMax || lines[0] !== 'v=0') return fail('bad-sdp');
  let media = 0;
  const fingerprints = new Set<string>();
  for (const line of lines) {
    // A bare CR or LF inside a "line" would hide a line (a second media section) from these checks while a
    // parser that splits on LF still sees it.
    if (line.length > L.sdpLineCharsMax || !/^[a-z]=[\x20-\x7e]*$/.test(line))
      return fail('bad-sdp');
    if (line.startsWith('m=')) {
      media++;
      if (!/^m=application [0-9]+ [A-Za-z0-9/]+( [A-Za-z0-9/*-]+)*$/.test(line))
        return fail('bad-sdp');
    }
    if (line.startsWith('a=fingerprint:')) {
      if (!FINGERPRINT.test(line)) return fail('bad-sdp');
      fingerprints.add(line.toUpperCase());
    }
  }
  // One distinct fingerprint (the same one may be repeated at session and media level): with several,
  // "the fingerprint the app bound" would not say which certificate the channel is checked against.
  return media === 1 && fingerprints.size === 1 ? pass(sdp) : fail('bad-sdp');
}

/** The DTLS fingerprint lines of a description (an app may bind them to an authenticated session). */
export function fingerprintsOf(sdp: string): string[] {
  return sdp
    .split('\r\n')
    .filter((l) => l.startsWith('a=fingerprint:'))
    .map((l) => l.slice('a=fingerprint:'.length).toUpperCase());
}

const prefixOf = (appId: string): string | undefined => {
  try {
    return marker(appId, 'direct', 1);
  } catch {
    return undefined;
  }
};

/** `<appId>-direct:1.<role>.<session>.<base64url of the SDP>` */
export function writeDirectText(
  appId: string,
  text: DirectText,
): TransferResult<string, TextReason> {
  const prefix = prefixOf(appId);
  if (!prefix) return fail('bad-app-id');
  if (!text || (text.role !== 'offer' && text.role !== 'answer')) return fail('bad-role');
  if (typeof text.session !== 'string' || !SESSION.test(text.session)) return fail('bad-session');
  if (!readSdp(text.sdp).ok) return fail('bad-sdp');
  const out = `${prefix}.${text.role}.${text.session}.${base64url(new TextEncoder().encode(text.sdp))}`;
  return out.length > L.textCharsMax ? fail('too-long') : pass(out);
}

export function readDirectText(
  appId: string,
  text: unknown,
): TransferResult<DirectText, TextReason> {
  const prefix = prefixOf(appId);
  if (!prefix || !domainBytes(appId, 'direct')) return fail('bad-app-id');
  if (typeof text !== 'string') return fail('not-text');
  if (text.length > L.textCharsMax) return fail('too-long');
  const parts = text.split('.');
  if (parts.length !== 4) return fail(text.startsWith(prefix) ? 'bad-format' : 'bad-marker');
  const [m, role, session, body] = parts as [string, string, string, string];
  if (m !== prefix) return fail('bad-marker');
  if (role !== 'offer' && role !== 'answer') return fail('bad-role');
  if (!SESSION.test(session)) return fail('bad-session');
  if (!/^[A-Za-z0-9_-]+$/.test(body) || body.length % 4 === 1) return fail('bad-format');
  let sdp: string;
  try {
    const bytes = fromBase64url(body);
    if (base64url(bytes) !== body) return fail('bad-format');
    sdp = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return fail('bad-format');
  }
  const ok = readSdp(sdp);
  if (!ok.ok) return fail('bad-sdp');
  return pass({ role, session, sdp });
}
