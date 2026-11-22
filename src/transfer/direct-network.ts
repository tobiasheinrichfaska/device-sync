// What a description and the connection statistics say about the network, as codes: which kinds of
// candidates a device offers and which way the connection took. Never keeps an address, only its kind.
import { TRANSFER_LIMITS as L } from './limits.ts';

export type Family = 'ipv4' | 'ipv6' | 'mdns';
export type Scope = 'local' | 'public';
export type CandidateType = 'host' | 'srflx' | 'prflx' | 'relay';

// Addresses that do not reach beyond the local network or the provider's address translation
// (100.64.0.0/10 is carrier-grade NAT in mobile networks); everything else counts as public.
const LOCAL_ADDRESSES: readonly RegExp[] = [
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
  /^127\./,
  /^0\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^f[cd][0-9a-f]{2}:/i,
  /^fe[89ab][0-9a-f]:/i,
  /^::1?$/,
];

export function addressKind(address: string): { family: Family; scope: Scope } | undefined {
  if (typeof address !== 'string' || address.length > 100) return undefined;
  const a = address.trim().replace(/^\[|\]$/g, '');
  if (/^[0-9a-z-]+\.local$/i.test(a)) return { family: 'mdns', scope: 'local' };
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a);
  let family: Family;
  if (v4) {
    if (v4.slice(1).some((part) => Number(part) > 255)) return undefined;
    family = 'ipv4';
  } else if (a.includes(':') && /^[0-9a-f:.]+$/i.test(a)) family = 'ipv6';
  else return undefined;
  return { family, scope: LOCAL_ADDRESSES.some((r) => r.test(a)) ? 'local' : 'public' };
}

export interface CandidateInfo {
  readonly type: CandidateType;
  readonly protocol: 'udp' | 'tcp';
  readonly family: Family;
  readonly scope: Scope;
}

/** One ICE candidate line (RFC 8839), with or without the `a=` of the SDP. */
export function parseCandidate(line: string): CandidateInfo | undefined {
  if (typeof line !== 'string' || line.length > L.sdpLineCharsMax) return undefined;
  const m =
    /^(?:a=)?candidate:\S+ \d+ (udp|tcp) \d+ (\S+) \d+ typ (host|srflx|prflx|relay)(?: |$)/i.exec(
      line.trim(),
    );
  if (!m) return undefined;
  const kind = addressKind(m[2] ?? '');
  if (!kind) return undefined;
  return {
    type: (m[3] ?? '').toLowerCase() as CandidateType,
    protocol: (m[1] ?? '').toLowerCase() as 'udp' | 'tcp',
    ...kind,
  };
}

export function candidatesOfSdp(sdp: string): CandidateInfo[] {
  if (typeof sdp !== 'string' || sdp.length > L.sdpCharsMax) return [];
  return sdp
    .split(/\r?\n/, L.sdpLinesMax)
    .filter((line) => line.startsWith('a=candidate:'))
    .map(parseCandidate)
    .filter((c): c is CandidateInfo => c !== undefined);
}

export type Reach =
  'ipv4-stun' | 'ipv6-stun' | 'ipv4-public-host' | 'ipv6-public-host' | 'local' | 'relay' | 'none';

/** How a device can be reached, as codes (no addresses). */
export function reachability(candidates: readonly CandidateInfo[]): Reach[] {
  const out: Reach[] = [];
  for (const [f, code] of [
    ['ipv4', 'ipv4-stun'],
    ['ipv6', 'ipv6-stun'],
  ] as const)
    if (candidates.some((c) => (c.type === 'srflx' || c.type === 'prflx') && c.family === f))
      out.push(code);
  for (const [f, code] of [
    ['ipv4', 'ipv4-public-host'],
    ['ipv6', 'ipv6-public-host'],
  ] as const)
    if (candidates.some((c) => c.type === 'host' && c.scope === 'public' && c.family === f))
      out.push(code);
  if (candidates.some((c) => c.type === 'host' && c.scope === 'local')) out.push('local');
  if (candidates.some((c) => c.type === 'relay')) out.push('relay');
  return out.length > 0 ? out : ['none'];
}

export interface PathEnd {
  readonly type: CandidateType;
  readonly family?: Family;
  readonly scope?: Scope;
}

export interface ChosenPath {
  readonly local: PathEnd;
  readonly remote: PathEnd;
  readonly protocol?: 'udp' | 'tcp';
  readonly rttMs?: number;
}

export type PathKind = 'relay' | 'same-network' | 'translated' | 'public' | 'unclear';

// A STUN-mapped address, or a public IPv4 address learned during the checks (peer-reflexive), means a
// router or the mobile network translated the address.
const translated = (e: PathEnd): boolean =>
  e.type === 'srflx' || (e.type === 'prflx' && e.family === 'ipv4' && e.scope === 'public');

/** First matching rule names the way (data, so a case is a row). Each device sees the pair from its side. */
const PATH_RULES: readonly {
  readonly when: (p: ChosenPath) => boolean;
  readonly kind: PathKind;
}[] = [
  { when: (p) => [p.local, p.remote].some((e) => e.type === 'relay'), kind: 'relay' },
  { when: (p) => [p.local, p.remote].every((e) => e.scope === 'local'), kind: 'same-network' },
  { when: (p) => [p.local, p.remote].some(translated), kind: 'translated' },
  { when: (p) => [p.local, p.remote].some((e) => e.scope === 'public'), kind: 'public' },
];

export function pathKind(path: ChosenPath): PathKind {
  return PATH_RULES.find((r) => r.when(path))?.kind ?? 'unclear';
}

type Stat = Readonly<Record<string, unknown>>;

function pathEnd(stat: Stat): PathEnd | undefined {
  const type = stat.candidateType;
  if (type !== 'host' && type !== 'srflx' && type !== 'prflx' && type !== 'relay') return undefined;
  const address = typeof stat.address === 'string' ? stat.address : stat.ip;
  const kind = typeof address === 'string' && address !== '' ? addressKind(address) : undefined;
  // A host candidate without a readable address is hidden behind an mDNS name, i.e. local.
  if (kind) return { type, ...kind };
  return type === 'host' ? { type, family: 'mdns', scope: 'local' } : { type };
}

/** The candidate pair the connection uses, from the entries of `RTCPeerConnection.getStats()`. */
export function chosenPath(stats: readonly Stat[]): ChosenPath | undefined {
  if (!Array.isArray(stats) || stats.length > L.statsMax) return undefined;
  const entries = stats.filter((s) => typeof s === 'object' && s !== null);
  const byId = new Map(entries.map((s) => [s.id, s]));
  const transport = entries.find(
    (s) => s.type === 'transport' && typeof s.selectedCandidatePairId === 'string',
  );
  const pair = transport
    ? byId.get(transport.selectedCandidatePairId)
    : entries.find(
        (s) =>
          s.type === 'candidate-pair' &&
          (s.selected === true || (s.nominated === true && s.state === 'succeeded')),
      );
  if (!pair) return undefined;
  const local = byId.get(pair.localCandidateId);
  const remote = byId.get(pair.remoteCandidateId);
  const l = local && pathEnd(local);
  const r = remote && pathEnd(remote);
  if (!l || !r) return undefined;
  const protocol = local?.protocol;
  const rtt = pair.currentRoundTripTime;
  return {
    local: l,
    remote: r,
    ...(protocol === 'udp' || protocol === 'tcp' ? { protocol } : {}),
    ...(typeof rtt === 'number' && Number.isFinite(rtt) && rtt >= 0
      ? { rttMs: Math.round(rtt * 1000) }
      : {}),
  };
}
