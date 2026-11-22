import { readFileSync } from 'node:fs';
import type { ConformanceCases } from '../../src/relay/conformance.ts';
import { createReferenceServer, type Defect, type RefApp } from './reference-server.ts';

export const CASES = JSON.parse(
  readFileSync(new URL('./conformance/cases.json', import.meta.url), 'utf8'),
) as ConformanceCases;

export const BASE = 'https://relay.test';

/** Tiny seeded PRNG (mulberry32): same seed, same sequence. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A reference server configured exactly as the fixture of the cases says. */
export function serverFor(opts: { defect?: Defect; now?: () => number } = {}) {
  const fx = CASES.fixture;
  const apps: Record<string, RefApp> = {};
  for (const [name, raw] of Object.entries(fx.apps)) {
    const a = raw as {
      origins: string[];
      proofKey: string | null;
      invitations: boolean;
      groups: number;
      blockedDevices?: string[];
    };
    apps[name] = {
      origins: a.origins,
      proofKeys: a.proofKey ? [(fx.proofKeys[a.proofKey] as { publicRaw: string }).publicRaw] : [],
      invitations: a.invitations,
      groups: a.groups,
      ...(a.blockedDevices ? { blocked: a.blockedDevices } : {}),
    };
  }
  return createReferenceServer({
    secret: Buffer.from(fx.secrets['main'] as string, 'base64url'),
    apps,
    ...(opts.defect ? { defect: opts.defect } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
}

/** App ids and origins of the fixture, for tests that need a client. */
export const ALPHA = { app: 'alpha', origin: 'https://alpha.example' };

/** A real proof for `alpha`, minted with the fixture's key (the runner's own minting, used directly). */
export async function mintProof(app: string, nowMs: number, offsetS = 120): Promise<string> {
  const key = CASES.fixture.proofKeys['main']!;
  const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64url');
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const payload = b64(
    new TextEncoder().encode(
      `{"v":1,"app":"${app}","bis":${Math.floor(nowMs / 1000) + offsetS},"n":"${nonce}"}`,
    ),
  );
  const k = await crypto.subtle.importKey(
    'jwk',
    key.privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    k,
    new TextEncoder().encode(`n1.${payload}`),
  );
  return `n1.${payload}.${b64(new Uint8Array(sig))}`;
}
