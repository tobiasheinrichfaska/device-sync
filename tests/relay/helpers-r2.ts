// Helpers of the revision-2 tests: keys and signers, token spellings for the readers, real founder
// tickets for the reference server, a client harness with a signer, and the mutators of the fuzz tests.
import { RelayClient, signerFromKeys } from '../../src/relay/index.ts';
import type {
  CredentialStore,
  FetchLike,
  PossessionSigner,
  RelayClientOptions,
} from '../../src/relay/index.ts';
import { ALPHA, BASE, CASES_R2, serverForR2 } from './helpers.ts';

export const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
export const MAC = b64(new Uint8Array(32).fill(7));
export const SIG = b64(new Uint8Array(64).fill(9));
export const RAND = b64(new Uint8Array(16).fill(3));
export const DEV = `geraet-${'ab12'.repeat(8)}`;
export const DEV2 = `geraet-${'cd34'.repeat(8)}`;
/** A well-formed raw public key (65 bytes starting with 4); not on the curve, for readers that only read. */
export const FAKE_KEY = b64(Uint8Array.from([4, ...new Uint8Array(64).fill(5)]));

export const certText = (
  o: {
    app?: string;
    group?: string;
    device?: string;
    role?: string;
    key?: string;
    end?: number;
  } = {},
): string =>
  `c1.${o.app ?? 'alpha'}.${o.group ?? '1'}.${o.device ?? DEV}.${o.role ?? 'buero'}.${o.key ?? FAKE_KEY}.${o.end ?? 1802476800}.${MAC}`;
export const inv2Text = (
  o: { app?: string; group?: string; inviter?: string; role?: string; end?: number } = {},
): string =>
  `e2.${o.app ?? 'alpha'}.${o.group ?? '1'}.${o.inviter ?? DEV}.${o.role ?? 'ohne'}.${o.end ?? 1802476800}.${RAND}.${MAC}`;
export const founderText = (o: { app?: string; group?: string; end?: number } = {}): string =>
  `g1.${o.app ?? 'alpha'}.${o.group ?? '2'}.${o.end ?? 1802476800}.${RAND}.${SIG}`;
export const ticketText = (app = 'alpha', device = DEV, end = 1802476800): string =>
  `z1.${app}.${device}.${end}.${MAC}`;

export const J = JSON.stringify;

/** A fresh device key pair and the signer over it. */
export async function newSigner(): Promise<{
  signer: PossessionSigner;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  return {
    signer: await signerFromKeys(pair.privateKey, pair.publicKey),
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
  };
}

const bytes = (u: Uint8Array): string => Buffer.from(u).toString('base64url');

/** A founder ticket signed with the fixture's developer key (the server holds its public half). */
export async function mintFounder(
  app: string,
  group: string,
  nowMs: number,
  offsetS = 600,
  keyName: 'main' | 'other' = 'main',
): Promise<string> {
  const jwk = CASES_R2.fixture.developerKeys?.[keyName]?.privateJwk as JsonWebKey;
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  const head = `g1.${app}.${group}.${Math.floor(nowMs / 1000) + offsetS}.${bytes(crypto.getRandomValues(new Uint8Array(16)))}`;
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(head),
  );
  return `${head}.${bytes(new Uint8Array(sig))}`;
}

export function memoryStore(): CredentialStore & { value: string | undefined } {
  const s = {
    value: undefined as string | undefined,
    get: () => s.value,
    set: (t: string) => {
      s.value = t;
    },
    remove: () => {
      s.value = undefined;
    },
  };
  return s;
}

export interface R2Harness {
  server: ReturnType<typeof serverForR2>;
  client: RelayClient;
  store: ReturnType<typeof memoryStore>;
  signer: PossessionSigner;
  calls: { url: string; init: RequestInit }[];
  sleeps: number[];
}

/** A client of revision 2 (with a signer) against a reference server; `wrap` may replace the network. */
export async function r2Harness(
  over: Partial<RelayClientOptions> = {},
  server: ReturnType<typeof serverForR2> = serverForR2(),
  wrap?: (inner: FetchLike) => FetchLike,
  app: { app: string; origin: string } = ALPHA,
): Promise<R2Harness> {
  const calls: { url: string; init: RequestInit }[] = [];
  const sleeps: number[] = [];
  const inner: FetchLike = (url, init) => {
    calls.push({ url, init });
    return server.fetch(url, init);
  };
  const store = over.store ? (over.store as ReturnType<typeof memoryStore>) : memoryStore();
  const { signer } = over.signer ? { signer: over.signer } : await newSigner();
  const client = new RelayClient({
    baseUrl: BASE,
    appId: app.app,
    origin: app.origin,
    fetch: wrap ? wrap(inner) : inner,
    store,
    clock: server.now,
    random: () => 0.5,
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    signer,
    ...over,
  });
  return { server, client, store, signer, calls, sleeps };
}

// ── mutators (seeded) ─────────────────────────────────────────────────────────────────────────────

export function mutateText(rng: () => number, text: string): string {
  const n = 1 + Math.floor(rng() * 4);
  let s = text;
  for (let i = 0; i < n; i += 1) {
    const at = Math.floor(rng() * (s.length + 1));
    switch (Math.floor(rng() * 6)) {
      case 0:
        s = s.slice(0, at) + s.slice(at + 1);
        break;
      case 1:
        s = s.slice(0, at) + String.fromCharCode(32 + Math.floor(rng() * 95)) + s.slice(at);
        break;
      case 2:
        s = s.slice(0, at);
        break;
      case 3:
        s = s.slice(0, at) + '"extra":1,' + s.slice(at);
        break;
      case 4:
        s = s.replace(/"([a-zA-Z]+)":/, '"__proto__":');
        break;
      default:
        s = s.replace(
          /true|false|null|\d+/,
          ['null', '"x"', '[]', '{}', '-1', '1e400'][Math.floor(rng() * 6)] as string,
        );
    }
  }
  return s;
}

export const randomValue = (rng: () => number, keys: readonly string[], depth = 0): unknown => {
  const k = Math.floor(rng() * (depth > 2 ? 5 : 7));
  if (k === 0) return null;
  if (k === 1) return rng() < 0.5;
  if (k === 2) return Math.floor(rng() * 4000) - 1000;
  if (k === 3) {
    const pool = ['', 'x', DEV, certText(), ticketText(), 'unlesbar', '2027-01-01', '1', 'buero'];
    return pool[Math.floor(rng() * pool.length)];
  }
  if (k === 4) return rng().toString(36);
  if (k === 5) {
    return Array.from({ length: Math.floor(rng() * 4) }, () => randomValue(rng, keys, depth + 1));
  }
  const o: Record<string, unknown> = {};
  for (const key of keys) if (rng() < 0.3) o[key] = randomValue(rng, keys, depth + 1);
  return o;
};
