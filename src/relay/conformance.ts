// The conformance runner: runs the language-neutral cases of tests/relay/conformance/cases.json
// against a RUNNING relay server and says, per case, whether the server behaves as
// docs/relay-protocol.md says. A server owner calls `runConformance(baseUrl, fetch, { cases })`.
// It speaks the protocol only over HTTP; the few things that need the server's help (a clock that
// can be moved, lower limits, a stand-in push service, a clean state) go through the OPTIONAL
// `control` object (spec: "Test interface"); a case that needs one the caller did not give is skipped,
// never counted as passed. It uses Web Crypto only, so it runs in browsers and in Node.
import { base64url, fromBase64url } from '../core/encoding.ts';
import { bodyHash, possessionText } from './possession.ts';

export interface ConformanceFixture {
  /** HMAC secrets (base64url) the server under test must be configured with, by name. */
  readonly secrets: Readonly<Record<string, string>>;
  /** Proof key pairs: the raw public key goes into the server's configuration, the private JWK signs proofs. */
  readonly proofKeys: Readonly<
    Record<string, { readonly publicRaw: string; readonly privateJwk: JsonWebKey }>
  >;
  /** The apps the server must serve (documentation for the server owner; the runner does not read it). */
  readonly apps: Readonly<Record<string, unknown>>;
  /** Revision 2: the developer's key pairs (founder tickets): the raw public key goes into the server, the private JWK signs. */
  readonly developerKeys?: Readonly<
    Record<string, { readonly publicRaw: string; readonly privateJwk: JsonWebKey }>
  >;
  /** Revision 2: developer passwords the server must hold (documentation; the runner sends them as the cases say). */
  readonly developerPasswords?: readonly unknown[];
  /** Revision 2: the names of the two request headers; the server under test may use others, the caller then says so here. */
  readonly headers?: { readonly possession: string; readonly version: string };
}

export type BodySpec =
  | { readonly json: unknown }
  | { readonly text: string }
  | {
      /** `prefix`, then `fill` repeated `count` times, then `suffix` (placeholders allowed in prefix and suffix). */
      readonly generate: {
        readonly prefix: string;
        readonly fill: string;
        readonly count: number;
        readonly suffix: string;
      };
    };

export interface Expectation {
  readonly status: number;
  /** A value must be equal; `null` means the header must be absent. Names in lower case. */
  readonly headers?: Readonly<Record<string, string | null>>;
  /** Exact JSON, with the typed patterns of the spec ("Conformance case format"). */
  readonly body?: unknown;
  /** Revision 2: for a header whose value is a comma separated list: every token named here is in it (case and spaces do not matter). */
  readonly headersInclude?: Readonly<Record<string, readonly string[]>>;
  /** The answer has no body (a preflight answer). */
  readonly empty?: boolean;
  /**
   * The server may close the connection instead of answering (the runner then counts the step as
   * passed). For a body far larger than the socket buffers: a server that answers 413 at once and
   * closes while the client is still writing can make the client see a reset instead of the answer
   * (RFC 9112, 9.6); an answer that does arrive must still match.
   */
  readonly mayCloseConnection?: boolean;
}

/** Revision 2: sign the request with a key the runner made (placeholder `devicekey`), for a certificate. */
export interface PossessionSpec {
  /** The name of the runner's device key. */
  readonly key: string;
  /** The certificate that goes in the signed text (placeholders allowed). */
  readonly certificate: string;
  /** Seconds added to the server's now for the signed time. Default 0. */
  readonly offset?: number;
  /** Made once under this name and reused (a replay of the same request). */
  readonly name?: string;
  /** Sign this path / this body instead of the ones sent (a signature for another request). */
  readonly signPath?: string;
  readonly signBody?: string;
}

export interface ControlStep {
  readonly advanceTime?: number;
  readonly setLimits?: Readonly<Record<string, number>>;
  readonly setPushResult?: number | 'unreachable';
}

export interface ConformanceStep {
  readonly name?: string;
  readonly control?: ControlStep;
  readonly request?: {
    readonly method: string;
    readonly path: string;
    readonly headers?: Readonly<Record<string, string>>;
    readonly body?: BodySpec;
    /** Revision 2: adds the possession header. */
    readonly possession?: PossessionSpec;
    /** Revision 2: adds the version header with this number. */
    readonly version?: number;
  };
  readonly expect?: Expectation;
  /** JSON pointers into the answer body; the string found is kept under that name. */
  readonly capture?: Readonly<Record<string, string>>;
  /** Run the step this many times (placeholders ending in `#` are fresh each time). */
  readonly repeat?: number;
}

export interface ConformanceCase {
  readonly name: string;
  readonly spec?: string;
  /** `clock`, `limits`, `push-stub`: what the case needs from the test interface. */
  readonly needs?: readonly string[];
  readonly steps: readonly ConformanceStep[];
}

export interface ConformanceCases {
  readonly format: 'relay-conformance/1';
  readonly fixture: ConformanceFixture;
  readonly cases: readonly ConformanceCase[];
}

/** The optional test interface of a server under test. */
export interface ConformanceControl {
  reset?(): Promise<void> | void;
  advanceTime?(ms: number): Promise<void> | void;
  setLimits?(limits: Readonly<Record<string, number>>): Promise<void> | void;
  setPushResult?(result: number | 'unreachable'): Promise<void> | void;
}

export interface ConformanceOptions {
  readonly cases: ConformanceCases;
  /** The server's clock in ms (default: this machine's clock; give the server's when they differ). */
  readonly now?: () => number;
  readonly control?: ConformanceControl;
  /** Only the cases for which this answers true. */
  readonly only?: (name: string) => boolean;
  /** Per request. Default 30 000. */
  readonly timeoutMs?: number;
}

export interface CaseResult {
  readonly name: string;
  readonly status: 'pass' | 'fail' | 'skip';
  readonly reasons: readonly string[];
}

export interface ConformanceReport {
  readonly passed: number;
  readonly failed: number;
  readonly skipped: number;
  readonly results: readonly CaseResult[];
}

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

const utf8 = new TextEncoder();

class Context {
  readonly devices = new Map<string, string>();
  readonly vars = new Map<string, string>();
  readonly proofs = new Map<string, string>();
  readonly invitations = new Map<string, string>();
  readonly keys = new Map<string, { publicRaw: string; privateKey: CryptoKey }>();
  readonly possessions = new Map<string, string>();
}

const randomHex = (bytes: number): string =>
  [...globalThis.crypto.getRandomValues(new Uint8Array(bytes))]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
const randomB64 = (bytes: number): string =>
  base64url(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));

async function hmac(secret: Uint8Array, text: string): Promise<string> {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    secret as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return base64url(
    new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, utf8.encode(text))),
  );
}

async function signProof(jwk: JsonWebKey, text: string): Promise<string> {
  const key = await globalThis.crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  const sig = await globalThis.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    utf8.encode(text),
  );
  return base64url(new Uint8Array(sig));
}

async function deviceKey(
  name: string,
  env: { readonly ctx: Context },
): Promise<{ publicRaw: string; privateKey: CryptoKey }> {
  let k = env.ctx.keys.get(name);
  if (!k) {
    const pair = (await globalThis.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const raw = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey));
    k = { publicRaw: base64url(raw), privateKey: pair.privateKey };
    env.ctx.keys.set(name, k);
  }
  return k;
}

interface Env {
  readonly fixture: ConformanceFixture;
  readonly nowMs: () => number;
  readonly ctx: Context;
}

async function mint(kind: string, args: string[], env: Env): Promise<string> {
  const nowS = Math.floor(env.nowMs() / 1000);
  const offset = (text: string | undefined): number => {
    const n = Number(text);
    if (!Number.isInteger(n)) throw new Error(`bad offset "${text}"`);
    return n;
  };
  const secretBytes = (name: string | undefined): Uint8Array => {
    const s = env.fixture.secrets[name ?? ''];
    if (s === undefined) throw new Error(`unknown secret "${name}"`);
    return fromBase64url(s);
  };
  switch (kind) {
    case 'device': {
      const name = args[0] ?? '';
      // A literal device id (for a device the server has configured as blocked) is used as it is.
      if (/^geraet-[0-9a-f]{32}$/.test(name)) return name;
      if (name.endsWith('#')) return `geraet-${randomHex(16)}`;
      let id = env.ctx.devices.get(name);
      if (!id) env.ctx.devices.set(name, (id = `geraet-${randomHex(16)}`));
      return id;
    }
    case 'var': {
      const v = env.ctx.vars.get(args[0] ?? '') ?? env.ctx.devices.get(args[0] ?? '');
      if (v === undefined) throw new Error(`unknown variable "${args[0]}"`);
      return v;
    }
    case 'access': {
      // A fifth argument names the access: it is made once and reused (it keeps its end time while
      // the server's clock moves).
      const [app, deviceName, off, secret, memo] = args;
      const kept = memo === undefined ? undefined : env.ctx.vars.get(`access:${memo}`);
      if (kept) return kept;
      const device = await mint('device', [deviceName ?? ''], env);
      const head = `z1.${app}.${device}.${nowS + offset(off)}`;
      const text = `${head}.${await hmac(secretBytes(secret), `zugang:${head}`)}`;
      if (memo !== undefined) env.ctx.vars.set(`access:${memo}`, text);
      return text;
    }
    case 'invitation': {
      const [app, off, secret, name] = args;
      const have = env.ctx.invitations.get(name ?? '');
      if (have) return have;
      const head = `e1.${app}.${nowS + offset(off)}.${randomB64(16)}`;
      const text = `${head}.${await hmac(secretBytes(secret), `einladung:${head}`)}`;
      env.ctx.invitations.set(name ?? '', text);
      return text;
    }
    case 'proof': {
      const [app, off, keyName, name] = args;
      const have = env.ctx.proofs.get(name ?? '');
      if (have) return have;
      const key = env.fixture.proofKeys[keyName ?? ''];
      if (!key) throw new Error(`unknown proof key "${keyName}"`);
      const payload = base64url(
        utf8.encode(`{"v":1,"app":"${app}","bis":${nowS + offset(off)},"n":"${randomB64(16)}"}`),
      );
      const text = `n1.${payload}.${await signProof(key.privateJwk, `n1.${payload}`)}`;
      env.ctx.proofs.set(name ?? '', text);
      return text;
    }
    case 'header': {
      const names = env.fixture.headers ?? {
        possession: 'x-relay-signature',
        version: 'x-relay-protocol',
      };
      const name = names[(args[0] ?? '') as 'possession' | 'version'];
      if (!name) throw new Error(`unknown header "${args[0]}"`);
      return name;
    }
    case 'devicekey':
      return (await deviceKey(args[0] ?? '', env)).publicRaw;
    case 'certificate': {
      // certificate:APP:GROUP:DEVICE:ROLE:KEY:OFFSET:SECRET[:NAME]; in a role `~` stands for `:`
      const [app, group, deviceName, role, keyName, off, secret, memo] = args;
      const kept = memo === undefined ? undefined : env.ctx.vars.get(`certificate:${memo}`);
      if (kept) return kept;
      const device = await mint('device', [deviceName ?? ''], env);
      const key = (await deviceKey(keyName ?? '', env)).publicRaw;
      const head = `c1.${app}.${group}.${device}.${(role ?? '').replace('~', ':')}.${key}.${nowS + offset(off)}`;
      const text = `${head}.${await hmac(secretBytes(secret), `zertifikat:${head}`)}`;
      if (memo !== undefined) env.ctx.vars.set(`certificate:${memo}`, text);
      return text;
    }
    case 'invitation2': {
      // invitation2:APP:GROUP:INVITER:ROLE:OFFSET:SECRET:NAME
      const [app, group, inviter, role, off, secret, name] = args;
      const have = env.ctx.invitations.get(name ?? '');
      if (have) return have;
      const device = await mint('device', [inviter ?? ''], env);
      const head = `e2.${app}.${group}.${device}.${(role ?? '').replace('~', ':')}.${nowS + offset(off)}.${randomB64(16)}`;
      const text = `${head}.${await hmac(secretBytes(secret), `einladung:${head}`)}`;
      env.ctx.invitations.set(name ?? '', text);
      return text;
    }
    case 'founder': {
      // founder:APP:GROUP:OFFSET:DEVELOPERKEY:NAME
      const [app, group, off, keyName, name] = args;
      const have = env.ctx.invitations.get(`g:${name}`);
      if (have) return have;
      const key = env.fixture.developerKeys?.[keyName ?? ''];
      if (!key) throw new Error(`unknown developer key "${keyName}"`);
      const head = `g1.${app}.${group}.${nowS + offset(off)}.${randomB64(16)}`;
      const text = `${head}.${await signProof(key.privateJwk, head)}`;
      env.ctx.invitations.set(`g:${name}`, text);
      return text;
    }
    default:
      throw new Error(`unknown placeholder "${kind}"`);
  }
}

/** Replaces every `{{kind:arg:arg}}` in a text. */
async function expandText(text: string, env: Env): Promise<string> {
  const parts: string[] = [];
  let last = 0;
  for (const m of text.matchAll(/\{\{([a-z0-9]+)((?::[^:{}]*)*)\}\}/g)) {
    parts.push(text.slice(last, m.index));
    const args = m[2] === '' ? [] : (m[2] as string).slice(1).split(':');
    parts.push(await mint(m[1] as string, args, env));
    last = (m.index as number) + m[0].length;
  }
  parts.push(text.slice(last));
  return parts.join('');
}

async function expand(value: unknown, env: Env): Promise<unknown> {
  if (typeof value === 'string') return expandText(value, env);
  if (Array.isArray(value)) return Promise.all(value.map((v) => expand(v, env)));
  if (typeof value === 'object' && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = await expand(v, env);
    return out;
  }
  return value;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** Compares an answer with an expectation; pushes one reason per difference. */
function match(expected: unknown, actual: unknown, at: string, reasons: string[]): void {
  if (isObject(expected) && typeof expected['$type'] === 'string') {
    const t = expected['$type'];
    if (t === 'any') return;
    if (t === 'string') {
      if (typeof actual !== 'string') return void reasons.push(`${at}: expected a string`);
      const pattern = expected['pattern'];
      if (typeof pattern === 'string' && !new RegExp(pattern).test(actual)) {
        reasons.push(
          `${at}: "${actual.length > 60 ? actual.slice(0, 60) + '…' : actual}" does not match ${pattern}`,
        );
      }
      return;
    }
    if (t === 'integer') {
      if (typeof actual !== 'number' || !Number.isInteger(actual))
        return void reasons.push(`${at}: expected an integer`);
      const { min, max } = expected;
      if (typeof min === 'number' && actual < min) reasons.push(`${at}: ${actual} is below ${min}`);
      if (typeof max === 'number' && actual > max) reasons.push(`${at}: ${actual} is above ${max}`);
      return;
    }
    if (t === 'boolean') {
      if (typeof actual !== 'boolean') reasons.push(`${at}: expected a boolean`);
      return;
    }
    if (t === 'array') {
      if (!Array.isArray(actual)) return void reasons.push(`${at}: expected an array`);
      const { length, maxLength } = expected;
      if (typeof length === 'number' && actual.length !== length)
        reasons.push(`${at}: length ${actual.length}, expected ${length}`);
      if (typeof maxLength === 'number' && actual.length > maxLength)
        reasons.push(`${at}: length ${actual.length} over ${maxLength}`);
      return;
    }
    reasons.push(`${at}: unknown type "${t}" in the case`);
    return;
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) {
      return void reasons.push(`${at}: expected an array of ${expected.length}`);
    }
    expected.forEach((e, i) => match(e, actual[i], `${at}[${i}]`, reasons));
    return;
  }
  if (isObject(expected)) {
    if (!isObject(actual)) return void reasons.push(`${at}: expected an object`);
    const open = expected['$open'] === true;
    for (const [k, v] of Object.entries(expected)) {
      if (k === '$open') continue;
      if (!(k in actual)) reasons.push(`${at}.${k}: missing`);
      else match(v, actual[k], `${at}.${k}`, reasons);
    }
    if (!open) {
      for (const k of Object.keys(actual)) {
        if (!(k in expected)) reasons.push(`${at}.${k}: member not in the protocol`);
      }
    }
    return;
  }
  if (expected !== actual)
    reasons.push(`${at}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function pointer(value: unknown, path: string): unknown {
  let cur = value;
  for (const raw of path.split('/').slice(1)) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (Array.isArray(cur)) cur = cur[Number(key)];
    else if (isObject(cur)) cur = cur[key];
    else return undefined;
  }
  return cur;
}

async function runStep(
  step: ConformanceStep,
  baseUrl: string,
  fetchFn: FetchLike,
  env: Env,
  options: ConformanceOptions,
  advanced: { ms: number },
  reasons: string[],
): Promise<void> {
  const label = step.name ?? step.request?.path ?? 'control';
  if (step.control) {
    const c = options.control;
    if (step.control.advanceTime !== undefined) {
      await c?.advanceTime?.(step.control.advanceTime);
      advanced.ms += step.control.advanceTime;
    }
    if (step.control.setLimits) await c?.setLimits?.(step.control.setLimits);
    if (step.control.setPushResult !== undefined)
      await c?.setPushResult?.(step.control.setPushResult);
  }
  if (!step.request) return;
  const times = Math.max(1, step.repeat ?? 1);
  for (let round = 1; round <= times; round += 1) {
    const tag = times > 1 ? `${label} #${round}` : label;
    const path = (await expand(step.request.path, env)) as string;
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(step.request.headers ?? {})) {
      headers[await expandText(k, env)] = (await expand(v, env)) as string;
    }
    let body: string | undefined;
    const spec = step.request.body;
    if (spec) {
      if ('json' in spec) body = JSON.stringify(await expand(spec.json, env));
      else if ('text' in spec) body = (await expand(spec.text, env)) as string;
      else {
        const g = spec.generate;
        const prefix = await expandText(g.prefix, env);
        const suffix = await expandText(g.suffix, env);
        body = prefix + g.fill.repeat(Math.max(0, g.count)) + suffix;
      }
    }
    const pz = step.request.possession;
    if (pz) {
      const certificate = await expandText(pz.certificate, env);
      let value = pz.name === undefined ? undefined : env.ctx.possessions.get(pz.name);
      if (value === undefined) {
        const key = await deviceKey(pz.key, env);
        const t = Math.floor(env.nowMs() / 1000) + (pz.offset ?? 0);
        const text = possessionText(
          step.request.method,
          pz.signPath === undefined ? path : await expandText(pz.signPath, env),
          t,
          await bodyHash(pz.signBody === undefined ? (body ?? '') : pz.signBody),
          certificate,
        );
        const sig = await globalThis.crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          key.privateKey,
          utf8.encode(text),
        );
        value = `${t}.${base64url(new Uint8Array(sig))}`;
        if (pz.name !== undefined) env.ctx.possessions.set(pz.name, value);
      }
      headers[env.fixture.headers?.possession ?? 'x-relay-signature'] = value;
    }
    if (step.request.version !== undefined) {
      headers[env.fixture.headers?.version ?? 'x-relay-protocol'] = String(step.request.version);
    }
    const controller = new AbortController();
    const timer = globalThis.setTimeout(() => controller.abort(), options.timeoutMs ?? 30_000);
    let response: Response;
    let text: string;
    try {
      response = await fetchFn(`${baseUrl}${path}`, {
        method: step.request.method,
        headers,
        ...(body === undefined ? {} : { body }),
        signal: controller.signal,
      });
      text = await response.text();
    } catch (e) {
      if (step.expect?.mayCloseConnection === true && !controller.signal.aborted) return;
      reasons.push(`${tag}: no answer (${e instanceof Error ? e.name : 'error'})`);
      return;
    } finally {
      globalThis.clearTimeout(timer);
    }
    const before = reasons.length;
    const expect = step.expect;
    if (expect) {
      if (response.status !== expect.status)
        reasons.push(`${tag}: status ${response.status}, expected ${expect.status}`);
      commonHeaders(response, expect, tag, reasons);
      for (const [name, want] of Object.entries(expect.headers ?? {})) {
        const got = response.headers.get(name);
        if (want === null ? got !== null : got !== want) {
          reasons.push(
            `${tag}: header ${name} is ${got === null ? 'absent' : `"${got}"`}, expected ${want === null ? 'absent' : `"${want}"`}`,
          );
        }
      }
      for (const [name, tokens] of Object.entries(expect.headersInclude ?? {})) {
        const got = (response.headers.get(name) ?? '')
          .split(',')
          .map((x) => x.trim().toLowerCase());
        for (const raw of tokens) {
          const want = (await expandText(raw, env)).toLowerCase();
          if (!got.includes(want)) reasons.push(`${tag}: header ${name} lacks "${want}"`);
        }
      }
      if (expect.empty && text !== '') reasons.push(`${tag}: expected no body`);
    }
    let json: unknown;
    if (text !== '') {
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
        if (expect?.body !== undefined || step.capture) reasons.push(`${tag}: body is not JSON`);
      }
    }
    if (expect?.body !== undefined && json !== undefined) {
      const expectedBody = await expand(expect.body, env);
      match(expectedBody, json, `${tag}: body`, reasons);
    }
    if (step.capture) {
      for (const [name, ptr] of Object.entries(step.capture)) {
        const v = pointer(json, ptr);
        if (typeof v === 'string') env.ctx.vars.set(name, v);
        else reasons.push(`${tag}: nothing to capture at ${ptr}`);
      }
    }
    if (reasons.length > before) return;
  }
}

/** What every answer of a version-1 relay carries. */
function commonHeaders(
  response: Response,
  expect: Expectation,
  tag: string,
  reasons: string[],
): void {
  const h = response.headers;
  if (h.get('cache-control') !== 'no-store') reasons.push(`${tag}: Cache-Control is not no-store`);
  if (h.get('x-content-type-options') !== 'nosniff')
    reasons.push(`${tag}: X-Content-Type-Options is not nosniff`);
  if (h.get('vary') !== 'Origin') reasons.push(`${tag}: Vary is not Origin`);
  if (
    expect.status !== 204 &&
    !(h.get('content-type') ?? '').toLowerCase().startsWith('application/json')
  ) {
    reasons.push(`${tag}: Content-Type is not application/json`);
  }
}

/** Runs every case against the server at `baseUrl` and reports each. Never throws for a server's behaviour. */
export async function runConformance(
  baseUrl: string,
  fetchFn: FetchLike,
  options: ConformanceOptions,
): Promise<ConformanceReport> {
  const base = baseUrl.replace(/\/+$/, '');
  const results: CaseResult[] = [];
  const startNow = options.now ?? Date.now;
  const advanced = { ms: 0 };
  for (const c of options.cases.cases) {
    if (options.only && !options.only(c.name)) continue;
    const missing = (c.needs ?? []).filter((n) => {
      const ctl = options.control;
      if (n === 'clock') return !ctl?.advanceTime;
      if (n === 'limits') return !ctl?.setLimits;
      if (n === 'push-stub') return !ctl?.setPushResult;
      if (n === 'reset') return !ctl?.reset;
      return true;
    });
    if (missing.length > 0) {
      results.push({
        name: c.name,
        status: 'skip',
        reasons: [`needs the test interface: ${missing.join(', ')}`],
      });
      continue;
    }
    if (options.control?.reset) {
      await options.control.reset();
      advanced.ms = 0;
    }
    const env: Env = {
      fixture: options.cases.fixture,
      nowMs: () => startNow() + advanced.ms,
      ctx: new Context(),
    };
    const reasons: string[] = [];
    try {
      for (const step of c.steps) {
        await runStep(step, base, fetchFn, env, options, advanced, reasons);
        if (reasons.length > 0) break;
      }
    } catch (e) {
      reasons.push(`the case itself failed: ${e instanceof Error ? e.message : 'error'}`);
    }
    results.push({ name: c.name, status: reasons.length === 0 ? 'pass' : 'fail', reasons });
  }
  const count = (s: CaseResult['status']): number => results.filter((r) => r.status === s).length;
  return { passed: count('pass'), failed: count('fail'), skipped: count('skip'), results };
}
