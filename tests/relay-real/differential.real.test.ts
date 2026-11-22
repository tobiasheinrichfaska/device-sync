// Opt-in: the same unusual requests to the REAL relay server and to the package's reference server;
// every difference must be on the list of known differences below (each is described in
// docs/relay-protocol.md, "Open points of version 1"), nothing else may differ.
import { createHmac } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BASE, CASES, serverFor } from '../relay/helpers.ts';
import { startReal, type RealServer } from './realserver.ts';

let real: RealServer;
beforeAll(async () => {
  real = await startReal();
});
afterAll(async () => real?.stop());

const secret = Buffer.from(CASES.fixture.secrets['main'] as string, 'base64url');
const A = `geraet-${'a'.repeat(32)}`;
const B = `geraet-${'b'.repeat(32)}`;
const nowS = Math.floor(Date.now() / 1000);
const token = (app: string, dev: string, off = 86_400): string => {
  const head = `z1.${app}.${dev}.${nowS + off}`;
  return `${head}.${createHmac('sha256', secret).update(`zugang:${head}`).digest('base64url')}`;
};
const ORIGIN = 'https://alpha.example';
const auth = (t = token('alpha', A)) => ({ Authorization: `Bearer ${t}` });
const json = { 'Content-Type': 'application/json' };

interface Probe {
  name: string;
  method?: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}
const post = (
  name: string,
  path: string,
  body: string | undefined,
  extra: Record<string, string> = {},
): Probe => ({
  name,
  path,
  method: 'POST',
  headers: { Origin: ORIGIN, ...json, ...auth(), ...extra },
  ...(body === undefined ? {} : { body }),
});

const drop = (an: unknown): string => JSON.stringify({ an });
const probes: Probe[] = [
  post('ping empty body', '/v1/ping', ''),
  post('ping null', '/v1/ping', 'null'),
  post('ping array', '/v1/ping', '[]'),
  post('ping string', '/v1/ping', '"x"'),
  post('ping not json', '/v1/ping', '{'),
  post('ping duplicate member', '/v1/ping', '{"a":1,"a":2}'),
  post('ping with space', '/v1/ping', ' { } '),
  post('ping unknown member', '/v1/ping', '{"x":1}'),
  post('ping proto', '/v1/ping', '{"__proto__":{}}'),
  post('ping deep', '/v1/ping', '['.repeat(2000) + ']'.repeat(2000)),
  post('ping BOM', '/v1/ping', '﻿{}'),
  post('ping utf8 charset', '/v1/ping', '{}', {
    'Content-Type': 'application/json; charset=utf-8',
  }),
  post('ping upper content type', '/v1/ping', '{}', { 'Content-Type': 'Application/JSON' }),
  post('ping text/plain', '/v1/ping', '{}', { 'Content-Type': 'text/plain' }),
  post('ping json-ish type', '/v1/ping', '{}', { 'Content-Type': 'application/jsonx' }),
  post('ping lowercase bearer', '/v1/ping', '{}', { Authorization: `bearer ${token('alpha', A)}` }),
  post('ping basic', '/v1/ping', '{}', { Authorization: `Basic ${token('alpha', A)}` }),
  post('ping double space', '/v1/ping', '{}', { Authorization: `Bearer  ${token('alpha', A)}` }),
  post('ping long auth', '/v1/ping', '{}', { Authorization: `Bearer ${'a'.repeat(5000)}` }),
  post('ping expired', '/v1/ping', '{}', auth(token('alpha', A, -10))),
  post('ping far future access', '/v1/ping', '{}', auth(token('alpha', A, 365 * 86_400))),
  post('ping other app origin', '/v1/ping', '{}', { Origin: 'https://beta.example' }),
  post('ping no origin', '/v1/ping', '{}', { Origin: '' }),
  post('ping origin trailing slash', '/v1/ping', '{}', { Origin: `${ORIGIN}/` }),
  post('ping origin uppercase', '/v1/ping', '{}', { Origin: ORIGIN.toUpperCase() }),
  post('ping origin http', '/v1/ping', '{}', { Origin: 'http://alpha.example' }),
  { name: 'ping GET', method: 'GET', path: '/v1/ping', headers: { Origin: ORIGIN, ...auth() } },
  {
    name: 'ping PUT',
    method: 'PUT',
    path: '/v1/ping',
    headers: { Origin: ORIGIN, ...json, ...auth() },
    body: '{}',
  },
  { name: 'ping HEAD', method: 'HEAD', path: '/v1/ping', headers: { Origin: ORIGIN, ...auth() } },
  post('path trailing slash', '/v1/ping/', '{}'),
  post('path double slash', '//v1/ping', '{}'),
  post('path upper', '/V1/ping', '{}'),
  post('path dot', '/v1/./ping', '{}'),
  post('path encoded', '/v1/pin%67', '{}'),
  post('path query', '/v1/ping?x=1', '{}'),
  post('path empty query', '/v1/ping?', '{}'),
  post('unknown path', '/v2/ping', '{}'),
  post('root', '/', '{}'),
  { name: 'health GET no origin', method: 'GET', path: '/gesund' },
  { name: 'health GET origin', method: 'GET', path: '/gesund', headers: { Origin: ORIGIN } },
  {
    name: 'health GET foreign origin',
    method: 'GET',
    path: '/gesund',
    headers: { Origin: 'https://evil.example' },
  },
  {
    name: 'health POST',
    method: 'POST',
    path: '/gesund',
    headers: { Origin: ORIGIN, ...json },
    body: '{}',
  },
  { name: 'health HEAD', method: 'HEAD', path: '/gesund' },
  { name: 'health query', method: 'GET', path: '/gesund?x' },
  { name: 'health trailing slash', method: 'GET', path: '/gesund/' },
  {
    name: 'preflight ping',
    method: 'OPTIONS',
    path: '/v1/ping',
    headers: { Origin: ORIGIN, 'Access-Control-Request-Method': 'POST' },
  },
  {
    name: 'preflight unknown path',
    method: 'OPTIONS',
    path: '/nope',
    headers: { Origin: ORIGIN, 'Access-Control-Request-Method': 'POST' },
  },
  {
    name: 'preflight health',
    method: 'OPTIONS',
    path: '/gesund',
    headers: { Origin: ORIGIN, 'Access-Control-Request-Method': 'GET' },
  },
  {
    name: 'preflight no request method',
    method: 'OPTIONS',
    path: '/v1/ping',
    headers: { Origin: ORIGIN },
  },
  {
    name: 'preflight PUT',
    method: 'OPTIONS',
    path: '/v1/ping',
    headers: { Origin: ORIGIN, 'Access-Control-Request-Method': 'PUT' },
  },
  {
    name: 'preflight foreign',
    method: 'OPTIONS',
    path: '/v1/ping',
    headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' },
  },
  {
    name: 'preflight no origin',
    method: 'OPTIONS',
    path: '/v1/ping',
    headers: { 'Access-Control-Request-Method': 'POST' },
  },
  {
    name: 'preflight request headers',
    method: 'OPTIONS',
    path: '/v1/ablegen',
    headers: {
      Origin: ORIGIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'authorization,content-type,x-version-hint',
    },
  },
  post('renew with member', '/v1/erneuern', '{"x":1}'),
  post('invite with member', '/v1/einladen', '{"rolle":"ohne"}'),
  post('drop empty list', '/v1/ablegen', drop([])),
  post('drop not a list', '/v1/ablegen', '{"an":{}}'),
  post(
    'drop 51',
    '/v1/ablegen',
    drop(
      Array.from({ length: 51 }, (_, i) => ({
        geraet: `geraet-${i.toString(16).padStart(32, '0')}`,
        inhalt: 'aA',
      })),
    ),
  ),
  post('drop self', '/v1/ablegen', drop([{ geraet: A, inhalt: 'aA' }])),
  post(
    'drop twice same',
    '/v1/ablegen',
    drop([
      { geraet: B, inhalt: 'aA' },
      { geraet: B, inhalt: 'aA' },
    ]),
  ),
  post('drop bad id', '/v1/ablegen', drop([{ geraet: 'geraet-xyz', inhalt: 'aA' }])),
  post(
    'drop uppercase id',
    '/v1/ablegen',
    drop([{ geraet: `geraet-${'B'.repeat(32)}`, inhalt: 'aA' }]),
  ),
  post('drop empty content', '/v1/ablegen', drop([{ geraet: B, inhalt: '' }])),
  post('drop padded base64', '/v1/ablegen', drop([{ geraet: B, inhalt: 'aGVsbG8=' }])),
  post('drop base64 plus', '/v1/ablegen', drop([{ geraet: B, inhalt: 'a+b/' }])),
  post('drop non-canonical tail', '/v1/ablegen', drop([{ geraet: B, inhalt: 'aB' }])),
  post('drop length 1 mod 4', '/v1/ablegen', drop([{ geraet: B, inhalt: 'aGVsb' }])),
  post('drop extra entry member', '/v1/ablegen', drop([{ geraet: B, inhalt: 'aA', x: 1 }])),
  post('drop extra top member', '/v1/ablegen', '{"an":[],"x":1}'),
  post('drop device number', '/v1/ablegen', drop([{ geraet: 5, inhalt: 'aA' }])),
  post(
    'drop other app id shape',
    '/v1/ablegen',
    drop([{ geraet: `geraet-${'0'.repeat(31)}`, inhalt: 'aA' }]),
  ),
  post(
    'collect ask 201',
    '/v1/abholen',
    JSON.stringify({
      anwesend: Array.from({ length: 201 }, (_, i) => `geraet-${i.toString(16).padStart(32, '0')}`),
    }),
  ),
  post('collect ask dup', '/v1/abholen', JSON.stringify({ anwesend: [B, B] })),
  post('collect ask self', '/v1/abholen', JSON.stringify({ anwesend: [A] })),
  post('collect ask bad', '/v1/abholen', JSON.stringify({ anwesend: ['x'] })),
  post('collect ask null', '/v1/abholen', JSON.stringify({ anwesend: null })),
  post('collect ask empty', '/v1/abholen', JSON.stringify({ anwesend: [] })),
  post('collect unknown member', '/v1/abholen', '{"x":1}'),
  post('ring empty', '/v1/klingeln', '{}'),
  post(
    'ring wrong host',
    '/v1/klingeln',
    JSON.stringify({
      endpunkt: 'https://evil.example/x',
      vapid: `vapid t=a.b.c, k=${'A'.repeat(87)}`,
      ttl: 1,
      dringlichkeit: 'low',
      inhalt: 'aA',
    }),
  ),
  post('enrol both', '/v1/einschreiben', '{"nachweis":"n1.a.b","einladung":"e1.a.b.c.d"}', {
    Authorization: '',
  }),
  post('enrol none', '/v1/einschreiben', '{}', { Authorization: '' }),
  post('enrol with bearer', '/v1/einschreiben', '{"nachweis":"n1.a.b"}'),
  post('enrol garbage proof', '/v1/einschreiben', '{"nachweis":"x"}', { Authorization: '' }),
  post('enrol garbage invitation', '/v1/einschreiben', '{"einladung":"x"}', { Authorization: '' }),
  post('enrol proof not string', '/v1/einschreiben', '{"nachweis":5}', { Authorization: '' }),
  post('enrol other secret access', '/v1/ping', '{}', {
    Authorization: `Bearer ${'z1.alpha.' + A + '.' + (nowS + 1000) + '.' + 'A'.repeat(43)}`,
  }),
  post('access unknown app', '/v1/ping', '{}', auth(token('nosuch', A))),
  post('access bad device', '/v1/ping', '{}', auth(token('alpha', 'geraet-zz'))),
  post(
    'access bis with plus',
    '/v1/ping',
    '{}',
    auth(token('alpha', A).replace(/\.\d+\./, '.+1.')),
  ),
  post('access gamma from alpha', '/v1/ping', '{}', auth(token('gamma', A))),
  post(
    'access of blocked',
    '/v1/ping',
    '{}',
    auth(token('blocked', 'geraet-00000000000000000000000000000001')),
  ),
];

interface Seen {
  status: number;
  type: string | null;
  cors: string | null;
  common: string;
  body: string;
}

const norm = (text: string, p: Probe): string => {
  if (p.method === 'HEAD') return 'head';
  try {
    const j = JSON.parse(text);
    // The existing relay says more in `/gesund` (members of its later admission revision); the protocol
    // lists them as optional, so only `ok` and `stand` are compared.
    if (j && typeof j === 'object' && j.ok === true && 'stand' in j) return 'health';
    if (j && typeof j === 'object' && 'art' in j) return `art=${j.art}`;
    return JSON.stringify(j, (k, v) =>
      ['bis', 'zugang', 'einladung', 'stand', 'v'].includes(k) ? '*' : v,
    );
  } catch {
    return `raw:${text.slice(0, 40)}`;
  }
};

async function run(
  f: (u: string, i: RequestInit) => Promise<Response>,
  base: string,
  p: Probe,
): Promise<Seen> {
  try {
    const headers = Object.fromEntries(Object.entries(p.headers ?? {}).filter(([, v]) => v !== ''));
    const r = await f(`${base}${p.path}`, {
      method: p.method ?? 'GET',
      headers,
      ...(p.body === undefined ? {} : { body: p.body }),
    });
    const text = await r.text();
    return {
      status: r.status,
      type: r.headers.get('content-type'),
      cors: r.headers.get('access-control-allow-origin'),
      common: [
        'cache-control',
        'x-content-type-options',
        'vary',
        'access-control-allow-methods',
        'access-control-max-age',
      ]
        .map((h) => `${h}=${r.headers.get(h)}`)
        .join(';'),
      body: norm(text, p),
    };
  } catch (e) {
    return { status: 0, type: null, cors: null, common: '', body: `ERR ${String(e)}` };
  }
}

describe('real relay against the reference server on unusual requests', () => {
  it('answers every probe like the reference server (only the documented differences remain)', async () => {
    const ref = serverFor();
    const diffs: string[] = [];
    for (const p of probes) {
      const a = await run(ref.fetch, BASE, p);
      const b = await run((u, i) => fetch(u, i), real.base, p);
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        diffs.push(`${p.name}\n   ref : ${JSON.stringify(a)}\n   real: ${JSON.stringify(b)}`);
      }
    }
    expect(diffs.join('\n')).toBe('');
  });

  it("the preflight lists Authorization and Content-Type (open point 6: the exact value is the server's)", async () => {
    const r = await fetch(`${real.base}/v1/ablegen`, {
      method: 'OPTIONS',
      headers: { Origin: ORIGIN, 'Access-Control-Request-Method': 'POST' },
    });
    const allowed = (r.headers.get('access-control-allow-headers') ?? '')
      .split(',')
      .map((x) => x.trim());
    expect(allowed).toEqual(expect.arrayContaining(['authorization', 'content-type']));
  });
});
