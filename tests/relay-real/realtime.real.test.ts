// Opt-in: behaviour that needs real time, against the real server as deployed (`node src/server.ts`,
// no test interface, real clocks): the 30-second wait of a message and of presence, and the time
// limits of the HTTP layer (slow body: readable 408 `zu-langsam`; slow head: Node's own bare 408).
import { createHmac } from 'node:crypto';
import { connect } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CASES } from '../relay/helpers.ts';
import { startPlain } from './realserver.ts';

let plain: Awaited<ReturnType<typeof startPlain>>;
beforeAll(async () => {
  plain = await startPlain();
});
afterAll(async () => plain?.stop());

const secret = Buffer.from(CASES.fixture.secrets['main'] as string, 'base64url');
const access = (dev: string): string => {
  const head = `z1.alpha.${dev}.${Math.floor(Date.now() / 1000) + 86_400}`;
  return `${head}.${createHmac('sha256', secret).update(`zugang:${head}`).digest('base64url')}`;
};
const A = `geraet-${'1'.repeat(32)}`;
const B = `geraet-${'2'.repeat(32)}`;
const call = async (dev: string, path: string, body: unknown) => {
  const r = await fetch(`${plain.base}${path}`, {
    method: 'POST',
    headers: {
      Origin: 'https://alpha.example',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${access(dev)}`,
    },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: (await r.json()) as any };
};
const sleep = (ms: number): Promise<void> => new Promise((ok) => setTimeout(ok, ms));

/** Sends `text` on a raw socket, then waits for the answer (or the close) and returns what arrived. */
function raw(text: string, waitMs: number): Promise<{ text: string; closedMs: number }> {
  return new Promise((ok) => {
    const t0 = Date.now();
    const port = Number(new URL(plain.base).port);
    let got = '';
    const s = connect(port, '127.0.0.1', () => s.write(text));
    s.on('data', (d) => (got += d.toString('latin1')));
    s.on('close', () => ok({ text: got, closedMs: Date.now() - t0 }));
    setTimeout(() => s.destroy(), waitMs);
  });
}

describe('real relay in real time', () => {
  it('a message and presence last 30 seconds', async () => {
    await call(B, '/v1/abholen', {}); // B is present from now on
    const sent = await call(A, '/v1/ablegen', { an: [{ geraet: B, inhalt: 'aGVsbG8' }] });
    expect(sent.json.ergebnisse[0]).toMatchObject({ ok: true, anwesend: true });
    await sleep(31_000);
    const asked = await call(A, '/v1/abholen', { anwesend: [B] });
    expect(asked.json.anwesend).toEqual([]);
    const got = await call(B, '/v1/abholen', {});
    expect(got.json.nachrichten).toEqual([]);

    await call(A, '/v1/ablegen', { an: [{ geraet: B, inhalt: 'aGVsbG8' }] });
    await sleep(25_000);
    const early = await call(B, '/v1/abholen', {});
    expect(early.json.nachrichten).toHaveLength(1);
  }, 120_000);

  it('a body that does not arrive in 14 s is a readable 408 zu-langsam, a head that does not arrive in 10 s a bare 408', async () => {
    const body = '{"x":1}';
    const [slowBody, slowHead] = await Promise.all([
      raw(
        `POST /v1/ping HTTP/1.1\r\nHost: x\r\nOrigin: https://alpha.example\r\nContent-Type: application/json\r\nAuthorization: Bearer ${access(A)}\r\nContent-Length: ${body.length}\r\n\r\n{`,
        20_000,
      ),
      raw('POST /v1/ping HTTP/1.1\r\nHost: x\r\nOrigin: https://alpha.example\r\n', 20_000),
    ]);
    expect(slowBody.text).toMatch(/^HTTP\/1\.1 408 /);
    expect(slowBody.text).toContain('"art":"zu-langsam"');
    expect(slowBody.text.toLowerCase()).toContain(
      'access-control-allow-origin: https://alpha.example',
    );
    expect(slowBody.closedMs).toBeGreaterThan(13_000);
    expect(slowBody.closedMs).toBeLessThan(17_000);
    expect(slowHead.text).toMatch(/^HTTP\/1\.1 408 /);
    expect(slowHead.text.toLowerCase()).not.toContain('access-control-allow-origin');
    expect(slowHead.closedMs).toBeGreaterThan(9_000);
    expect(slowHead.closedMs).toBeLessThan(13_000);
  }, 60_000);
});
