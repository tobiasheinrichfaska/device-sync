// Opt-in helper: starts tests/relay-real/harness.ts as a child process against the real relay
// server in RELAY_REAL_PATH and gives the base URL plus a `ConformanceControl` that talks to the
// harness's control port.
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { realAppsJson } from './fixture-apps.ts';
import { envNames } from './real-source.ts';
import type { ConformanceControl } from '../../src/relay/conformance.ts';

export interface RealServer {
  readonly base: string;
  readonly control: ConformanceControl & {
    pushes(): Promise<unknown[]>;
    now(): Promise<number>;
    reset(): Promise<void>;
  };
  stop(): Promise<void>;
}

export const realPath = (): string | undefined => process.env['RELAY_REAL_PATH'];

export async function startReal(): Promise<RealServer> {
  const root = realPath();
  if (!root) throw new Error('set RELAY_REAL_PATH to the directory of the real relay server');
  const child: ChildProcess = spawn(
    process.execPath,
    [new URL('./harness.ts', import.meta.url).pathname],
    { env: { ...process.env, RELAY_REAL_PATH: root }, stdio: ['ignore', 'pipe', 'inherit'] },
  );
  const ports = await new Promise<{ relay: number; control: number }>((ok, fail) => {
    let text = '';
    child.stdout!.on('data', (c: Buffer) => {
      text += c.toString();
      const line = text.split('\n')[0];
      if (text.includes('\n') && line) ok(JSON.parse(line));
    });
    child.on('exit', (code) => fail(new Error(`harness exited with ${code}`)));
  });
  const call = async (body: object): Promise<any> => {
    const r = await fetch(`http://127.0.0.1:${ports.control}/`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(JSON.stringify(j));
    return j;
  };
  return {
    base: `http://127.0.0.1:${ports.relay}`,
    control: {
      reset: async () => void (await call({ op: 'reset' })),
      advanceTime: async (ms) => void (await call({ op: 'advanceTime', ms })),
      setLimits: async (limits) => void (await call({ op: 'setLimits', limits })),
      setPushResult: async (result) => void (await call({ op: 'setPushResult', result })),
      pushes: async () => (await call({ op: 'pushes' })).pushes,
      now: async () => (await call({ op: 'now' })).now,
    },
    stop: async () => {
      child.kill('SIGTERM');
      await new Promise((ok) => child.once('exit', ok));
    },
  };
}

/**
 * The real server exactly as it is deployed: `node src/server.ts` with its own environment
 * variables (apps file, secret, PORT; their names are read from its start module), real clocks, real limits and no test
 * interface. Only the apps and the secret come from the conformance fixture.
 */
export async function startPlain(): Promise<{ base: string; stop(): Promise<void> }> {
  const root = realPath();
  if (!root) throw new Error('set RELAY_REAL_PATH to the directory of the real relay server');
  const fixture = JSON.parse(
    readFileSync(new URL('../relay/conformance/cases.json', import.meta.url), 'utf8'),
  ).fixture;
  const dir = mkdtempSync(join(tmpdir(), 'relay-real-'));
  const apps = join(dir, 'apps.json');
  writeFileSync(apps, realAppsJson(fixture));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const names = envNames(root);
  const child = spawn(process.execPath, [join(root, 'src/server.ts')], {
    env: {
      PATH: process.env['PATH'] ?? '',
      PORT: String(port),
      [names.apps]: apps,
      [names.secret]: fixture.secrets.main,
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  await new Promise<void>((ok, fail) => {
    child.stdout!.on('data', (c: Buffer) => {
      if (c.toString().includes('"start"')) ok();
    });
    child.on('exit', (code) => fail(new Error(`server exited with ${code}`)));
  });
  return {
    base: `http://127.0.0.1:${port}`,
    stop: async () => {
      child.kill('SIGTERM');
      await new Promise((ok) => child.once('exit', ok));
    },
  };
}
