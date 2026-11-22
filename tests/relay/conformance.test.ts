// The conformance runner against the reference server (it must pass), without the test interface
// (cases that need it are skipped, never passed), and against deliberately broken variants of the
// server (it must fail).
import { describe, expect, it } from 'vitest';
import { runConformance } from '../../src/relay/conformance.ts';
import { BASE, CASES, serverFor } from './helpers.ts';
import type { Defect } from './reference-server.ts';

const failures = (r: Awaited<ReturnType<typeof runConformance>>): string[] =>
  r.results.filter((x) => x.status === 'fail').map((x) => `${x.name}: ${x.reasons.join(' | ')}`);

describe('conformance runner against the reference server', () => {
  it('passes every case with the test interface', async () => {
    const server = serverFor();
    const report = await runConformance(BASE, server.fetch, {
      cases: CASES,
      control: server.control,
    });
    expect(failures(report)).toEqual([]);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBe(CASES.cases.length);
  });

  it('without the test interface the cases that need it are skipped, the rest pass', async () => {
    const server = serverFor();
    const report = await runConformance(BASE, server.fetch, { cases: CASES });
    expect(failures(report)).toEqual([]);
    const needing = CASES.cases.filter((c) => (c.needs ?? []).length > 0);
    expect(needing.length).toBeGreaterThan(5);
    expect(report.skipped).toBe(needing.length);
    expect(report.passed).toBe(CASES.cases.length - needing.length);
    for (const r of report.results.filter((x) => x.status === 'skip')) {
      expect(r.reasons[0]).toContain('test interface');
    }
  });

  it('a clock offset between runner and server does not matter when the runner is told the server time', async () => {
    const server = serverFor({ now: () => Date.now() + 3_600_000 });
    const report = await runConformance(BASE, server.fetch, {
      cases: CASES,
      control: server.control,
      now: server.now,
    });
    expect(failures(report)).toEqual([]);
  });

  it('every case has a name, steps, and every request step an expectation; names are unique', () => {
    const names = new Set<string>();
    for (const c of CASES.cases) {
      expect(names.has(c.name), c.name).toBe(false);
      names.add(c.name);
      expect(c.steps.length, c.name).toBeGreaterThan(0);
      for (const s of c.steps) if (s.request) expect(s.expect, c.name).toBeDefined();
    }
  });

  it('the cases cover every endpoint and every error kind a client can provoke over HTTP', () => {
    const text = JSON.stringify(CASES.cases);
    for (const path of [
      '/gesund',
      '/v1/einschreiben',
      '/v1/ping',
      '/v1/erneuern',
      '/v1/einladen',
      '/v1/ablegen',
      '/v1/abholen',
      '/v1/klingeln',
    ]) {
      expect(text, path).toContain(`"${path}`);
    }
    // Kinds that need a clock, a long wait, or a fault in the server cannot be provoked.
    const unreachable = new Set(['zu-langsam', 'beschaeftigt', 'intern', 'neue-fassung-noetig']);
    const kinds = [...text.matchAll(/"art":"([a-z-]+)"/g)].map((m) => m[1]);
    for (const k of [
      'unbekannt',
      'methode',
      'herkunft',
      'typ',
      'zu-gross',
      'unlesbar',
      'zugang-fehlt',
      'zugang-ungueltig',
      'zugang-abgelaufen',
      'app-unbekannt',
      'gesperrt',
      'zu-viele-anfragen',
      'nachweis-ungueltig',
      'nachweis-nicht-eingerichtet',
      'nachweis-unterschrift',
      'nachweis-abgelaufen',
      'einladung-ungueltig',
      'einladung-abgelaufen',
      'einladen-aus',
      'verbraucht',
      'zu-viele-einschreibungen',
      'zu-viele-einladungen',
      'klingeln-ungueltig',
      'klingeln-zu-oft',
      'push-dienst',
      'geraete-voll',
      'aufnahme-geschlossen',
      'voll',
      'app-voll',
      'absender-voll',
      'empfaenger-voll',
    ]) {
      expect(unreachable.has(k), k).toBe(false);
      expect(kinds, k).toContain(k);
    }
  });
});

describe('conformance runner against broken servers', () => {
  const defects: readonly Defect[] = [
    'origin-status',
    'no-nosniff',
    'no-vary',
    'cache-allowed',
    'expired-as-invalid',
    'keep-after-collect',
    'cors-for-all',
    'unknown-member-ok',
    'self-drop-ok',
    'reuse-wrong-kind',
    'drop-no-order',
    'preflight-for-all',
  ];
  for (const defect of defects) {
    it(`fails on the defect "${defect}"`, async () => {
      const server = serverFor({ defect });
      const report = await runConformance(BASE, server.fetch, {
        cases: CASES,
        control: server.control,
      });
      expect(report.failed, defect).toBeGreaterThan(0);
    });
  }

  it('a server that is not there fails every case it runs, with a reason, and never throws', async () => {
    const report = await runConformance(BASE, () => Promise.reject(new Error('down')), {
      cases: CASES,
      only: (n) => n.startsWith('ping with'),
    });
    expect(report.failed).toBe(1);
    expect(report.results[0]?.reasons[0]).toContain('no answer');
  });
});
