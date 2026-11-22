// The conformance cases of revision 2 (admission) against the reference server: they must pass with
// the test interface, a runner without it skips what needs it, and deliberately broken servers fail.
import { describe, expect, it } from 'vitest';
import { runConformance } from '../../src/relay/conformance.ts';
import { BASE, CASES_R2, serverForR2 } from './helpers.ts';
import type { Defect } from './reference-server.ts';

const failures = (r: Awaited<ReturnType<typeof runConformance>>): string[] =>
  r.results.filter((x) => x.status === 'fail').map((x) => `${x.name}: ${x.reasons.join(' | ')}`);

describe('revision 2: conformance cases against the reference server', () => {
  it('passes every case with the test interface', async () => {
    const server = serverForR2();
    const report = await runConformance(BASE, server.fetch, {
      cases: CASES_R2,
      control: server.control,
    });
    expect(failures(report)).toEqual([]);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBe(CASES_R2.cases.length);
  });

  it('without the test interface every case that needs a clean state is skipped, never passed', async () => {
    const server = serverForR2();
    const report = await runConformance(BASE, server.fetch, { cases: CASES_R2 });
    expect(failures(report)).toEqual([]);
    const needing = CASES_R2.cases.filter((c) => (c.needs ?? []).length > 0);
    expect(report.skipped).toBe(needing.length);
  });

  it('names are unique, every request step has an expectation, every case says its spec', () => {
    const names = new Set<string>();
    for (const c of CASES_R2.cases) {
      expect(names.has(c.name), c.name).toBe(false);
      names.add(c.name);
      expect(c.spec, c.name).toMatch(/^Revision 2/);
      for (const s of c.steps) if (s.request) expect(s.expect, c.name).toBeDefined();
    }
  });

  it('the cases reach every endpoint and every error kind of revision 2 that can be provoked over HTTP', () => {
    const text = JSON.stringify(CASES_R2.cases);
    for (const path of ['/v1/geraete', '/v1/sperren', '/v1/einladen', '/v1/erneuern', '/v1/ping']) {
      expect(text, path).toContain(`"${path}"`);
    }
    const kinds = [...text.matchAll(/"art":"([a-z-]+)"/g)].map((m) => m[1]);
    for (const k of [
      'besitz-fehlt',
      'besitz-ungueltig',
      'besitz-zeit',
      'rolle-nicht-erlaubt',
      'sperrliste-voll',
      'entwickler-ungueltig',
      'entwickler-abgelaufen',
      'entwickler-belegt',
      'neue-fassung-noetig',
      'gesperrt',
      'verbraucht',
      'aufnahme-geschlossen',
      'einladung-ungueltig',
      'unlesbar',
      'zugang-abgelaufen',
      'zugang-ungueltig',
      'herkunft',
    ]) {
      expect(kinds, k).toContain(k);
    }
  });
});

describe('revision 2: the runner fails broken servers', () => {
  const defects: readonly Defect[] = [
    'possession-unchecked',
    'possession-replay',
    'blocked-ticket-only',
    'role-unchecked',
    'group-leak',
    'blocked-as-expired',
    'founder-reusable',
    'preflight-no-headers',
  ];
  for (const defect of defects) {
    it(`fails on the defect "${defect}"`, async () => {
      const server = serverForR2({ defect });
      const report = await runConformance(BASE, server.fetch, {
        cases: CASES_R2,
        control: server.control,
      });
      expect(report.failed, defect).toBeGreaterThan(0);
    });
  }
});
