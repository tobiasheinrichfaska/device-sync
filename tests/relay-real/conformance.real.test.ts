// Opt-in (`npm run test:relay-real`): the conformance cases against the REAL relay server over real HTTP.
import { readFileSync, writeFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runConformance, type ConformanceCases } from '../../src/relay/conformance.ts';
import { startPlain, startReal, type RealServer } from './realserver.ts';

const CASES = JSON.parse(
  readFileSync(new URL('../relay/conformance/cases.json', import.meta.url), 'utf8'),
) as ConformanceCases;

let real: RealServer;
beforeAll(async () => {
  real = await startReal();
});
afterAll(async () => real?.stop());

describe('real relay server: conformance', () => {
  it('passes every case', async () => {
    let skew = 0;
    const control = {
      ...real.control,
      advanceTime: async (ms: number) => {
        skew += ms;
        await real.control.advanceTime!(ms);
      },
      reset: async () => {
        skew = 0;
        await real.control.reset();
      },
    };
    const report = await runConformance(real.base, fetch, {
      cases: CASES,
      control,
      now: () => Date.now() + skew,
      timeoutMs: 60_000,
    });
    if (process.env['RELAY_REAL_REPORT']) {
      writeFileSync(process.env['RELAY_REAL_REPORT'], JSON.stringify(report, null, 1));
    }
    const bad = report.results
      .filter((r) => r.status !== 'pass')
      .map((r) => `${r.status} ${r.name}: ${r.reasons.join(' | ')}`);
    expect(bad).toEqual([]);
    expect(report.passed).toBe(CASES.cases.length);
  }, 600_000);
});

describe('real relay server as deployed (node src/server.ts, no test interface)', () => {
  it('passes every case that needs no test interface, skips the others', async () => {
    const plain = await startPlain();
    try {
      const report = await runConformance(plain.base, fetch, { cases: CASES, timeoutMs: 60_000 });
      const bad = report.results
        .filter((r) => r.status === 'fail')
        .map((r) => `${r.name}: ${r.reasons.join(' | ')}`);
      expect(bad).toEqual([]);
      const needing = CASES.cases.filter((c) => (c.needs ?? []).length > 0).length;
      expect(report.skipped).toBe(needing);
      expect(report.passed).toBe(CASES.cases.length - needing);
    } finally {
      await plain.stop();
    }
  }, 600_000);
});
