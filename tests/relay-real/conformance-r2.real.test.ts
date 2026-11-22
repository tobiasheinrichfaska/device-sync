// Opt-in (`npm run test:relay-real`): the conformance cases of revision 2 (admission) against the REAL
// relay server over real HTTP, with the test interface of the harness (clock, limits, reset).
import { readFileSync, writeFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runConformance, type ConformanceCases } from '../../src/relay/conformance.ts';
import { realHeaderNames } from './real-source.ts';
import { realPath, startReal, type RealServer } from './realserver.ts';

const FILE = JSON.parse(
  readFileSync(new URL('../relay/conformance/cases-r2.json', import.meta.url), 'utf8'),
) as ConformanceCases;
// The real server spells the two headers its own way; everything else is the fixture's.
const CASES: ConformanceCases = {
  ...FILE,
  fixture: { ...FILE.fixture, headers: realHeaderNames(realPath() as string) },
};

let real: RealServer;
beforeAll(async () => {
  real = await startReal('r2');
});
afterAll(async () => real?.stop());

describe('real relay server: revision 2 conformance', () => {
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
    if (process.env['RELAY_REAL_REPORT_R2']) {
      writeFileSync(process.env['RELAY_REAL_REPORT_R2'], JSON.stringify(report, null, 1));
    }
    const bad = report.results
      .filter((r) => r.status !== 'pass')
      .map((r) => `${r.status} ${r.name}: ${r.reasons.join(' | ')}`);
    expect(bad).toEqual([]);
    expect(report.passed).toBe(CASES.cases.length);
  }, 600_000);
});
