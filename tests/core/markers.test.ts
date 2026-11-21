import { describe, expect, it } from 'vitest';
import { FORMAT_VERSION, marker } from '../../src/core/markers.ts';

describe('marker', () => {
  it('builds appId-kind:version with the format version by default', () => {
    expect(FORMAT_VERSION).toBe(2);
    expect(marker('demo', 'device')).toBe('demo-device:2');
    expect(marker('demo', 'device', FORMAT_VERSION)).toBe('demo-device:2');
  });

  it('accepts the boundaries of the appId pattern', () => {
    expect(() => marker('ab', 'x')).not.toThrow();
    expect(() => marker('a' + '1'.repeat(15), 'x')).not.toThrow();
  });

  it('refuses invalid appIds with a clear error', () => {
    for (const bad of [
      '',
      'a',
      'Demo',
      'dEmo',
      '1demo',
      'a'.repeat(17),
      'de-mo',
      'de mo',
      'dem_o',
    ]) {
      expect(() => marker(bad, 'x')).toThrow(/invalid appId/);
    }
  });

  it('regression: a kind or version cannot smuggle in separators (two markers reading the same)', () => {
    // without the check, ('a-b', 'c') and ('a', 'b-c') would both read "a-b-c:2" style texts
    for (const bad of [
      '',
      'Dev',
      'de-vice',
      'de:vice',
      'de|vice',
      'de vice',
      '1dev',
      'x'.repeat(33),
    ]) {
      expect(() => marker('demo', bad)).toThrow(/invalid kind/);
    }
    for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => marker('demo', 'device', bad)).toThrow(/invalid version/);
    }
    expect(marker('demo', 'device', 0)).toBe('demo-device:0');
  });

  it('different appIds give different markers', () => {
    expect(marker('one', 'device')).not.toBe(marker('two', 'device'));
  });
});
