import { describe, expect, it } from 'vitest';
import { canonical, checkValue } from '../../src/core/canonical.ts';

describe('canonical', () => {
  it('sorts keys, drops undefined, keeps null (both earlier implementations)', () => {
    expect(canonical({ b: 1, a: { d: [3, 1], c: 'x' }, z: undefined })).toBe(
      '{"a":{"c":"x","d":[3,1]},"b":1}',
    );
    expect(canonical({ a: 1, b: 2 })).toBe(canonical({ b: 2, a: 1 }));
    expect(canonical(null)).toBe('null');
    expect(canonical(undefined)).toBe('null');
  });

  it('keeps array order, nulls non-JSON array members, differing values differ', () => {
    expect(canonical([2, 1])).not.toBe(canonical([1, 2]));
    expect(canonical([undefined, () => 1, [[]]])).toBe('[null,null,[[]]]');
    expect(canonical({ a: 1 })).not.toBe(canonical({ a: 2 }));
    expect(canonical({ a: null })).not.toBe(canonical({}));
    expect(canonical({ a: undefined })).toBe(canonical({}));
  });

  it('sorts keys as code units, not numerically', () => {
    expect(canonical({ '': 0, 10: 1, 9: 2, B: 3, a: 4 })).toBe('{"":0,"10":1,"9":2,"B":3,"a":4}');
  });

  it('escapes like JSON.stringify and keeps unicode', () => {
    const value = { z: [1, { b: null, a: [] }], a: 'ü "\\\n😀', n: -0.5, e: 1e21, u: undefined };
    expect(canonical(value)).toBe(
      '{"a":"ü \\"\\\\\\n😀","e":1e+21,"n":-0.5,"z":[1,{"a":[],"b":null}]}',
    );
    expect(canonical('x')).toBe('"x"');
    expect(canonical(3)).toBe('3');
    expect(canonical({ k: {} })).toBe('{"k":{}}');
  });
});

describe('checkValue', () => {
  // Hashes computed with the algorithm of the earlier implementations.
  const vectors: [unknown, string][] = [
    [
      { z: [1, { b: null, a: [] }], a: 'ü "\\\n😀', n: -0.5, e: 1e21, u: undefined },
      '8I2NpkH1YEPoiZsfypSVaqQliFb69W3aNSQhYNsCaVg',
    ],
    [[undefined, () => 1, [[]]], '0OKFqYNInCiuxDSMBX3IdELLGGF8Eg7zQRt_naJFzTE'],
    [{ '': 0, 10: 1, 9: 2, B: 3, a: 4 }, 'Dbxma3huJYQLrriI9qXIb81EDve_sxrs5xE2dXv5zH8'],
    ['x', 'ui30kDosFOhtw7zKWJEbRKwdJRS3Inv26wjPuXj1Whs'],
    [3, 'TgdAhWK-24tgzgXB3s_jrRa3IjCWfeAfZAt-Rym0n84'],
    [null, 'dCNOmK_nSY-12vHzasLXiswzlGT5UHA7jAGYkvmCuQs'],
    [undefined, 'dCNOmK_nSY-12vHzasLXiswzlGT5UHA7jAGYkvmCuQs'],
    [{ k: {} }, 'NTj88XTTHF58Tf_E_5RmcO6wD2sAIKY80yCr6HgtqtQ'],
  ];
  it.each(vectors)('fixed vector %#', (value, expected) => {
    expect(checkValue(value)).toBe(expected);
  });

  it('is stable under key order and sensitive to content', () => {
    expect(checkValue({ a: 1, b: [1, 2] })).toBe(checkValue({ b: [1, 2], a: 1 }));
    expect(checkValue({ a: 1 })).not.toBe(checkValue({ a: 2 }));
    expect(checkValue({ a: 1 })).toHaveLength(43);
  });
});
