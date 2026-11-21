import { describe, expect, it } from 'vitest';
import {
  DEFAULT_DEVICE_ID,
  LIMITS,
  parseChange,
  parseSyncMessage,
  parseVector,
  resolveLimits,
  type Change,
  type Limits,
  type SyncMessage,
} from '../../src/log/index.ts';
import {
  CHECK,
  SIG,
  garbage,
  int,
  mutate,
  nestedList,
  nestedObject,
  pick,
  randomChange,
  randomMessage,
  randomVector,
  references,
} from './fuzz.ts';
import { prng } from './helpers.ts';

const change = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  device: 'a',
  seq: 1,
  clock: 1,
  collection: 'items',
  id: 'r1',
  kind: 'set',
  fields: { title: 'x' },
  knew: {},
  ...extra,
});
const piece = (extra: Record<string, unknown> = {}) => ({
  t: 'changes',
  changes: [change(extra)],
  last: true,
});
const parsedPiece = (extra: Record<string, unknown> = {}) => parseSyncMessage(piece(extra));
const fieldsOf = (fields: unknown) => change({ fields });
const json = (v: unknown): unknown => JSON.parse(JSON.stringify(v));
const withProto = (key: string, value: unknown): Record<string, unknown> =>
  JSON.parse(`{"${key}":${JSON.stringify(value)}}`) as Record<string, unknown>;

/** A list of strings whose JSON text is exactly `target` characters long. */
function jsonOfLength(target: number, maxText = LIMITS.maxText): string[] {
  const n = Math.ceil((target - 1) / (maxText + 3));
  let rest = target - 3 * n - 1;
  const out: string[] = [];
  for (let i = 0; i < n; i += 1) {
    const take = Math.min(maxText, rest);
    out.push('x'.repeat(take));
    rest -= take;
  }
  expect(JSON.stringify(out).length).toBe(target);
  return out;
}

describe('strict reading: what is not exactly the shape is undefined', () => {
  it('accepts a minimal and a full change, and a changes message', () => {
    expect(parseChange(change())).toEqual(change());
    const full = change({
      knew: { a: 3, b: 0 },
      time: 1_700_000_000_000,
      by: 'someone',
      check: CHECK,
      sig: SIG,
    });
    expect(parseChange(full)).toEqual(full);
    expect(
      parseChange({
        device: 'a',
        seq: 2,
        clock: 5,
        collection: 'items',
        id: 'r1',
        kind: 'delete',
        knew: {},
      }),
    ).toBeDefined();
    expect(parseSyncMessage({ t: 'changes', changes: [], last: true })).toEqual({
      t: 'changes',
      changes: [],
      last: true,
    });
  });

  const bad: [string, unknown][] = [
    ['null', null],
    ['an array', []],
    ['a text', 'stand'],
    ['a number', 1],
    ['stand without vector', { t: 'stand' }],
    ['stand with negative count', { t: 'stand', vector: { a: -1 } }],
    ['stand with fractional count', { t: 'stand', vector: { a: 1.5 } }],
    ['done with a bad fingerprint', { t: 'done', vector: {}, fingerprint: 'xyz' }],
    [
      'done with an upper-case fingerprint',
      { t: 'done', vector: {}, fingerprint: 'ABCDEF01'.repeat(4) },
    ],
    ['done without fingerprint', { t: 'done', vector: {} }],
    ['a change that is only a device', { t: 'changes', changes: [{ device: 'a' }], last: true }],
    ['last is not a boolean', { t: 'changes', changes: [], last: 'yes' }],
    ['last is missing', { t: 'changes', changes: [] }],
    ['changes is not a list', { t: 'changes', changes: {}, last: true }],
    ['an unknown type', { t: 'other' }],
    ['no type', { vector: {} }],
    ['an unknown member of a stand', { t: 'stand', vector: {}, extra: 1 }],
    [
      'an unknown member of done',
      { t: 'done', vector: {}, fingerprint: '01234567'.repeat(4), extra: 1 },
    ],
    ['an unknown member of changes', { t: 'changes', changes: [], last: true, extra: 1 }],
    [
      'a class instance as message',
      new (class M {
        t = 'stand';
        vector = {};
      })(),
    ],
  ];
  for (const [label, raw] of bad) {
    it(`refuses ${label}`, () => {
      expect(parseSyncMessage(raw)).toBeUndefined();
    });
  }

  const badChange: [string, Record<string, unknown>][] = [
    ['set without fields', { fields: undefined }],
    ['set with empty fields', { fields: {} }],
    ['set with fields that is a list', { fields: [] }],
    ['a time that is a text', { time: 'yesterday' }],
    ['a negative time', { time: -1 }],
    ['a fractional time', { time: 1.5 }],
    ['an empty author label', { by: '' }],
    ['an author label with a control character', { by: 'a\u0000b' }],
    ['a label that is a number', { by: 1 }],
    ['an empty id', { id: '' }],
    ['an id with a control character', { id: 'a\nb' }],
    ['a too long id', { id: 'x'.repeat(LIMITS.maxId + 1) }],
    ['a too long collection', { collection: 'x'.repeat(LIMITS.maxId + 1) }],
    ['an empty collection', { collection: '' }],
    ['a huge clock', { clock: 1e300 }],
    ['clock 2^53', { clock: 2 ** 53 }],
    ['seq 2^53', { seq: 2 ** 53 }],
    ['clock zero', { clock: 0 }],
    ['seq zero', { seq: 0 }],
    ['a negative seq', { seq: -1 }],
    ['a fractional seq', { seq: 1.5 }],
    ['a seq that is a text', { seq: '1' }],
    ['NaN as clock', { clock: Number.NaN }],
    ['Infinity as seq', { seq: Infinity }],
    ['a delete with fields', { kind: 'delete' }],
    ['a redacted with fields', { kind: 'redacted' }],
    ['an unknown kind', { kind: 'update' }],
    ['a kind that is a number', { kind: 1 }],
    ['an unknown member', { extra: 1 }],
    ['an unknown member that is a list', { unsigned: [] }],
    ['a signature without check value', { sig: SIG }],
    ['a check value of the wrong length', { check: 'c'.repeat(42) }],
    ['a check value with a bad character', { check: '+'.repeat(43) }],
    ['a signature of the wrong length', { check: CHECK, sig: 's'.repeat(85) }],
    ['a signature that is not a text', { check: CHECK, sig: 1 }],
    ['knew that is a list', { knew: [] }],
    ['knew with a negative number', { knew: { a: -1 } }],
    ['knew with a text number', { knew: { a: '1' } }],
    ['knew with a device that is no device id', { knew: { 'a b': 1 } }],
    ['a device with a space', { device: 'a b' }],
    ['an empty device', { device: '' }],
    ['a device longer than the default pattern', { device: 'a'.repeat(81) }],
    ['a device with a control character', { device: 'a\u0000' }],
    ['a field named like the prototype', { fields: withProto('__proto__', 1) }],
    ['a field named constructor', { fields: { constructor: 1 } }],
    ['a field named prototype', { fields: { prototype: 1 } }],
    ['a field with an empty name', { fields: { '': 1 } }],
    ['a field name with a control character', { fields: { 'a\u0001': 1 } }],
    ['a field name over the limit', { fields: { ['x'.repeat(LIMITS.maxName + 1)]: 1 } }],
    ['an undefined field value', { fields: { a: undefined } }],
    ['NaN as a value', { fields: { a: Number.NaN } }],
    ['Infinity as a value', { fields: { a: Infinity } }],
    ['-Infinity inside a list', { fields: { a: [-Infinity] } }],
    ['a Date as a value', { fields: { a: new Date(0) } }],
    ['a function as a value', { fields: { a: () => 1 } }],
    ['a symbol as a value', { fields: { a: Symbol('s') } }],
    ['a bigint as a value', { fields: { a: 1n } }],
    ['a Map as a value', { fields: { a: new Map() } }],
    [
      'a class instance inside a value',
      {
        fields: {
          a: [
            new (class P {
              x = 1;
            })(),
          ],
        },
      },
    ],
    ['a prototype name inside a value', { fields: { a: withProto('__proto__', { y: 1 }) } }],
    ['a nested constructor key', { fields: { a: { constructor: 1 } } }],
    ['a key with a control character inside a value', { fields: { a: { 'b\u0001': 1 } } }],
    ['an undefined inside a list', { fields: { a: [1, undefined] } }],
    ['a sparse list', { fields: { a: [1, , 3] } }], // eslint-disable-line no-sparse-arrays
  ];
  for (const [label, extra] of badChange) {
    it(`refuses a change with ${label}`, () => {
      expect(parseChange(change(extra))).toBeUndefined();
      expect(parsedPiece(extra)).toBeUndefined();
    });
  }

  it('a signature never without its check value; a check value alone passes (erased start data)', () => {
    const both = parsedPiece({ check: CHECK, sig: SIG });
    expect(both?.t === 'changes' && both.changes[0]?.sig).toBe(SIG);
    expect(parsedPiece({ check: undefined, sig: SIG })).toBeUndefined();
    expect(parsedPiece({ check: 'short', sig: SIG })).toBeUndefined();
    expect(parsedPiece({ check: CHECK, sig: `${SIG}x` })).toBeUndefined();
    const checkOnly = parsedPiece({ check: CHECK, sig: undefined });
    expect(checkOnly?.t === 'changes' && checkOnly.changes[0]?.check).toBe(CHECK);
    const neither = parsedPiece({ check: undefined, sig: undefined });
    expect(neither?.t === 'changes' && neither.changes[0]?.sig).toBeUndefined();
  });

  it('treats an undefined optional member as absent (it is not on the wire)', () => {
    expect(parseChange(change({ time: undefined, by: undefined }))).toEqual(change());
  });

  it('one bad change refuses the whole message', () => {
    expect(
      parseSyncMessage({
        t: 'changes',
        changes: [change(), change({ seq: 0 }), change()],
        last: true,
      }),
    ).toBeUndefined();
  });

  it('a list or an object is a value; nested up to the depth limit', () => {
    const value = {
      tags: ['a', 'b'],
      pos: { x: 1, y: [1, 2, { z: null }] },
      flag: true,
      n: -0.5,
      s: 'Ä ö ü ß – „quote“ 😀',
    };
    expect(parseChange(fieldsOf(value))).toEqual(fieldsOf(value));
  });

  it('a whole record entry travels and arrives the same', () => {
    const entry = { label: '2 of 4', dims: { grade: '7-8' }, note: 'Ä ö ü ß – „quote“' };
    const msg = parseSyncMessage(json(piece({ fields: entry })));
    expect(msg?.t === 'changes' && msg.changes[0]?.fields).toEqual(entry);
  });

  it('vectors: a stand is only counts of devices', () => {
    expect(parseVector({ a: 0, b: 12 })).toEqual({ a: 0, b: 12 });
    expect(parseVector({})).toEqual({});
    for (const bad of [
      null,
      [],
      'a',
      { a: Number.NaN },
      { a: Infinity },
      { a: 2 ** 53 },
      { a: '1' },
    ]) {
      expect(parseVector(bad)).toBeUndefined();
    }
    expect(parseVector(withProto('__proto__', 1))).toBeUndefined();
    expect(parseVector({ constructor: 1 })).toBeUndefined();
    expect(parseVector({ prototype: 1 })).toBeUndefined();
  });

  it('the device id pattern is an option; ids are not hard-wired to a length', () => {
    const hex16 = (s: string) => /^[0-9a-f]{16}$/.test(s);
    const id = '0123456789abcdef';
    expect(parseVector({ a: 1 })).toEqual({ a: 1 });
    expect(parseVector({ a: 1 }, { deviceId: hex16 })).toBeUndefined();
    expect(parseVector({ [id]: 1 }, { deviceId: hex16 })).toEqual({ [id]: 1 });
    expect(parseChange(change({ device: id }), { deviceId: hex16 })).toBeDefined();
    expect(parseChange(change(), { deviceId: hex16 })).toBeUndefined();
    expect(parseChange(change({ knew: { a: 1 } }), { deviceId: () => true })).toBeDefined();
    expect(
      parseChange(change({ device: id, knew: { a: 1 } }), { deviceId: hex16 }),
    ).toBeUndefined();
    // the prototype names stay refused even when the predicate would take them
    expect(parseVector(withProto('__proto__', 1), { deviceId: () => true })).toBeUndefined();
    expect(
      parseChange(change({ device: 'constructor' }), { deviceId: () => true }),
    ).toBeUndefined();
    expect(DEFAULT_DEVICE_ID.test('a.b_c-9')).toBe(true);
  });
});

describe('every limit, at the limit and one over (driven by LIMITS)', () => {
  it('maxFields', () => {
    const make = (n: number) =>
      Object.fromEntries(Array.from({ length: n }, (_, i) => [`f${i}`, 1]));
    expect(parseChange(fieldsOf(make(LIMITS.maxFields)))).toBeDefined();
    expect(parseChange(fieldsOf(make(LIMITS.maxFields + 1)))).toBeUndefined();
  });

  it('maxText (a text inside a value)', () => {
    expect(parseChange(fieldsOf({ a: 'x'.repeat(LIMITS.maxText) }))).toBeDefined();
    expect(parseChange(fieldsOf({ a: 'x'.repeat(LIMITS.maxText + 1) }))).toBeUndefined();
    expect(parseChange(fieldsOf({ a: ['x'.repeat(LIMITS.maxText + 1)] }))).toBeUndefined();
  });

  it('maxValueChars (one value as JSON)', () => {
    expect(parseChange(fieldsOf({ a: jsonOfLength(LIMITS.maxValueChars) }))).toBeDefined();
    expect(parseChange(fieldsOf({ a: jsonOfLength(LIMITS.maxValueChars + 1) }))).toBeUndefined();
    // the limit is per value, not per change
    const two = { a: jsonOfLength(LIMITS.maxValueChars), b: jsonOfLength(LIMITS.maxValueChars) };
    expect(parseChange(fieldsOf(two))).toBeDefined();
  });

  it('maxDepth', () => {
    expect(parseChange(fieldsOf({ a: nestedList(LIMITS.maxDepth) }))).toBeDefined();
    expect(parseChange(fieldsOf({ a: nestedList(LIMITS.maxDepth + 1) }))).toBeUndefined();
    expect(parseChange(fieldsOf({ a: nestedObject(LIMITS.maxDepth) }))).toBeDefined();
    expect(parseChange(fieldsOf({ a: nestedObject(LIMITS.maxDepth + 1) }))).toBeUndefined();
    // depth counts containers; a scalar at the deepest level is fine
    expect(parseChange(fieldsOf({ a: nestedList(LIMITS.maxDepth, 'x') }))).toBeDefined();
  });

  it('maxEntries (list and object)', () => {
    const list = (n: number) => Array.from({ length: n }, () => 1);
    const object = (n: number) => Object.fromEntries(list(n).map((v, i) => [`k${i}`, v]));
    expect(parseChange(fieldsOf({ a: list(LIMITS.maxEntries) }))).toBeDefined();
    expect(parseChange(fieldsOf({ a: list(LIMITS.maxEntries + 1) }))).toBeUndefined();
    expect(parseChange(fieldsOf({ a: object(LIMITS.maxEntries) }))).toBeDefined();
    expect(parseChange(fieldsOf({ a: object(LIMITS.maxEntries + 1) }))).toBeUndefined();
  });

  it('maxDevices (stand, done and knew)', () => {
    const vector = (n: number) =>
      Object.fromEntries(Array.from({ length: n }, (_, i) => [`d${i}`, i]));
    expect(parseVector(vector(LIMITS.maxDevices))).toBeDefined();
    expect(parseVector(vector(LIMITS.maxDevices + 1))).toBeUndefined();
    expect(parseSyncMessage({ t: 'stand', vector: vector(LIMITS.maxDevices) })).toBeDefined();
    expect(parseSyncMessage({ t: 'stand', vector: vector(LIMITS.maxDevices + 1) })).toBeUndefined();
    expect(parseChange(change({ knew: vector(LIMITS.maxDevices) }))).toBeDefined();
    expect(parseChange(change({ knew: vector(LIMITS.maxDevices + 1) }))).toBeUndefined();
  });

  it('maxChanges (one message)', () => {
    const many = (n: number) => ({
      t: 'changes',
      changes: Array.from({ length: n }, (_, i) => change({ seq: i + 1 })),
      last: true,
    });
    expect(parseSyncMessage(many(LIMITS.maxChanges))).toBeDefined();
    expect(parseSyncMessage(many(LIMITS.maxChanges + 1))).toBeUndefined();
  });

  it('maxName (field names, author label, keys inside a value)', () => {
    const name = (n: number) => 'x'.repeat(n);
    expect(parseChange(fieldsOf({ [name(LIMITS.maxName)]: 1 }))).toBeDefined();
    expect(parseChange(fieldsOf({ [name(LIMITS.maxName + 1)]: 1 }))).toBeUndefined();
    expect(parseChange(change({ by: name(LIMITS.maxName) }))).toBeDefined();
    expect(parseChange(change({ by: name(LIMITS.maxName + 1) }))).toBeUndefined();
    expect(parseChange(fieldsOf({ a: { [name(LIMITS.maxName)]: 1 } }))).toBeDefined();
    expect(parseChange(fieldsOf({ a: { [name(LIMITS.maxName + 1)]: 1 } }))).toBeUndefined();
  });

  it('maxId (collection and record id)', () => {
    const id = (n: number) => 'x'.repeat(n);
    expect(parseChange(change({ id: id(LIMITS.maxId) }))).toBeDefined();
    expect(parseChange(change({ id: id(LIMITS.maxId + 1) }))).toBeUndefined();
    expect(parseChange(change({ collection: id(LIMITS.maxId) }))).toBeDefined();
    expect(parseChange(change({ collection: id(LIMITS.maxId + 1) }))).toBeUndefined();
  });

  it('pieceBytes and maxSessionChanges are documented defaults', () => {
    expect(LIMITS.pieceBytes).toBe(12000);
    expect(LIMITS.maxSessionChanges).toBeGreaterThan(LIMITS.maxChanges);
  });

  it('LIMITS is frozen and an override never leaks into the defaults', () => {
    expect(Object.isFrozen(LIMITS)).toBe(true);
    const before = { ...LIMITS };
    expect(parseChange(fieldsOf({ a: 1, b: 2 }), { limits: { maxFields: 1 } })).toBeUndefined();
    expect(parseChange(fieldsOf({ a: 1, b: 2 }))).toBeDefined();
    expect({ ...LIMITS }).toEqual(before);
  });
});

describe('limits override (partial, per call)', () => {
  const tight: Partial<Limits> = {
    maxFields: 2,
    maxText: 5,
    maxValueChars: 20,
    maxDepth: 2,
    maxEntries: 3,
    maxDevices: 2,
    maxChanges: 2,
    maxName: 5,
    maxId: 6,
  };

  it('every limit can be tightened', () => {
    expect(parseChange(fieldsOf({ a: 1, b: 2, c: 3 }), { limits: tight })).toBeUndefined();
    expect(parseChange(fieldsOf({ a: 1, b: 2 }), { limits: tight })).toBeDefined();
    expect(parseChange(fieldsOf({ a: 'abcdef' }), { limits: tight })).toBeUndefined();
    expect(parseChange(fieldsOf({ a: 'abcde' }), { limits: tight })).toBeDefined();
    expect(parseChange(fieldsOf({ a: [1, 2, 3, 4] }), { limits: tight })).toBeUndefined();
    expect(parseChange(fieldsOf({ a: [[[1]]] }), { limits: tight })).toBeUndefined();
    expect(parseChange(fieldsOf({ a: [[1]] }), { limits: tight })).toBeDefined();
    expect(parseChange(fieldsOf({ abcdef: 1 }), { limits: tight })).toBeUndefined();
    expect(parseChange(change({ id: 'abcdefg' }), { limits: tight })).toBeUndefined();
    expect(parseVector({ a: 1, b: 1, c: 1 }, { limits: tight })).toBeUndefined();
    expect(
      parseChange(fieldsOf({ a: ['aaaaa', 'aaaaa', 'aaaaa'] }), { limits: tight }),
    ).toBeUndefined();
    const three = {
      t: 'changes',
      changes: [change(), change({ seq: 2 }), change({ seq: 3 })],
      last: true,
    };
    expect(parseSyncMessage(three, { limits: tight })).toBeUndefined();
    expect(parseSyncMessage(three)).toBeDefined();
  });

  it('every limit can be raised above the default', () => {
    const wide = {
      limits: { maxFields: 41, maxText: 2001, maxDepth: 7, maxEntries: 201, maxName: 121 },
    };
    expect(
      parseChange(
        fieldsOf(Object.fromEntries(Array.from({ length: 41 }, (_, i) => [`f${i}`, 1]))),
        wide,
      ),
    ).toBeDefined();
    expect(parseChange(fieldsOf({ a: 'x'.repeat(2001) }), wide)).toBeDefined();
    expect(parseChange(fieldsOf({ a: nestedList(7) }), wide)).toBeDefined();
    expect(parseChange(fieldsOf({ a: Array.from({ length: 201 }, () => 1) }), wide)).toBeDefined();
    expect(parseChange(fieldsOf({ ['x'.repeat(121)]: 1 }), wide)).toBeDefined();
  });

  it('members that are not numbers are ignored; partial override keeps the rest', () => {
    expect(resolveLimits()).toBe(LIMITS);
    const merged = resolveLimits({ maxFields: 3, maxText: 'no' as unknown as number });
    expect(merged.maxFields).toBe(3);
    expect(merged.maxText).toBe(LIMITS.maxText);
    expect(merged.pieceBytes).toBe(LIMITS.pieceBytes);
  });
});

describe('never throws, never mutates, never aliases', () => {
  const hostile = (): Record<string, unknown> => {
    const o: Record<string, unknown> = { t: 'stand' };
    Object.defineProperty(o, 'vector', {
      enumerable: true,
      get() {
        throw new Error('boom');
      },
    });
    return o;
  };

  it('survives throwing getters, revoked proxies and a throwing predicate', () => {
    expect(parseSyncMessage(hostile())).toBeUndefined();
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    for (const parse of [parseChange, parseVector, parseSyncMessage]) {
      expect(parse(proxy)).toBeUndefined();
    }
    const throwing = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('boom');
        },
      },
    );
    expect(parseChange(throwing)).toBeUndefined();
    expect(
      parseVector(
        { a: 1 },
        {
          deviceId: () => {
            throw new Error('boom');
          },
        },
      ),
    ).toBeUndefined();
  });

  it('survives a cyclic value', () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    expect(parseChange(fieldsOf({ a: cycle }))).toBeUndefined();
    const list: unknown[] = [];
    list.push(list);
    expect(parseChange(fieldsOf({ a: list }))).toBeUndefined();
  });

  it('a frozen input is read (nothing is written to it) and the result is a fresh copy', () => {
    const deepFreeze = <T>(v: T): T => {
      if (typeof v === 'object' && v !== null) {
        Object.values(v).forEach(deepFreeze);
        Object.freeze(v);
      }
      return v;
    };
    const raw = deepFreeze(piece({ fields: { a: { b: [1, { c: 2 }] }, d: [1] }, knew: { a: 1 } }));
    const snapshot = JSON.stringify(raw);
    const parsed = parseSyncMessage(raw) as Extract<SyncMessage, { t: 'changes' }>;
    expect(parsed).toBeDefined();
    const mine = references(parsed);
    for (const ref of references(raw)) expect(mine.has(ref)).toBe(false);
    // writing into the result does not reach the input
    (parsed.changes[0]?.fields?.a as { b: unknown[] }).b.push(9);
    expect(JSON.stringify(raw)).toBe(snapshot);
  });

  it('keys of the result are own plain properties (no prototype tricks)', () => {
    const parsed = parseChange(fieldsOf({ a: 1 })) as Change;
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(parsed.fields)).toBe(Object.prototype);
  });
});

describe('depth bombs and huge inputs do not blow the stack', () => {
  const BOMB = 10_000;

  it('10000 nested lists / objects as a field value', () => {
    expect(parseChange(fieldsOf({ a: nestedList(BOMB) }))).toBeUndefined();
    expect(parseChange(fieldsOf({ a: nestedObject(BOMB) }))).toBeUndefined();
  });

  it('a nested bomb in every other place', () => {
    for (const where of ['vector', 'fields', 'knew', 'x', 'changes']) {
      expect(
        parseSyncMessage({ t: 'stand', vector: nestedObject(BOMB), [where]: nestedList(BOMB) }),
      ).toBeUndefined();
    }
    expect(parseChange(change({ knew: nestedObject(BOMB) }))).toBeUndefined();
    expect(parseChange(change({ unknown: nestedList(BOMB) }))).toBeUndefined();
    expect(
      parseSyncMessage({ t: 'changes', changes: nestedList(BOMB), last: true }),
    ).toBeUndefined();
    expect(parseVector(nestedObject(BOMB))).toBeUndefined();
  });

  it('a very wide value stops at the limits, not after reading all of it', () => {
    const wide = Array.from({ length: 1_000_000 }, () => 1);
    expect(parseChange(fieldsOf({ a: wide }))).toBeUndefined();
    const manyKeys = Object.fromEntries(Array.from({ length: 100_000 }, (_, i) => [`k${i}`, 1]));
    expect(parseChange(fieldsOf(manyKeys))).toBeUndefined();
    // the node budget: a 200 x 200 x 200 tree stays within the limits per level but is far too big
    const tree = Array.from({ length: 200 }, () => Array.from({ length: 200 }, () => [1, 2, 3]));
    const start = Date.now();
    expect(parseChange(fieldsOf({ a: tree }))).toBeUndefined();
    expect(Date.now() - start).toBeLessThan(500);
  });
});

describe('fuzzing (seeded)', () => {
  const RUNS = 6000;

  /** Checks a returned change against the shape, written independently of the parser. */
  function validChange(c: Change): void {
    const allowed = [
      'device',
      'seq',
      'clock',
      'collection',
      'id',
      'kind',
      'fields',
      'knew',
      'time',
      'by',
      'check',
      'sig',
    ];
    for (const key of Object.keys(c)) expect(allowed).toContain(key);
    expect(DEFAULT_DEVICE_ID.test(c.device)).toBe(true);
    expect(Number.isSafeInteger(c.seq) && c.seq >= 1).toBe(true);
    expect(Number.isSafeInteger(c.clock) && c.clock >= 1).toBe(true);
    expect(['set', 'delete', 'redacted']).toContain(c.kind);
    expect(c.collection.length).toBeLessThanOrEqual(LIMITS.maxId);
    expect(c.id.length).toBeLessThanOrEqual(LIMITS.maxId);
    if (c.kind === 'set') {
      const n = Object.keys(c.fields ?? {}).length;
      expect(n >= 1 && n <= LIMITS.maxFields).toBe(true);
      for (const v of Object.values(c.fields ?? {})) {
        expect(JSON.stringify(v).length).toBeLessThanOrEqual(LIMITS.maxValueChars);
      }
    } else expect(c.fields).toBeUndefined();
    if (c.sig !== undefined) expect(c.check).toBeDefined();
    if (c.knew) expect(Object.keys(c.knew).length).toBeLessThanOrEqual(LIMITS.maxDevices);
    for (const key of ['__proto__', 'constructor', 'prototype']) {
      expect(Object.keys(c.fields ?? {})).not.toContain(key);
    }
  }

  function noAlias(result: unknown, input: unknown): void {
    const mine = references(result);
    for (const ref of references(input))
      if (mine.has(ref)) throw new Error('result aliases the input');
  }

  function fuzz(
    seed: number,
    parse: (raw: unknown) => unknown,
    valid: (rng: () => number) => unknown,
    check: (result: unknown) => void,
  ) {
    const rng = prng(seed);
    let accepted = 0;
    let refused = 0;
    for (let i = 0; i < RUNS; i += 1) {
      const kind = int(rng, 3);
      const input =
        kind === 0 ? garbage(rng) : mutate(rng, valid(rng)); /* 2/3 mutations of valid input */
      let result: unknown;
      try {
        result = parse(input);
      } catch (error) {
        throw new Error(`parser threw on input #${i}: ${String(error)}`);
      }
      if (result === undefined) {
        refused += 1;
        continue;
      }
      accepted += 1;
      check(result);
      noAlias(result, input);
      // a result is a fixed point of the parser (it only ever returns what it would accept again)
      expect(parse(result)).toEqual(result);
    }
    return { accepted, refused, runs: RUNS };
  }

  it('parseChange: 6000 inputs never throw; results are valid and unaliased', () => {
    const out = fuzz(
      101,
      (raw) => parseChange(raw),
      randomChange,
      (r) => validChange(r as Change),
    );
    expect(out.runs).toBeGreaterThanOrEqual(5000);
    expect(out.accepted).toBeGreaterThan(100);
    expect(out.refused).toBeGreaterThan(100);
  });

  it('parseVector: 6000 inputs never throw; results are valid and unaliased', () => {
    const out = fuzz(
      202,
      (raw) => parseVector(raw),
      randomVector,
      (r) => {
        const entries = Object.entries(r as Record<string, number>);
        expect(entries.length).toBeLessThanOrEqual(LIMITS.maxDevices);
        for (const [device, seq] of entries) {
          expect(DEFAULT_DEVICE_ID.test(device)).toBe(true);
          expect(Number.isSafeInteger(seq) && seq >= 0).toBe(true);
        }
      },
    );
    expect(out.runs).toBeGreaterThanOrEqual(5000);
    expect(out.accepted).toBeGreaterThan(100);
    expect(out.refused).toBeGreaterThan(100);
  });

  it('parseSyncMessage: 6000 inputs never throw; results are valid and unaliased', () => {
    const out = fuzz(
      303,
      (raw) => parseSyncMessage(raw),
      randomMessage,
      (r) => {
        const m = r as SyncMessage;
        expect(['stand', 'changes', 'done']).toContain(m.t);
        if (m.t === 'changes') {
          expect(m.changes.length).toBeLessThanOrEqual(LIMITS.maxChanges);
          m.changes.forEach(validChange);
          expect(typeof m.last).toBe('boolean');
        }
        if (m.t === 'done') expect(m.fingerprint).toMatch(/^[0-9a-f]{32}$/);
        expect(Object.keys(m).length).toBe(m.t === 'stand' ? 2 : 3);
      },
    );
    expect(out.runs).toBeGreaterThanOrEqual(5000);
    expect(out.accepted).toBeGreaterThan(100);
    expect(out.refused).toBeGreaterThan(100);
  });

  it('an unknown member added anywhere in a message or a change is always refused', () => {
    const rng = prng(404);
    for (let i = 0; i < 1000; i += 1) {
      const message = json(randomMessage(rng)) as Record<string, unknown>;
      expect(parseSyncMessage(message)).toBeDefined();
      expect(
        parseSyncMessage({ ...message, [pick(rng, ['extra', 'v', 'sig', 'x'])]: 1 }),
      ).toBeUndefined();
      const c = json(randomChange(rng)) as Record<string, unknown>;
      expect(parseChange(c)).toBeDefined();
      expect(
        parseChange({ ...c, [pick(rng, ['extra', 'v', 'set', 'x'])]: garbage(rng) ?? 1 }),
      ).toBeUndefined();
    }
  });

  it('a prototype key anywhere in fields, knew or a vector is always refused', () => {
    const rng = prng(505);
    for (let i = 0; i < 500; i += 1) {
      const key = pick(rng, ['__proto__', 'constructor', 'prototype']);
      const c = json({ ...randomChange(rng), kind: 'set', fields: { a: { b: 1 } } }) as Record<
        string,
        any
      >;
      const poisoned = structuredClone(c);
      Object.defineProperty(poisoned.fields, key, {
        value: 1,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      expect(parseChange(poisoned)).toBeUndefined();
      const deep = structuredClone(c);
      Object.defineProperty(deep.fields.a, key, {
        value: 1,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      expect(parseChange(deep)).toBeUndefined();
      const knew = structuredClone(c);
      knew.knew = {};
      Object.defineProperty(knew.knew, key, {
        value: 1,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      expect(parseChange(knew)).toBeUndefined();
    }
  });
});

describe('round trip: serialise, parse, equal', () => {
  it('random valid changes, vectors and messages survive JSON unchanged', () => {
    const rng = prng(606);
    for (let i = 0; i < 2000; i += 1) {
      const c = randomChange(rng);
      expect(parseChange(json(c))).toEqual(c);
      const v = randomVector(rng);
      expect(parseVector(json(v))).toEqual(v);
      const m = randomMessage(rng);
      expect(parseSyncMessage(json(m))).toEqual(m);
    }
  });

  it('serialise → parse → serialise is stable', () => {
    const rng = prng(707);
    for (let i = 0; i < 500; i += 1) {
      const text = JSON.stringify(randomMessage(rng));
      const parsed = parseSyncMessage(JSON.parse(text));
      expect(JSON.stringify(parsed)).toBe(text);
    }
  });
});

describe('regression: the size of a whole message is bounded', () => {
  const change = (i: number, size: number): unknown => ({
    device: 'a',
    seq: i + 1,
    clock: i + 1,
    collection: 'items',
    id: `r${i}`,
    kind: 'set',
    fields: Object.fromEntries(Array.from({ length: 40 }, (_, j) => [`f${j}`, 'y'.repeat(size)])),
    knew: {},
  });
  const message = (count: number, size: number): unknown => ({
    t: 'changes',
    last: true,
    changes: Array.from({ length: count }, (_, i) => change(i, size)),
  });

  it('500 changes that are each within every other limit but together ~8 MB are refused', () => {
    // each change is fine on its own; without a total limit this was accepted
    expect(parseChange(change(0, 380))).toBeDefined();
    expect(parseSyncMessage(message(500, 380))).toBeUndefined();
  });

  it('a message just under the limit is accepted, one just over is refused (limit from Limits)', () => {
    const limits = { maxMessageChars: 20_000 };
    const small = message(1, 400); // ~16.7 k characters
    expect(parseSyncMessage(small, { limits })).toBeDefined();
    expect(parseSyncMessage(message(2, 400), { limits })).toBeUndefined();
  });

  it('the default admits any single change the other limits allow', () => {
    const one = message(1, 380);
    expect(JSON.stringify(one).length).toBeLessThan(LIMITS.maxMessageChars);
    expect(parseSyncMessage(one)).toBeDefined();
  });
});
