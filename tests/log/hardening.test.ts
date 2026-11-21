// Regression tests for the findings of the adversarial review of the log layer: unsafe names,
// unchecked local writes, the clock-jump rule, and an invented `knew`. Each case is a proof of
// concept that worked against the earlier code.
import { describe, expect, it } from 'vitest';
import { canonical } from '../../src/core/index.ts';
import {
  LIMITS,
  MAX_CLOCK_JUMP,
  emptyReplica,
  findRecord,
  fingerprint,
  merge,
  missingFor,
  parseChange,
  remove,
  restore,
  softDelete,
  undo,
  valuesOf,
  visibleRecords,
  write,
  type Change,
  type Replica,
  type VersionVector,
} from '../../src/log/index.ts';
import { COL, ok, prng, sync, written } from './helpers.ts';

function change(
  device: string,
  seq: number,
  clock: number,
  fields: Record<string, unknown>,
  extra: Partial<Change> = {},
): Change {
  return {
    device,
    seq,
    clock,
    collection: COL,
    id: 'r1',
    kind: 'set',
    fields,
    knew: {},
    ...extra,
  };
}

const UNSAFE = ['__proto__', 'constructor', 'prototype'];

describe('H3: names that reach the prototype', () => {
  it.each(UNSAFE)(
    'the parser refuses %s as collection, id, field name, value key and device',
    (bad) => {
      const base = change('a', 1, 1, { f: 1 });
      expect(parseChange(base)).toBeDefined();
      expect(parseChange({ ...base, collection: bad })).toBeUndefined();
      expect(parseChange({ ...base, id: bad })).toBeUndefined();
      expect(
        parseChange(
          JSON.parse(
            `{"device":"a","seq":1,"clock":1,"collection":"c","id":"i","kind":"set","knew":{},"fields":{"${bad}":1}}`,
          ),
        ),
      ).toBeUndefined();
      expect(parseChange(change('a', 1, 1, { f: JSON.parse(`{"${bad}":1}`) }))).toBeUndefined();
      expect(parseChange({ ...base, device: bad })).toBeUndefined();
      expect(
        parseChange(
          JSON.parse(
            `{"device":"a","seq":1,"clock":1,"collection":"c","id":"i","kind":"set","fields":{"f":1},"knew":{"${bad}":1}}`,
          ),
        ),
      ).toBeUndefined();
    },
  );

  it.each(UNSAFE)('write refuses %s as collection, id and field name', (bad) => {
    const r = emptyReplica('a');
    expect(write(r, bad, 'x', { f: 1 })).toEqual({ ok: false, reason: 'invalid-name' });
    expect(write(r, COL, bad, { f: 1 })).toEqual({ ok: false, reason: 'invalid-name' });
    expect(write(r, COL, 'x', JSON.parse(`{"${bad}":1}`))).toEqual({
      ok: false,
      reason: 'invalid-name',
    });
    expect(write(r, COL, 'x', { f: JSON.parse(`{"${bad}":1}`) })).toEqual({
      ok: false,
      reason: 'invalid-name',
    });
  });

  it('a change that reaches merge with the name __proto__ cannot corrupt the replica', () => {
    // merge is not the gate (the parser is), but whatever reaches it stays an ordinary entry
    const evil = merge(emptyReplica('b'), [
      change('a', 1, 1, { f: 1 }, { collection: '__proto__', id: 'kids' }),
      change('a', 2, 2, { f: 2 }, { id: '__proto__' }),
    ]).replica;
    expect(Object.getPrototypeOf(evil.collections)).toBe(null);
    expect(Object.keys(evil.collections).sort()).toEqual(['__proto__', COL]);
    expect(findRecord(evil, '__proto__', 'kids')?.id).toBe('kids');
    expect(visibleRecords(evil, '__proto__')).toHaveLength(1);
    expect(findRecord(evil, COL, '__proto__')?.id).toBe('__proto__');
    expect(findRecord(evil, 'fields', 'kids')).toBeUndefined();
    // log and data agree after another merge
    const again = merge(evil, [change('a', 3, 3, { f: 3 })]).replica;
    expect(Object.keys(again.collections).sort()).toEqual(['__proto__', COL]);
    expect(fingerprint(again)).toMatch(/^[0-9a-f]{32}$/);
  });

  it('ordinary names that are inherited object members work: toString, valueOf, hasOwnProperty', () => {
    let r = emptyReplica('toString');
    r = ok(write(r, 'toString', 'valueOf', { toString: 1, valueOf: 2, hasOwnProperty: 3 }));
    r = ok(write(r, 'hasOwnProperty', 'isPrototypeOf', { x: 1 }));
    expect(valuesOf(findRecord(r, 'toString', 'valueOf')!)).toEqual({
      toString: 1,
      valueOf: 2,
      hasOwnProperty: 3,
    });
    expect(r.vector).toHaveProperty('toString', 2);
    expect(findRecord(r, 'toString', 'nothere')).toBeUndefined();
    expect(findRecord(r, 'constructor', 'x')).toBeUndefined();
    expect(visibleRecords(r, 'toString')).toHaveLength(1);
    expect(visibleRecords(r, 'valueOf')).toEqual([]);
    // a peer whose device id is an inherited member is not held forever
    let peer = emptyReplica('peer');
    peer = merge(peer, r.log).replica;
    expect(peer.vector).toHaveProperty('toString', 2);
    expect(
      merge(peer, [change('toString', 3, 9, { z: 1 }, { knew: { toString: 2 } })]).held,
    ).toEqual([]);
    expect(fingerprint(peer)).toBe(fingerprint(r));
  });

  it('a device named like an inherited member is not seen as already held', () => {
    const merged = merge(emptyReplica('x'), [change('toString', 1, 1, { f: 1 })]);
    expect(merged.applied).toBe(1);
    expect(merged.held).toEqual([]);
  });

  it.each([
    ['bidi override', 'a‮b'],
    ['zero width space', 'a​b'],
    ['byte order mark', '﻿a'],
    ['NUL', 'a\u0000b'],
    ['newline', 'a\nb'],
    ['not NFC (e + combining accent)', 'é'],
  ])('names with %s are refused by the parser and by write', (_label, bad) => {
    const base = change('a', 1, 1, { f: 1 });
    expect(parseChange({ ...base, collection: bad })).toBeUndefined();
    expect(parseChange({ ...base, id: bad })).toBeUndefined();
    expect(parseChange({ ...base, by: bad })).toBeUndefined();
    expect(parseChange(change('a', 1, 1, { [bad]: 1 }))).toBeUndefined();
    expect(parseChange(change('a', 1, 1, { f: { [bad]: 1 } }))).toBeUndefined();
    const r = emptyReplica('a');
    expect(write(r, bad, 'x', { f: 1 })).toEqual({ ok: false, reason: 'invalid-name' });
    expect(write(r, COL, bad, { f: 1 })).toEqual({ ok: false, reason: 'invalid-name' });
    expect(write(r, COL, 'x', { [bad]: 1 })).toEqual({ ok: false, reason: 'invalid-name' });
    expect(write(r, COL, 'x', { f: { [bad]: 1 } })).toEqual({ ok: false, reason: 'invalid-name' });
    expect(write(r, COL, 'x', { f: 1 }, { by: bad })).toEqual({
      ok: false,
      reason: 'invalid-origin',
    });
  });

  it('the NFC form of an accented name is accepted', () => {
    expect(parseChange({ ...change('a', 1, 1, { f: 1 }), id: 'é' })).toBeDefined();
    expect(write(emptyReplica('a'), COL, 'é', { f: 1 }).ok).toBe(true);
  });
});

describe('H4: local writing obeys the rules of the strict parser', () => {
  const r0 = emptyReplica('a');
  class Thing {
    x = 1;
  }
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  const invalid: [string, unknown][] = [
    ['Date', new Date(0)],
    ['Map', new Map()],
    ['Set', new Set()],
    ['class instance', new Thing()],
    ['function', () => 1],
    ['symbol', Symbol('s')],
    ['bigint', 1n],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['undefined', undefined],
    ['undefined in an array', [1, undefined]],
    ['undefined in an object', { a: undefined }],
    ['sparse array', [1, , 3]], // eslint-disable-line no-sparse-arrays
    ['cycle', cycle],
    [
      'object with a throwing getter',
      Object.defineProperty({}, 'g', {
        enumerable: true,
        get() {
          throw new Error('x');
        },
      }),
    ],
  ];
  it.each(invalid)('refuses %s as a value', (_label, value) => {
    // a cycle runs into the depth limit, everything else is not JSON
    const reason = _label === 'cycle' ? 'too-large' : 'invalid-value';
    expect(write(r0, COL, 'x', { f: value })).toEqual({ ok: false, reason });
    expect(write(r0, COL, 'x', { f: [value] })).toEqual({ ok: false, reason });
  });

  it('refuses too long text, too deep, too many entries, too long JSON with a precise reason', () => {
    expect(write(r0, COL, 'x', { note: 'x'.repeat(LIMITS.maxText + 1) })).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect(write(r0, COL, 'x', { note: 'x'.repeat(LIMITS.maxText) }).ok).toBe(true);
    let deep: unknown = 1;
    for (let i = 0; i < LIMITS.maxDepth + 1; i += 1) deep = [deep];
    expect(write(r0, COL, 'x', { f: deep })).toEqual({ ok: false, reason: 'too-large' });
    expect(write(r0, COL, 'x', { f: new Array(LIMITS.maxEntries + 1).fill(1) })).toEqual({
      ok: false,
      reason: 'too-large',
    });
    const wide = Object.fromEntries(Array.from({ length: 41 }, (_, i) => [`f${i}`, 1]));
    expect(write(r0, COL, 'x', wide)).toEqual({ ok: false, reason: 'too-many-fields' });
    expect(write(r0, COL, 'x', Object.fromEntries(Object.entries(wide).slice(0, 40))).ok).toBe(
      true,
    );
    expect(write(r0, 'c'.repeat(LIMITS.maxId + 1), 'x', { f: 1 }).ok).toBe(false);
    expect(write(r0, COL, 'x', { ['n'.repeat(LIMITS.maxName + 1)]: 1 })).toEqual({
      ok: false,
      reason: 'invalid-name',
    });
    expect(write(r0, COL, 'x', {})).toEqual({ ok: false, reason: 'no-fields' });
  });

  it('a limits override applies to local writing as to the parser', () => {
    expect(write(r0, COL, 'x', { n: 'abc' }, {}, { limits: { maxText: 2 } })).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect(write(r0, COL, 'x', { n: 'abc' }, {}, { limits: { maxText: 3 } }).ok).toBe(true);
  });

  it('refuses a bad origin and a bad own device id', () => {
    expect(write(r0, COL, 'x', { f: 1 }, { time: -1 })).toEqual({
      ok: false,
      reason: 'invalid-origin',
    });
    expect(write(r0, COL, 'x', { f: 1 }, { time: 1.5 })).toEqual({
      ok: false,
      reason: 'invalid-origin',
    });
    expect(write(emptyReplica('bad id'), COL, 'x', { f: 1 })).toEqual({
      ok: false,
      reason: 'invalid-device',
    });
    expect(write(emptyReplica('__proto__'), COL, 'x', { f: 1 })).toEqual({
      ok: false,
      reason: 'invalid-device',
    });
  });

  it('the 2001-character note: a receiver would refuse the exchange, so the write is refused', () => {
    // earlier code accepted it; every receiver then answered `unreadable` and, the numbering being
    // gapless, nothing later from this device ever arrived
    const out = write(r0, COL, 'x', { note: 'n'.repeat(2001) });
    expect(out.ok).toBe(false);
  });

  it('softDelete, restore, undo and remove validate the names and origin too', () => {
    const r = written(r0, 'x', { f: 1 });
    expect(softDelete(r, COL, 'x', { by: 'a‮b' })).toEqual({
      ok: false,
      reason: 'invalid-origin',
    });
    const hidden = ok(softDelete(r, COL, 'x'));
    expect(restore(hidden, COL, 'x', { time: -5 })).toEqual({
      ok: false,
      reason: 'invalid-origin',
    });
    const target = { device: 'a', seq: 1 };
    expect(undo(r, COL, 'x', target, { by: '​' })).toEqual({
      ok: false,
      reason: 'invalid-origin',
    });
    expect(remove(r, COL, 'x', { by: '​' })).toEqual({ ok: false, reason: 'invalid-origin' });
    expect(remove(r, COL, 'x')).toMatchObject({ ok: true });
  });

  it('every accepted write is read back by the strict parser and survives JSON unchanged', () => {
    const values: unknown[] = [
      null,
      true,
      0,
      -0.5,
      1e21,
      'ü "\\\n😀',
      [],
      {},
      [1, 'a', null, [2, { k: [] }]],
      { toString: 1, valueOf: [1], nested: { a: { b: null } } },
    ];
    let r = emptyReplica('a');
    values.forEach((v, i) => {
      r = ok(write(r, COL, `r${i}`, { f: v, g: [v] }, { time: i, by: 'u' }));
    });
    for (const c of r.log) {
      const wire = JSON.parse(JSON.stringify(c)) as unknown;
      const parsed = parseChange(wire);
      expect(parsed, `${c.seq}`).toBeDefined();
      expect(canonical(parsed?.fields)).toBe(canonical(c.fields));
    }
  });

  it('the stored copy does not share structure with the caller', () => {
    const value = { a: [1] };
    const r = ok(write(emptyReplica('a'), COL, 'x', { f: value }));
    value.a.push(2);
    expect(findRecord(r, COL, 'x')?.fields.f?.value).toEqual({ a: [1] });
  });
});

describe('M1: one merge call takes every change that can become applicable', () => {
  it('50 clock jumps interleaved with honest writes are all taken by ONE merge', () => {
    // M's change k needs the clock H's change k-1 raised; H's change k needs M's change k first.
    // One pass in device order takes one pair per pass.
    const rounds = 50;
    const changes: Change[] = [];
    for (let k = 1; k <= rounds; k += 1) {
      changes.push(change('m', k, (2 * k - 1) * MAX_CLOCK_JUMP, { f: k }, { id: 'jump' }));
      changes.push(change('n', k, 2 * k * MAX_CLOCK_JUMP, { f: -k }, { id: 'honest' }));
    }
    const fresh = merge(emptyReplica('x'), changes);
    expect(fresh.held).toEqual([]);
    expect(fresh.applied).toBe(2 * rounds);
    expect(fresh.replica.vector).toMatchObject({ m: rounds, n: rounds });
  });

  it('a jump that no honest write bridges stays held for good', () => {
    const out = merge(emptyReplica('x'), [change('m', 1, MAX_CLOCK_JUMP + 1, { f: 1 })]);
    expect(out.applied).toBe(0);
    expect(out.held).toHaveLength(1);
  });
});

describe('M2: `knew` cannot be left out or invented', () => {
  const noKnew = (c: Change): Change => {
    const { knew: _knew, ...rest } = c;
    return rest;
  };

  it('the parser refuses a set or delete change without knew; a redacted one needs none', () => {
    expect(parseChange(noKnew(change('a', 1, 1, { f: 1 })))).toBeUndefined();
    const del: Change = { device: 'a', seq: 1, clock: 1, collection: COL, id: 'r', kind: 'delete' };
    expect(parseChange(del)).toBeUndefined();
    expect(parseChange({ ...del, knew: {} })).toBeDefined();
    expect(parseChange({ ...del, kind: 'redacted' })).toBeDefined();
  });

  it('write always sets knew', () => {
    const r = written(emptyReplica('a'), 'x', { f: 1 });
    expect(r.log[0]?.knew).toEqual({});
    expect(remove(r, COL, 'x')).toMatchObject({ ok: true });
  });

  it('a change without knew is not applied by merge (held)', () => {
    const out = merge(emptyReplica('x'), [noKnew(change('a', 1, 1, { f: 1 }))]);
    expect(out.applied).toBe(0);
    expect(out.held).toHaveLength(1);
  });

  it('causal hold: a change waits until the replica holds what it says its author knew', () => {
    const b = change('b', 1, 5, { f: 'b' }, { knew: { a: 2 } });
    const a1 = change('a', 1, 1, { f: 'a1' });
    const a2 = change('a', 2, 2, { f: 'a2' }, { knew: { a: 1 } });
    const early = merge(emptyReplica('x'), [a1, b]);
    expect(early.replica.vector).toEqual({ a: 1 });
    expect(early.held.map((c) => c.device)).toEqual(['b']);
    // delivered later, in any order within one call
    const late = merge(early.replica, [b, a2]);
    expect(late.held).toEqual([]);
    expect(late.replica.vector).toEqual({ a: 2, b: 1 });
  });

  it('an invented huge knew blocks only its own author; others and the author’s earlier changes pass', () => {
    const lie = change('h2', 2, 9, { f: 'lie' }, { knew: { h1: Number.MAX_SAFE_INTEGER } });
    const out = merge(emptyReplica('x'), [
      change('h2', 1, 1, { f: 'ok' }),
      lie,
      change('h2', 3, 10, { f: 'after' }),
      change('h3', 1, 3, { g: 1 }, { id: 'r2' }),
    ]);
    expect(out.replica.vector).toEqual({ h2: 1, h3: 1 });
    expect(out.held.map((c) => `${c.device}#${c.seq}`)).toEqual(['h2#2', 'h2#3']);
  });

  it('a suppressed notice is no longer possible: the lying change is held, the conflict is kept', () => {
    let a = emptyReplica('a');
    a = written(a, 'r1', { f: 'base' });
    const b0 = sync(a, emptyReplica('b'));
    const aw = written(a, 'r1', { f: 'from a' });
    const bw = written(b0, 'r1', { f: 'from b' });
    const both = merge(aw, missingFor(bw, aw.vector)).replica;
    expect(both.notices).toHaveLength(1);
    // an attacker c rewrites the same field claiming to have known a lot
    const lie = change('c', 1, 1_000, { f: 'evil' }, { knew: { a: 2 ** 53 - 1, b: 2 ** 53 - 1 } });
    const after = merge(both, [lie]);
    expect(after.applied).toBe(0);
    expect(after.replica.notices).toEqual(both.notices);
    expect(valuesOf(findRecord(after.replica, COL, 'r1')!)).toEqual(
      valuesOf(findRecord(both, COL, 'r1')!),
    );
  });

  it('honest knew still settles: a write that knew every head resolves the notice', () => {
    let a = written(emptyReplica('a'), 'r1', { f: 'base' });
    let b = sync(a, emptyReplica('b'));
    a = written(a, 'r1', { f: 'A' });
    b = written(b, 'r1', { f: 'B' });
    a = sync(b, a);
    expect(a.notices).toHaveLength(1);
    a = written(a, 'r1', { f: 'settled' });
    expect(a.notices).toEqual([]);
  });

  it('delivery in any order converges (dependencies across devices, shuffled)', () => {
    const rand = prng(7);
    let a = written(emptyReplica('a'), 'r1', { f: 1 });
    let b = sync(a, emptyReplica('b'));
    let c = sync(a, emptyReplica('c'));
    for (let i = 0; i < 6; i += 1) {
      a = written(a, 'r1', { f: `a${i}` });
      b = written(sync(a, b), 'r1', { g: `b${i}` });
      c = written(sync(b, c), 'r1', { f: `c${i}`, g: `c${i}` });
      a = sync(c, a);
    }
    const all = [...a.log, ...b.log, ...c.log];
    const target = merge(emptyReplica('t'), all).replica;
    for (let round = 0; round < 25; round += 1) {
      const shuffled = [...all].sort(() => rand() - 0.5);
      let r: Replica = emptyReplica('t');
      // several smaller batches in random order, then everything again
      for (let i = 0; i < shuffled.length; i += 7) r = merge(r, shuffled.slice(i, i + 7)).replica;
      r = merge(r, shuffled).replica;
      expect(r.vector).toEqual(target.vector);
      expect(fingerprint(r)).toBe(fingerprint(target));
      expect(r.notices).toEqual(target.notices);
    }
  });

  it('knew naming only devices the replica already holds does not hold anything back', () => {
    const vec: VersionVector = { a: 1 };
    const out = merge(emptyReplica('x'), [
      change('a', 1, 1, { f: 1 }),
      change('b', 1, 2, { f: 2 }, { knew: vec }),
    ]);
    expect(out.held).toEqual([]);
  });
});
