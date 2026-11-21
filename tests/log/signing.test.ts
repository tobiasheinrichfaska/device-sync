import { describe, expect, it } from 'vitest';
import { generateDeviceKeys, verifyText } from '../../src/core/index.ts';
import {
  changeCheckValue,
  changeSigningText,
  emptyReplica,
  historyOf,
  insertSignatures,
  judgeChange,
  judgeChanges,
  merge,
  readChanges,
  signChange,
  signOwnChanges,
  write,
  type Change,
  type JudgeOptions,
  type KeySource,
  type Replica,
  type Verdict,
} from '../../src/log/index.ts';
import { redacted } from '../../src/log/merge.ts';
import { COL, ok, written, removed } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
const pair = async () => (await generateDeviceKeys()).signing;
const keysOf = (map: Record<string, CryptoKey | undefined>): KeySource => ({
  keyFor: (device) => map[device],
});
const options = (map: Record<string, CryptoKey | undefined>, extra: Partial<JudgeOptions> = {}) =>
  ({
    appId: APP,
    dataSet: SET,
    keys: keysOf(map),
    allowFinalDelete: () => true,
    ...extra,
  }) satisfies JudgeOptions;
const here = (device = 'b'): Replica => emptyReplica(device);
const last = (r: Replica): Change => r.log[r.log.length - 1] as Change;

async function signedLog(r: Replica, key: CryptoKey, set = SET, app = APP): Promise<Replica> {
  return insertSignatures(r, await signOwnChanges(app, key, r, set));
}

async function oneSigned(device = 'a', fields: Record<string, unknown> = { title: 'x' }) {
  const keys = await pair();
  const r = written(emptyReplica(device), 'r1', fields, { time: 1_700_000_000_000, by: 'u' });
  const change = await signChange(APP, keys.privateKey, last(r), SET);
  return { keys, change, replica: r };
}

describe('changeSigningText', () => {
  const change: Change = {
    device: 'a',
    seq: 1,
    clock: 3,
    collection: 'items',
    id: 'x',
    kind: 'set',
    check: 'c1',
  };

  it('has exactly this form (a change of it is a change of the wire format)', () => {
    expect(changeSigningText('demo', change, 'main')).toBe(
      'demo-change:2|{"check":"c1","clock":3,"collection":"items","device":"a","id":"x","kind":"set","seq":1,"set":"main","v":2}',
    );
  });

  it('a redacted change counts as set; a delete stays delete', () => {
    expect(changeSigningText('demo', { ...change, kind: 'redacted' }, 'main')).toBe(
      changeSigningText('demo', change, 'main'),
    );
    expect(changeSigningText('demo', { ...change, kind: 'delete' }, 'main')).toContain(
      '"kind":"delete"',
    );
  });

  it('takes the check value from the content when the change has none', () => {
    const { check: _unused, ...bare } = { ...change, fields: { title: 't' } };
    expect(changeSigningText('demo', bare, 'main')).toContain(
      `"check":${JSON.stringify(changeCheckValue(bare))}`,
    );
  });

  it('refuses an invalid appId', () => {
    expect(() => changeSigningText('Bad Id', change, 'main')).toThrow();
  });
});

describe('signChange and judgeChange', () => {
  it('a signed change checks with its author key', async () => {
    const { keys, change, replica } = await oneSigned();
    expect(change.check).toBe(changeCheckValue(last(replica)));
    expect(change.sig).toMatch(/^[A-Za-z0-9_-]{86}$/);
    const state = here();
    expect(await judgeChange({ ...options({ a: keys.publicKey }), state }, change)).toBe('checked');
  });

  it('every signed field, the data set and the app: one flipped at a time makes it false', async () => {
    const { keys, change } = await oneSigned();
    const state = here();
    const everyKey: KeySource = { keyFor: () => keys.publicKey };
    const cases: [string, Partial<Change>, { appId?: string; dataSet?: string }][] = [
      ['device', { device: 'b' }, {}],
      ['seq', { seq: change.seq + 1 }, {}],
      ['clock', { clock: change.clock + 1 }, {}],
      ['collection', { collection: 'other' }, {}],
      ['id', { id: 'r2' }, {}],
      ['kind set to delete', { kind: 'delete' }, {}],
      ['check', { check: 'AAAA' }, {}],
      ['data set', {}, { dataSet: 'other' }],
      ['appId', {}, { appId: 'otherapp' }],
    ];
    // the unchanged change passes, so a failing case is the flip and nothing else
    expect(
      await verifyText(keys.publicKey, changeSigningText(APP, change, SET), change.sig as string),
    ).toBe(true);
    for (const [name, flip, where] of cases) {
      const altered = { ...change, ...flip };
      const appId = where.appId ?? APP;
      const dataSet = where.dataSet ?? SET;
      const text = changeSigningText(appId, altered, dataSet);
      expect(await verifyText(keys.publicKey, text, change.sig as string), name).toBe(false);
      const verdict = await judgeChange(
        { appId, dataSet, keys: everyKey, state },
        altered as Change,
      );
      expect(verdict, name).toBe('false');
    }
  });

  it('a signature made under one appId does not verify under another', async () => {
    const keys = await pair();
    const r = written(emptyReplica('a'), 'r1', { title: 'x' });
    const one = await signChange('one', keys.privateKey, last(r), SET);
    const key = { keyFor: () => keys.publicKey };
    const judge = (appId: string) =>
      judgeChange({ appId, dataSet: SET, keys: key, state: here() }, one);
    expect(await judge('one')).toBe('checked');
    expect(await judge('two')).toBe('false');
  });

  it('a signature names its data set', async () => {
    const { keys, change } = await oneSigned();
    const key = { keyFor: () => keys.publicKey };
    const judge = (dataSet: string) =>
      judgeChange({ appId: APP, dataSet, keys: key, state: here() }, change);
    expect(await judge(SET)).toBe('checked');
    expect(await judge('other')).toBe('false');
  });

  it('altered content with the old check value, or with a recomputed one and the old signature: false', async () => {
    const { keys, change } = await oneSigned();
    const ctx = { ...options({ a: keys.publicKey }), state: here() };
    const altered = { ...change, fields: { title: 'changed' } };
    expect(await judgeChange(ctx, altered)).toBe('false');
    expect(await judgeChange(ctx, { ...altered, check: changeCheckValue(altered) })).toBe('false');
    for (const flip of [{ knew: { z: 9 } }, { time: 5 }, { by: 'other' }]) {
      expect(await judgeChange(ctx, { ...change, ...flip }), JSON.stringify(flip)).toBe('false');
    }
  });

  it('another key: false', async () => {
    const { change } = await oneSigned();
    const stranger = await pair();
    const ctx = { ...options({ a: stranger.publicKey }), state: here() };
    expect(await judgeChange(ctx, change)).toBe('false');
  });

  it('unsigned or without check value: false, even for an author nobody knows', async () => {
    const { keys, change } = await oneSigned();
    const known = { ...options({ a: keys.publicKey }), state: here() };
    const unknown = { ...options({}), state: here() };
    const { sig: _s, ...unsigned } = change;
    const { check: _c, ...noCheck } = change;
    for (const ctx of [known, unknown]) {
      expect(await judgeChange(ctx, unsigned)).toBe('false');
      expect(await judgeChange(ctx, noCheck)).toBe('false');
      expect(await judgeChange(ctx, last(written(emptyReplica('a'), 'r1', { title: 'x' })))).toBe(
        'false',
      );
    }
  });

  it('wrong-length, garbage and non-base64url signatures are false and never throw', async () => {
    const { keys, change } = await oneSigned();
    const ctx = { ...options({ a: keys.publicKey }), state: here() };
    for (const sig of ['x', 'a'.repeat(86), '!!!', `${change.sig}=`, change.sig?.slice(0, 80)]) {
      expect(await judgeChange(ctx, { ...change, sig } as Change), String(sig)).toBe('false');
    }
  });

  it('an author this device cannot check yet waits; once the key is known it checks', async () => {
    const { keys, change } = await oneSigned();
    const state = here();
    expect(await judgeChange({ ...options({}), state }, change)).toBe('pending');
    const forged = { ...change, fields: { title: 'forged' } };
    const withCheck = { ...forged, check: changeCheckValue(forged) };
    // a forgery with a matching check value still waits while nobody can judge its signature
    expect(await judgeChange({ ...options({}), state }, withCheck)).toBe('pending');
    expect(await judgeChange({ ...options({ a: keys.publicKey }), state }, withCheck)).toBe(
      'false',
    );
    expect(await judgeChange({ ...options({ a: keys.publicKey }), state }, change)).toBe('checked');
  });

  it('a change under the receiver’s own id that it does not hold is false', async () => {
    const keys = await pair();
    const r = await signedLog(written(emptyReplica('a'), 'r1', { title: 'x' }), keys.privateKey);
    const opts = options({ a: keys.publicKey }, { ownDevice: 'a' });
    expect(await judgeChange({ ...opts, state: r }, last(r))).toBe('checked');
    const more = await signedLog(written(r, 'r1', { title: 'y' }), keys.privateKey);
    expect(await judgeChange({ ...opts, state: r }, last(more))).toBe('false');
    expect(await judgeChange({ ...options({ a: keys.publicKey }), state: r }, last(more))).toBe(
      'checked',
    );
  });

  it('signChange: an erased change without check value cannot be signed and comes back as it is', async () => {
    const keys = await pair();
    const bare: Change = {
      device: 'a',
      seq: 1,
      clock: 1,
      collection: COL,
      id: 'r1',
      kind: 'redacted',
    };
    expect(await signChange(APP, keys.privateKey, bare, SET)).toBe(bare);
  });
});

describe('special and rights hooks, neverErase', () => {
  it('the special hook decides first: checked without signature, false with a valid one, pending, or defers', async () => {
    const { keys, change } = await oneSigned();
    const plain = written(emptyReplica('a'), 'r1', { title: 'x' });
    const unsigned = last(plain);
    const base = options({ a: keys.publicKey }, { ownDevice: 'a' });
    const state = here();
    const ctx = (special: JudgeOptions['special']) => ({
      ...base,
      ...(special ? { special } : {}),
      state,
    });
    expect(
      await judgeChange(
        ctx(() => 'checked'),
        unsigned,
      ),
    ).toBe('checked');
    // before the own-id rule, too
    expect(
      await judgeChange(
        ctx(() => 'checked'),
        change,
      ),
    ).toBe('checked');
    expect(
      await judgeChange(
        ctx(() => 'false'),
        change,
      ),
    ).toBe('false');
    expect(
      await judgeChange(
        ctx(() => 'pending'),
        change,
      ),
    ).toBe('pending');
    expect(
      await judgeChange(
        ctx(() => undefined),
        unsigned,
      ),
    ).toBe('false');
    const selective = (c: Change) => (c.id === 'r1' ? 'checked' : undefined);
    expect(await judgeChange(ctx(selective), unsigned)).toBe('checked');
    expect(await judgeChange(ctx(selective), { ...unsigned, id: 'r9' })).toBe('false');
  });

  it('the rights hook gets the author and the change; false refuses a valid signature', async () => {
    const { keys, change } = await oneSigned();
    const seen: [string, string][] = [];
    const deny = (author: string, c: Change) => (seen.push([author, c.id]), false);
    const allow = () => true;
    const state = here();
    const opts = (mayWrite: JudgeOptions['mayWrite']) => ({
      ...options({ a: keys.publicKey }),
      ...(mayWrite ? { mayWrite } : {}),
      state,
    });
    expect(await judgeChange(opts(deny), change)).toBe('false');
    expect(seen).toEqual([['a', 'r1']]);
    expect(await judgeChange(opts(allow), change)).toBe('checked');
    expect(await judgeChange(opts(undefined), change)).toBe('checked');
  });

  it('the rights hook is not asked for a forged signature or an unknown author', async () => {
    const { keys, change } = await oneSigned();
    let asked = 0;
    const mayWrite = () => (asked++, true);
    const forged = { ...change, seq: 7 };
    const state = here();
    expect(
      await judgeChange({ ...options({ a: keys.publicKey }, { mayWrite }), state }, forged),
    ).toBe('false');
    expect(await judgeChange({ ...options({}, { mayWrite }), state }, change)).toBe('pending');
    expect(asked).toBe(0);
  });

  it('a final deletion in a neverErase collection is false; a set there or a delete elsewhere is fine', async () => {
    const keys = await pair();
    let r = emptyReplica('a');
    r = ok(write(r, 'devices', 'd1', { name: 'one' }));
    r = removed(r, 'devices', 'd1');
    r = written(r, 'r1', { title: 'x' });
    r = removed(r, COL, 'r1');
    r = await signedLog(r, keys.privateKey);
    const opts = options({ a: keys.publicKey }, { neverErase: ['devices'] });
    const verdicts = await judgeChanges({ ...opts, state: here() }, r.log);
    // log: redacted d1 set, delete d1, redacted r1 set, delete r1
    expect(r.log.map((c) => `${c.collection}/${c.kind}`)).toEqual([
      'devices/redacted',
      'devices/delete',
      `${COL}/redacted`,
      `${COL}/delete`,
    ]);
    // the erased write of r1 waits: its deletion is judged right but cannot apply, as the number
    // before it (the refused deletion of the list) is missing
    expect(verdicts).toEqual(['false', 'false', 'pending', 'checked']);
    const withoutList = await judgeChanges(
      { ...options({ a: keys.publicKey }), state: here() },
      r.log,
    );
    expect(withoutList).toEqual(['checked', 'checked', 'checked', 'checked']);
  });
});

describe('a final deletion', () => {
  it('erases the content; the signature stays checkable beside the deletion', async () => {
    const keys = await pair();
    const r = await signedLog(
      written(emptyReplica('a'), 'r1', { title: 'secret' }),
      keys.privateKey,
    );
    const original = last(r);
    const deleted = await signedLog(removed(r, COL, 'r1'), keys.privateKey);
    const [erased, deletion] = deleted.log as [Change, Change];
    expect(erased.kind).toBe('redacted');
    expect(erased.fields).toBeUndefined();
    expect(erased.sig).toBe(original.sig);
    const ctx = { ...options({ a: keys.publicKey }), state: here() };
    expect(await judgeChanges(ctx, [erased, deletion])).toEqual(['checked', 'checked']);
    expect(await judgeChanges({ ...ctx, state: { ...here(), log: [deletion] } }, [erased])).toEqual(
      ['checked'],
    );
    // a receiver that holds the original and then the deletion keeps the signature in the log
    const b = merge(merge(here(), [deletion]).replica, [original]).replica;
    expect(b.log.find((c) => c.seq === 1)?.sig).toBe(original.sig);
  });

  it('the erased change still verifies: its check value was taken before the erasure', async () => {
    const { keys, change } = await oneSigned();
    const erased = redacted(change);
    expect(erased.fields).toBeUndefined();
    expect(erased.check).toBe(change.check);
    const text = changeSigningText(APP, erased, SET);
    expect(text).toBe(changeSigningText(APP, change, SET));
    expect(await verifyText(keys.publicKey, text, erased.sig as string)).toBe(true);
    // alone it is not taken: an erased change counts only beside its deletion (see M3 in review2)
    const ctx = { ...options({ a: keys.publicKey }), state: here() };
    expect(await judgeChange(ctx, erased)).toBe('false');
  });

  it('an erased write without its deletion is false (a forwarder cannot erase a signed write)', async () => {
    const { keys, change } = await oneSigned();
    const ctx = { ...options({ a: keys.publicKey }), state: here() };
    expect(await judgeChanges(ctx, [redacted(change)])).toEqual(['false']);
  });

  it('beside a deletion that waits (author not checkable yet), it waits too; beside a false one it is false', async () => {
    const a = await pair();
    const c = await pair();
    const r = await signedLog(written(emptyReplica('a'), 'r1', { title: 'x' }), a.privateKey);
    const byC = await signedLog(
      removed(merge(emptyReplica('c'), r.log).replica, COL, 'r1'),
      c.privateKey,
    );
    const onlyA = { ...options({ a: a.publicKey }), state: here() };
    expect(await judgeChanges(onlyA, [byC.log[0] as Change, last(byC)])).toEqual([
      'pending',
      'pending',
    ]);
    const both = { ...options({ a: a.publicKey, c: c.publicKey }), state: here() };
    expect(await judgeChanges(both, [byC.log[0] as Change, last(byC)])).toEqual([
      'checked',
      'checked',
    ]);
    const forgedDelete = { ...last(byC), id: 'r2' };
    expect(await judgeChanges(both, [byC.log[0] as Change, forgedDelete])).toEqual([
      'false',
      'false',
    ]);
  });

  it('a write erased before it was signed is still signed later, over its check value', async () => {
    const keys = await pair();
    let r = written(emptyReplica('a'), 'r1', { title: 'x' });
    const content = changeCheckValue(last(r));
    r = removed(r, COL, 'r1');
    expect(r.log[0]).toMatchObject({ kind: 'redacted', check: content });
    const signed = await signedLog(r, keys.privateKey);
    expect(signed.log.every((c) => c.sig)).toBe(true);
    const ctx = { ...options({ a: keys.publicKey }), state: here() };
    expect(await judgeChanges(ctx, signed.log)).toEqual(['checked', 'checked']);
  });
});

describe('own changes', () => {
  it('every unsigned own change is signed and put into the replica of now; others’ are not', async () => {
    const keys = await pair();
    let r = written(written(emptyReplica('a'), 'r1', { title: '1' }), 'r1', { title: '2' });
    const signed = await signOwnChanges(APP, keys.privateKey, r, SET);
    expect(signed.map((c) => c.seq)).toEqual([1, 2]);
    const withSigs = insertSignatures(written(r, 'r2', { title: '3' }), signed);
    expect(withSigs.log.map((c) => !!c.sig)).toEqual([true, true, false]);
    const theirs = merge(emptyReplica('b'), withSigs.log).replica;
    expect(await signOwnChanges(APP, keys.privateKey, theirs, SET)).toEqual([]);
    expect(historyOf(withSigs, COL, 'r1').map((h) => [h.seq, h.signed])).toEqual([
      [2, true],
      [1, true],
    ]);
    r = withSigs;
    expect(insertSignatures(r, [])).toBe(r);
    expect(insertSignatures(r, signed)).toBe(r);
  });

  it('a signature made before the erasure goes into the erased write; one over other content does not', async () => {
    const keys = await pair();
    let r = written(emptyReplica('a'), 'r1', { title: 'x' });
    const before = await signOwnChanges(APP, keys.privateKey, r, SET);
    r = removed(r, COL, 'r1');
    expect(insertSignatures(r, before).log[0]?.sig).toBe(before[0]?.sig);
    const other = [
      {
        ...(before[0] as Change),
        check: changeCheckValue({ ...(before[0] as Change), fields: { title: 'y' } }),
      },
    ];
    expect(insertSignatures(r, other)).toBe(r);
  });
});

describe('readChanges', () => {
  it('takes what checks, counts what waits, refuses all on one false', async () => {
    const a = await pair();
    const c = await pair();
    const fromA = await signedLog(written(emptyReplica('a'), 'r1', { title: '1' }), a.privateKey);
    const fromC = await signedLog(written(emptyReplica('c'), 'r2', { title: '2' }), c.privateKey);
    const opts = options({ a: a.publicKey });
    const ok1 = await readChanges(here(), [...fromA.log, ...fromC.log], opts);
    expect(ok1.accepted.map((x) => x.device)).toEqual(['a']);
    expect(ok1.pending.map((x) => x.device)).toEqual(['c']);
    expect(ok1.rejected).toBe(0);
    const forged = { ...last(fromA), fields: { title: '9' } };
    const bad = await readChanges(here(), [forged, ...fromC.log, ...fromA.log], opts);
    expect(bad).toMatchObject({ accepted: [], pending: [], rejected: 1 });
    const unsigned = last(written(emptyReplica('a'), 'r7', { title: 'u' }));
    const bad2 = await readChanges(here(), [...fromA.log, unsigned], opts);
    expect(bad2.accepted).toEqual([]);
    expect(bad2.rejected).toBe(1);
  });

  it('what a batch takes may make further authors checkable in the same batch', async () => {
    const a = await pair();
    const c = await pair();
    const intro = await signedLog(
      ok1Write(emptyReplica('a'), 'devices', 'c', { known: true }),
      a.privateKey,
    );
    const fromC = await signedLog(written(emptyReplica('c'), 'r2', { title: '2' }), c.privateKey);
    const calls: string[] = [];
    const keys: KeySource = {
      keyFor: (device, state) => {
        calls.push(device);
        if (device === 'a') return a.publicKey;
        return device === 'c' && state.collections.devices?.['c'] ? c.publicKey : undefined;
      },
    };
    const opts = { appId: APP, dataSet: SET, keys };
    const both = await readChanges(here(), [...fromC.log, ...intro.log], opts);
    expect(both.accepted.map((x) => x.device).sort()).toEqual(['a', 'c']);
    expect(both.pending).toEqual([]);
    // without the introducing change the other one keeps waiting
    const alone = await readChanges(here(), fromC.log, opts);
    expect(alone.accepted).toEqual([]);
    expect(alone.pending).toHaveLength(1);
  });

  it('a pending change comes again and is taken once its key is known', async () => {
    const { keys, change } = await oneSigned();
    const first = await readChanges(here(), [change], options({}));
    expect(first.pending).toEqual([change]);
    const second = await readChanges(here(), first.pending, options({ a: keys.publicKey }));
    expect(second.accepted).toEqual([change]);
  });

  it('applies the hooks: the rights hook refusing one change refuses the batch', async () => {
    const a = await pair();
    const r = await signedLog(
      written(written(emptyReplica('a'), 'r1', { title: '1' }), 'r2', { title: '2' }),
      a.privateKey,
    );
    const mayWrite = (_author: string, c: Change) => c.id !== 'r2';
    const out = await readChanges(here(), r.log, options({ a: a.publicKey }, { mayWrite }));
    expect(out).toMatchObject({ accepted: [], pending: [], rejected: 1 });
    const fine = await readChanges(here(), r.log, options({ a: a.publicKey }));
    expect(fine.accepted).toHaveLength(2);
  });
});

function ok1Write(r: Replica, collection: string, id: string, fields: Record<string, unknown>) {
  return ok(write(r, collection, id, fields));
}

describe('regression: members the signature does not cover', () => {
  it('a change with an unknown member is false, however valid its signature is', async () => {
    const { keys, change } = await oneSigned();
    const opts = (extra: Partial<JudgeOptions> = {}) => ({
      ...options({ a: keys.publicKey }, extra),
      state: here(),
    });
    expect(await judgeChange(opts(), change)).toBe('checked');
    for (const extra of [{ foo: 1 }, { fields2: {} }, { knew2: {} }, { sigx: 'x' }]) {
      const smuggled = { ...change, ...extra } as Change;
      expect(await judgeChange(opts(), smuggled), JSON.stringify(extra)).toBe('false');
    }
  });

  it('the special case cannot wave an unknown member through either', async () => {
    const { change } = await oneSigned();
    const opts = { ...options({}, { special: () => 'checked' as const }), state: here() };
    expect(await judgeChange(opts, { ...change, foo: 1 } as Change)).toBe('false');
  });

  it('one smuggling change aborts the whole batch', async () => {
    const keys = await pair();
    let r = written(emptyReplica('a'), 'r1', { title: 'x' });
    r = written(r, 'r2', { title: 'y' });
    const [first, second] = await Promise.all(
      r.log.map((c) => signChange(APP, keys.privateKey, c, SET)),
    );
    const opts = options({ a: keys.publicKey });
    // both signed correctly: taken
    expect(
      (await readChanges(here(), [first as Change, second as Change], opts)).accepted,
    ).toHaveLength(2);
    // the same, but one carries a member the signature does not cover: nothing is taken
    const smuggled = { ...(second as Change), foo: 1 } as Change;
    expect(await readChanges(here(), [first as Change, smuggled], opts)).toMatchObject({
      accepted: [],
      pending: [],
      rejected: 1,
    });
  });
});

describe('start data accepted by a special hook, also when erased (both earlier implementations)', () => {
  const START = 'start';
  const compiled = written(emptyReplica(START), 'r1', { title: 'x' }).log;
  const original = compiled[0] as Change;
  // exactly as compiled in: same content and clock; a number it does not know comes from a newer
  // version and waits; an erased copy counts when its check value is the compiled content's
  const special = (c: Change): Verdict | undefined => {
    if (c.device !== START) return undefined;
    const known = compiled.find((k) => k.seq === c.seq);
    if (!known) return 'pending';
    if (c.kind === 'redacted') return c.check === changeCheckValue(known) ? 'checked' : 'false';
    return changeCheckValue(c) === changeCheckValue(known) && c.clock === known.clock
      ? 'checked'
      : 'false';
  };

  it('counts only exactly as compiled; a newer version waits', async () => {
    const ctx = { ...options({}, { special }), state: here() };
    expect(await judgeChange(ctx, original)).toBe('checked');
    expect(await judgeChange(ctx, { ...original, fields: { title: 'other' } })).toBe('false');
    expect(await judgeChange(ctx, { ...original, clock: 99 })).toBe('false');
    expect(await judgeChange(ctx, { ...original, seq: 2, clock: 2 })).toBe('pending');
    // without the hook it is just an unsigned change
    expect(await judgeChange({ ...options({}), state: here() }, original)).toBe('false');
  });

  it('an erased copy passes only beside its record’s final deletion', async () => {
    const keys = await pair();
    let r = merge(emptyReplica('a'), compiled).replica;
    r = await signedLog(removed(r, COL, 'r1'), keys.privateKey);
    const erased = r.log.find((c) => c.device === START) as Change;
    const deletion = last(r);
    expect(erased).toMatchObject({ kind: 'redacted', check: changeCheckValue(original) });
    const ctx = { ...options({ a: keys.publicKey }, { special }), state: here() };
    expect(await judgeChanges(ctx, [erased, deletion])).toEqual(['checked', 'checked']);
    expect(await judgeChanges(ctx, [erased])).toEqual(['false']);
    expect(await judgeChanges(ctx, [{ ...erased, check: 'AAAA' }, deletion])).toEqual([
      'false',
      'checked',
    ]);
  });
});
