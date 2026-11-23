// Gaps found against the earlier implementations: app validation per collection (`fieldRules`), what
// happens to a whole session when the receiver's rights refuse one change, and three properties of
// the model pinned on their own (equal values are no conflict, a shortened `knew`, the size of a change
// among 25 devices).
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDeviceKeys } from '../../src/core/index.ts';
import {
  emptyReplica,
  fingerprint,
  insertSignatures,
  judgeChanges,
  merge,
  missingFor,
  onSyncMessage,
  pieces,
  receiveJudged,
  remove,
  signOwnChanges,
  softDelete,
  startSession,
  undo,
  write,
  type Change,
  type FieldRules,
  type JudgeOptions,
  type KeySource,
  type Replica,
  type Session,
  type SyncMessage,
} from '../../src/log/index.ts';
import { COL } from './helpers.ts';

const APP = 'syncdemo';
const SET = 'main';
const pairs: Record<string, CryptoKeyPair> = {};
const keySource: KeySource = { keyFor: (device) => pairs[device]?.publicKey };
const NAMES = ['a', 'b', 'x', 'y'];

beforeAll(async () => {
  for (const id of NAMES) pairs[id] = (await generateDeviceKeys()).signing;
});

const judgeFor = (me: string, extra: Partial<JudgeOptions> = {}): JudgeOptions => ({
  appId: APP,
  dataSet: SET,
  keys: keySource,
  ownDevice: me,
  allowFinalDelete: () => true,
  ...extra,
});

async function signed(replica: Replica): Promise<Replica> {
  const key = (pairs[replica.device] as CryptoKeyPair).privateKey;
  return insertSignatures(replica, await signOwnChanges(APP, key, replica, SET));
}

const json = (m: unknown): unknown => JSON.parse(JSON.stringify(m));
const okw = (r: ReturnType<typeof write>): Replica => {
  if (!r.ok) throw new Error(`refused ${r.reason}`);
  return r.replica;
};

/** One direction of a session: `to` sends its stand, `from` answers, `to` reads the answer judged. */
async function deliver(
  from: Replica,
  to: Replica,
  extra: Partial<JudgeOptions> = {},
  options: { pieceBytes?: number; fieldRules?: FieldRules } = {},
): Promise<{ session: Session; replica: Replica }> {
  const sender = await signed(from);
  const limits = options.pieceBytes ? { limits: { pieceBytes: options.pieceBytes } } : {};
  const asked = startSession(to);
  const reply = onSyncMessage(
    startSession(sender).session,
    sender,
    asked.send[0] as SyncMessage,
    limits,
  );
  let current = { session: asked.session, replica: to };
  for (const message of reply.send) {
    const step = await receiveJudged(
      current.session,
      current.replica,
      json(message),
      judgeFor(to.device, extra),
      { ...limits, ...(options.fieldRules ? { fieldRules: options.fieldRules } : {}) },
    );
    current = { session: step.session, replica: step.replica };
  }
  return current;
}

describe('fieldRules: the app validates names, values and relations per collection', () => {
  const OWNER = 'owner';
  const rules: FieldRules = (change, state) => {
    if (change.collection !== 'plans') return undefined;
    for (const [name, value] of Object.entries(change.fields ?? {})) {
      if (!['owner', 'day', 'state'].includes(name)) return 'unknown-field';
      if (name === 'day' && !(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value))) {
        return 'bad-day';
      }
    }
    const current = state.collections['plans']?.[change.id]?.fields[OWNER]?.value;
    if (current !== undefined && current !== change.device) return 'not-the-owner';
    return undefined;
  };

  it('local writing is refused with the code, before anything is created', () => {
    const a = emptyReplica('a');
    const options = { fieldRules: rules };
    const bad = write(a, 'plans', 'p1', { colour: 'red' }, {}, options);
    expect(bad).toEqual({ ok: false, reason: 'field-rules', detail: 'unknown-field' });
    expect(write(a, 'plans', 'p1', { day: '2026-13' }, {}, options)).toEqual({
      ok: false,
      reason: 'field-rules',
      detail: 'bad-day',
    });
    const good = okw(write(a, 'plans', 'p1', { owner: 'a', day: '2026-11-22' }, {}, options));
    expect(good.log).toHaveLength(1);
    // other collections are not touched by the rule
    expect(write(a, 'notes', 'n1', { anything: 1 }, {}, options).ok).toBe(true);
    // a relation to the present state: another device's record
    const b = merge(emptyReplica('b'), good.log).replica;
    expect(write(b, 'plans', 'p1', { state: 'x' }, {}, options)).toEqual({
      ok: false,
      reason: 'field-rules',
      detail: 'not-the-owner',
    });
    // the other write paths ask too
    expect(remove(a, 'plans', 'nothing', {}, { fieldRules: () => 'no-delete' })).toEqual({
      ok: false,
      reason: 'field-rules',
      detail: 'no-delete',
    });
    expect(softDelete(good, 'plans', 'p1', {}, { fieldRules: () => 'frozen' })).toMatchObject({
      reason: 'field-rules',
    });
    expect(
      undo(good, 'plans', 'p1', { device: 'a', seq: 1 }, {}, { fieldRules: () => 'frozen' }),
    ).toMatchObject({
      reason: 'field-rules',
    });
  });

  it('a rule that throws or answers badly refuses (fail closed)', () => {
    const a = emptyReplica('a');
    const throwing: FieldRules = () => {
      throw new Error('boom');
    };
    expect(write(a, COL, 'r', { t: 1 }, {}, { fieldRules: throwing })).toEqual({
      ok: false,
      reason: 'field-rules',
      detail: 'invalid-rule-answer',
    });
    for (const answer of ['', 'x'.repeat(121), 5, null, {}, true]) {
      const bad = write(
        a,
        COL,
        'r',
        { t: 1 },
        {},
        { fieldRules: (() => answer) as unknown as FieldRules },
      );
      expect(bad, String(answer)).toMatchObject({ ok: false, detail: 'invalid-rule-answer' });
    }
    expect(write(a, COL, 'r', { t: 1 }, {}, { fieldRules: () => undefined }).ok).toBe(true);
  });

  it('the receiver refuses the whole session with the same code, and takes nothing', async () => {
    // x has no rule: it writes a record a peer with the rule refuses
    const x = okw(write(emptyReplica('x'), 'plans', 'p9', { colour: 'red' }));
    const b = okw(write(emptyReplica('b'), COL, 'mine', { t: 1 }));
    for (const where of ['options', 'judge'] as const) {
      const result =
        where === 'options'
          ? await deliver(x, b, {}, { fieldRules: rules })
          : await deliver(x, b, { fieldRules: rules });
      expect(result.session.refusal).toBe('forged');
      expect(result.session.refusalReason).toBe('field-rules');
      expect(result.session.refusalDetail).toBe('unknown-field');
      expect(result.session.refusalDevice).toBe('x');
      expect(result.replica).toBe(b);
    }
    // without the rule the same session is taken
    const open = await deliver(x, b);
    expect(open.session.refusal).toBeUndefined();
    expect(open.replica.vector['x']).toBe(1);
  });

  it('runs once per change, after the signature and the rights, and never for an erased change', async () => {
    let x = emptyReplica('x');
    for (let i = 0; i < 6; i += 1) x = okw(write(x, COL, `r${i}`, { t: i }));
    x = okw(remove(x, COL, 'r0'));
    const seen: string[] = [];
    const spy: FieldRules = (change) => (seen.push(`${change.kind}:${change.seq}`), undefined);
    const result = await deliver(x, emptyReplica('b'), {}, { fieldRules: spy });
    expect(result.session.refusal).toBeUndefined();
    // 7 changes: five writes, one erased write (not asked), one deletion
    expect(seen).toHaveLength(6);
    expect(seen.filter((s) => s.startsWith('redacted'))).toHaveLength(0);
    expect(seen).toContain('delete:7');
    // an unsigned change is refused before the rule is asked
    seen.length = 0;
    const forged = { ...(x.log[1] as Change) } as Change & { sig?: string };
    delete forged.sig;
    const step = await receiveJudged(
      startSession(emptyReplica('b')).session,
      emptyReplica('b'),
      json({ t: 'changes', changes: [forged], last: true }),
      judgeFor('b', { fieldRules: spy }),
    );
    expect(step.session.refusalReason).toBe('unsigned');
    expect(seen).toHaveLength(0);
    // a mayWrite that says no is asked first
    const denied = await deliver(x, emptyReplica('b'), { mayWrite: () => false, fieldRules: spy });
    expect(denied.session.refusalReason).toBe('not-allowed');
    expect(seen).toHaveLength(0);
  });
});

describe('rights at the receiver: a refused change refuses the whole session', () => {
  async function world() {
    // x writes things, a holds x's changes and its own, b has not met x
    let x = emptyReplica('x');
    for (let i = 0; i < 5; i += 1) x = okw(write(x, COL, `x${i}`, { from: 'x', i }));
    let a = emptyReplica('a');
    for (let i = 0; i < 20; i += 1)
      a = okw(write(a, COL, `a${i}`, { from: 'a', i, pad: 'p'.repeat(200) }));
    a = merge(a, (await signed(x)).log).replica;
    for (let i = 0; i < 20; i += 1)
      a = okw(write(a, COL, `late${i}`, { from: 'a', i, pad: 'p'.repeat(200) }));
    const b = okw(write(emptyReplica('b'), COL, 'bmine', { from: 'b' }));
    return { a, b };
  }
  const noX: Partial<JudgeOptions> = { mayWrite: (author) => author !== 'x' };

  it('nothing is taken, not even the allowed changes of earlier pieces; the replica is the same value', async () => {
    const { a, b } = await world();
    for (const pieceBytes of [100_000, 1500]) {
      const sent = pieces((await signed(a)).log, { limits: { pieceBytes } });
      const many = pieceBytes < 100_000;
      if (many) expect(sent.length).toBeGreaterThan(3);
      let step = { session: startSession(b).session, replica: b } as {
        session: Session;
        replica: Replica;
      };
      for (const message of sent) {
        const next = await receiveJudged(
          step.session,
          step.replica,
          json(message),
          judgeFor('b', noX),
          {
            limits: { pieceBytes },
          },
        );
        step = { session: next.session, replica: next.replica };
      }
      expect(step.session.refusal).toBe('forged');
      expect(step.session.refusalReason).toBe('not-allowed');
      expect(step.session.refusalDevice).toBe('x');
      expect(step.replica).toBe(b);
      expect(step.replica.vector).toEqual(b.vector);
      expect(step.session.taken).toBe(0);
    }
  });

  it('a refused piece ends the session at once: later pieces are ignored, the answer is empty', async () => {
    const { a, b } = await world();
    const sent = pieces((await signed(a)).log, { limits: { pieceBytes: 1500 } });
    let step = { session: startSession(b).session, replica: b, send: [] as unknown[] };
    let refusedAt = -1;
    for (let i = 0; i < sent.length; i += 1) {
      const next = await receiveJudged(
        step.session,
        step.replica,
        json(sent[i]),
        judgeFor('b', noX),
      );
      step = { session: next.session, replica: next.replica, send: next.send as unknown[] };
      if (next.session.refusal && refusedAt < 0) refusedAt = i;
      if (refusedAt >= 0) expect(step.send).toEqual([]);
    }
    expect(refusedAt).toBeGreaterThanOrEqual(0);
    expect(refusedAt).toBeLessThan(sent.length - 1);
    expect(step.replica).toBe(b);
  });

  it('is the same every time (no loop of partial progress) and a later allowing rule takes everything gaplessly', async () => {
    const { a, b } = await world();
    const first = await deliver(a, b, noX);
    const second = await deliver(a, first.replica, noX);
    expect(first.session.refusal).toBe('forged');
    expect(second.session.refusal).toBe('forged');
    expect(second.replica).toBe(b);
    // what the other authors lack is untouched; once the rule allows x, the next session takes all
    const allowed = await deliver(a, second.replica, {});
    expect(allowed.session.refusal).toBeUndefined();
    expect(allowed.replica.vector).toEqual({ ...b.vector, a: 40, x: 5 });
    // numbering stayed gapless: every device's changes are 1..n in the log
    for (const [device, n] of Object.entries(allowed.replica.vector)) {
      const seqs = allowed.replica.log.filter((c) => c.device === device).map((c) => c.seq);
      expect(seqs).toEqual(Array.from({ length: n }, (_, i) => i + 1));
    }
  });

  it('an honest sender can find what peers would refuse in its own log, before sending', async () => {
    const { a } = await world();
    const verdicts = await judgeChanges(
      { ...judgeFor('b', noX), state: emptyReplica('b') },
      (await signed(a)).log.filter((c) => c.device === 'x'),
    );
    expect(verdicts.every((v) => v === 'false')).toBe(true);
  });

  it('with the unjudged path the changes are taken as they are (rights are the judged path)', () => {
    const x = okw(write(emptyReplica('x'), COL, 'r', { t: 1 }));
    expect(merge(emptyReplica('b'), missingFor(x, {})).applied).toBe(1);
  });
});

describe('model properties of the earlier implementations, pinned', () => {
  it('two devices writing the same value at the same time leave no notice; different values do', () => {
    const base = okw(write(emptyReplica('a'), COL, 'r', { title: 'start', n: 1 }));
    let a = base;
    let b = merge(emptyReplica('b'), base.log).replica;
    a = okw(write(a, COL, 'r', { title: 'same', n: { k: [1, 2] } }));
    b = okw(write(b, COL, 'r', { title: 'same', n: { k: [1, 2] } }));
    const ab = merge(a, b.log.slice(1)).replica;
    const ba = merge(b, a.log.slice(1)).replica;
    expect(ab.notices).toEqual([]);
    expect(ba.notices).toEqual([]);
    expect(fingerprint(ab)).toBe(fingerprint(ba));
    // key order inside an object value does not make values different
    let c = base;
    let d = merge(emptyReplica('d'), base.log).replica;
    c = okw(write(c, COL, 'r', { n: { p: 1, q: 2 } }));
    d = okw(write(d, COL, 'r', { n: { q: 2, p: 1 } }));
    expect(merge(c, d.log.slice(1)).replica.notices).toEqual([]);
    // different values: one notice naming both
    let e = base;
    let f = merge(emptyReplica('f'), base.log).replica;
    e = okw(write(e, COL, 'r', { title: 'one' }));
    f = okw(write(f, COL, 'r', { title: 'two' }));
    const ef = merge(e, f.log.slice(1)).replica;
    expect(ef.notices).toHaveLength(1);
    expect(ef.notices[0]?.values.map((v) => v.value)).toEqual(['one', 'two']);
  });

  it('`knew` names only the devices that wrote the fields touched, among 25 devices a change is about half a KB', () => {
    const ids = Array.from({ length: 25 }, (_, i) =>
      `dev-${i.toString(16).padStart(2, '0')}${'ab12cd34ef56'.repeat(2)}`.slice(0, 22),
    );
    let replicas = ids.map((id, i) =>
      okw(write(emptyReplica(id), COL, `own${i}`, { title: `t${i}` })),
    );
    // everybody gets everything
    const all = replicas.flatMap((r) => r.log);
    replicas = replicas.map((r) => merge(r, all).replica);
    const r0 = replicas[0] as Replica;
    expect(Object.keys(r0.vector)).toHaveLength(25);
    // writing a field of a record only this device ever wrote: it names itself only
    const next = okw(write(r0, COL, 'own0', { title: 'again' }));
    const change = next.log[next.log.length - 1] as Change;
    expect(change.knew).toEqual({ [ids[0] as string]: 1 });
    const size = JSON.stringify(change).length;
    expect(size).toBeLessThan(500);
    // with the whole stand it would be several times that
    const whole = JSON.stringify({ ...change, knew: r0.vector }).length;
    expect(whole).toBeGreaterThan(size * 3);
    // a field written by 25 devices one after the other still names one head
    let chain = replicas[0] as Replica;
    for (let i = 1; i < 25; i += 1) {
      chain = okw(write(chain, COL, 'shared', { note: `n${i}` }));
      const next = merge(replicas[i] as Replica, chain.log).replica;
      replicas[i] = okw(write(next, COL, 'shared', { note: `m${i}` }));
      chain = merge(chain, replicas[i]!.log).replica;
    }
    const last = chain.log[chain.log.length - 1] as Change;
    expect(Object.keys(last.knew ?? {}).length).toBeLessThanOrEqual(2);
  });
});
