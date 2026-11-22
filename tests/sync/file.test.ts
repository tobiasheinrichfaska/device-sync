// The exchange file: one way, asynchronous, carrier-free; the stand memory; the strict payload reader.
import { describe, expect, it } from 'vitest';
import { generateDeviceKeys, publicKeys, sealFile } from '../../src/core/index.ts';
import { emptyReplica, merge, write, type Replica } from '../../src/log/index.ts';
import { EMPTY_MAILBOX, addEnvelopes } from '../../src/post/index.ts';
import { sealEnvelope } from '../../src/core/index.ts';
import {
  EMPTY_STANDS,
  fileMark,
  makeExchangeFile,
  readExchangePayload,
  readStandMemory,
  rememberStand,
  takeExchangeFile,
  type ExchangeFileConfig,
  type SyncConfig,
} from '../../src/sync/index.ts';
import { APP, prng, world, type Member } from './helpers.ts';

const PLAN = 'plan';
const NOW = 1_800_000_000_000;
const cfgOf = (m: Member, sets: SyncConfig['sets'] = { [PLAN]: {} }): ExchangeFileConfig => ({
  ...m.config,
  sets,
  post: {},
});

const put = (r: Replica, _set: string, id: string, v: unknown): Replica => {
  const out = write(r, 'rows', id, { v }, { time: 1 });
  if (!out.ok) throw new Error(out.reason);
  return out.replica;
};
const rows = (r: Replica | undefined): string[] => Object.keys(r?.collections.rows ?? {}).sort();

describe('the exchange file', () => {
  it('carries what the other lacks, its own stand, envelopes and a notice; the answer file only what is new', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = w.members as [Member, Member];
    const cfgA = cfgOf(a);
    const cfgB = cfgOf(b);
    let planA = put(emptyReplica(a.id), PLAN, 'r1', 1);
    planA = put(planA, PLAN, 'r2', 2);
    const sealed = await sealEnvelope({
      appId: APP,
      author: { device: a.id, signing: a.keys.signing.privateKey },
      recipients: [b.intro.dh],
      channel: 'x',
      day: new Date(NOW).toISOString().slice(0, 10),
      body: new Uint8Array([1]),
      random: (n) => crypto.getRandomValues(new Uint8Array(n)),
    });
    if (!sealed.ok) throw new Error(sealed.reason);
    const box = addEnvelopes(
      APP,
      EMPTY_MAILBOX,
      [sealed.envelope],
      new Date(NOW).toISOString().slice(0, 10),
    );
    if (!box.ok) throw new Error(box.reason);

    const made = await makeExchangeFile(cfgA, {
      to: b.id,
      replica: a.replica,
      held: { sets: { [PLAN]: planA }, mailbox: box.mailbox },
      notice: 'hello-b',
      nowMs: NOW,
    });
    if (!made.ok) throw new Error(made.reason);
    expect(made.changes).toBeGreaterThan(2);
    expect(made.envelopes).toBe(1);

    // B takes it with an empty plan of its own
    const took = await takeExchangeFile(cfgB, { file: made.file, replica: b.replica, nowMs: NOW });
    if (!took.ok) throw new Error(`${took.reason} ${took.detail}`);
    expect(took.from).toBe(a.id);
    expect(rows(took.sets[PLAN])).toEqual(['r1', 'r2']);
    expect(took.received.length).toBe(1);
    expect(took.notice).toBe('hello-b');
    expect(took.refused).toEqual({});
    expect(took.memory[a.id]?.[PLAN]).toEqual(planA.vector);

    // B writes something and answers; the answer carries B's news only (A's changes are in the memory)
    const planB = put(took.sets[PLAN] as Replica, PLAN, 'r3', 3);
    const back = await makeExchangeFile(cfgB, {
      to: a.id,
      replica: took.replica,
      held: { sets: { [PLAN]: planB } },
      memory: took.memory,
      nowMs: NOW,
    });
    if (!back.ok) throw new Error(back.reason);
    expect(back.changes).toBe(1);
    const tookBack = await takeExchangeFile(cfgA, {
      file: back.file,
      replica: made.replica,
      held: { sets: { [PLAN]: planA } },
      nowMs: NOW,
    });
    if (!tookBack.ok) throw new Error(tookBack.reason);
    expect(rows(tookBack.sets[PLAN])).toEqual(['r1', 'r2', 'r3']);
  });

  it('only the named receiver opens it, and only from a trusted sender', async () => {
    const w = await world(['A', 'B', 'C'], { outsiders: 1 });
    const [a, b, c] = w.members as [Member, Member, Member];
    const made = await makeExchangeFile(cfgOf(a), {
      to: b.id,
      replica: a.replica,
      held: { sets: { [PLAN]: put(emptyReplica(a.id), PLAN, 'r1', 1) } },
      nowMs: NOW,
    });
    if (!made.ok) throw new Error(made.reason);
    // C is no device of the list: it cannot even be a recipient
    const toC = await makeExchangeFile(cfgOf(a), { to: c.id, replica: a.replica, nowMs: NOW });
    expect(toC).toMatchObject({ ok: false, reason: 'recipient-not-trusted' });
    // the file is for B: A cannot take its own file, nor can anybody else
    expect(
      await takeExchangeFile(cfgOf(c), { file: made.file, replica: c.replica, nowMs: NOW }),
    ).toMatchObject({
      ok: false,
      reason: 'wrong-recipient',
    });
    // a file from a device this one does not trust
    const ck = c.keys;
    const stray = await sealFile({
      appId: APP,
      own: { device: c.id, agreement: ck.agreement },
      to: { device: b.id, dh: b.intro.dh },
      payload: new TextEncoder().encode('x'),
      random: new Uint8Array(12).fill(3),
    });
    if (!stray.ok) throw new Error(stray.reason);
    expect(
      await takeExchangeFile(cfgOf(b), { file: stray.file, replica: b.replica, nowMs: NOW }),
    ).toMatchObject({
      ok: false,
      reason: 'sender-not-trusted',
    });
    // damaged bytes
    const damaged = Uint8Array.from(made.file);
    damaged[damaged.length - 30] = (damaged[damaged.length - 30] ?? 0) ^ 1;
    expect(
      (await takeExchangeFile(cfgOf(b), { file: damaged, replica: b.replica, nowMs: NOW })).ok,
    ).toBe(false);
    expect(
      await takeExchangeFile(cfgOf(b), { file: new Uint8Array(5), replica: b.replica, nowMs: NOW }),
    ).toMatchObject({
      ok: false,
      reason: 'not-a-file',
    });
  });

  it('a forged change refuses its set whole; the other sets still count', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = w.members as [Member, Member];
    const cfgA = cfgOf(a, { [PLAN]: {}, other: {} });
    const cfgB = cfgOf(b, { [PLAN]: {}, other: {} });
    const good = put(emptyReplica(a.id), PLAN, 'g1', 1);
    const bad = put(emptyReplica(a.id), 'other', 'b1', 1);
    const made = await makeExchangeFile(cfgA, {
      to: b.id,
      replica: a.replica,
      held: { sets: { [PLAN]: good, other: bad } },
      nowMs: NOW,
    });
    if (!made.ok) throw new Error(made.reason);
    // B reads it with another app rule for `other`: nothing of A may be written there
    const cfgStrict = cfgOf(b, { [PLAN]: {}, other: { judge: { mayWrite: () => false } } });
    const took = await takeExchangeFile(cfgStrict, {
      file: made.file,
      replica: b.replica,
      nowMs: NOW,
    });
    if (!took.ok) throw new Error(took.reason);
    expect(rows(took.sets[PLAN])).toEqual(['g1']);
    expect(rows(took.sets.other)).toEqual([]);
    expect(Object.keys(took.refused)).toEqual(['other']);
    void cfgB;
  });

  it('a set that is not registered, or that the sender may not exchange, is dropped', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = w.members as [Member, Member];
    const made = await makeExchangeFile(cfgOf(a, { [PLAN]: {}, other: {} }), {
      to: b.id,
      replica: a.replica,
      held: {
        sets: {
          [PLAN]: put(emptyReplica(a.id), PLAN, 'g1', 1),
          other: put(emptyReplica(a.id), 'other', 'b1', 1),
        },
      },
      nowMs: NOW,
    });
    if (!made.ok) throw new Error(made.reason);
    const took = await takeExchangeFile(cfgOf(b, { [PLAN]: {} }), {
      file: made.file,
      replica: b.replica,
      nowMs: NOW,
    });
    if (!took.ok) throw new Error(took.reason);
    expect(took.dropped['unknown-set']).toBe(1);
    expect(rows(took.sets[PLAN])).toEqual(['g1']);
    const blocked = await takeExchangeFile(
      cfgOf(b, { [PLAN]: { mayExchange: () => false }, other: {} }),
      { file: made.file, replica: b.replica, nowMs: NOW },
    );
    if (!blocked.ok) throw new Error(blocked.reason);
    expect(blocked.dropped['set-not-allowed']).toBe(1);
    expect(rows(blocked.sets.other)).toEqual(['b1']);
    expect(rows(blocked.sets[PLAN])).toEqual([]);
  });

  it('a set the recipient may not read is not put into the file at all', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = w.members as [Member, Member];
    const made = await makeExchangeFile(
      cfgOf(a, { [PLAN]: {}, secret: { mayExchange: (p) => p.device !== b.id } }),
      {
        to: b.id,
        replica: a.replica,
        held: { sets: { secret: put(emptyReplica(a.id), 'secret', 's', 'x') } },
        nowMs: NOW,
      },
    );
    if (!made.ok) throw new Error(made.reason);
    const took = await takeExchangeFile(cfgOf(b, { [PLAN]: {}, secret: {} }), {
      file: made.file,
      replica: b.replica,
      nowMs: NOW,
    });
    if (!took.ok) throw new Error(took.reason);
    expect(rows(took.sets.secret)).toEqual([]);
  });

  it('a notice over the bound or an oversized bad-input is refused when made', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = w.members as [Member, Member];
    expect(
      await makeExchangeFile(cfgOf(a), {
        to: b.id,
        replica: a.replica,
        notice: 'x'.repeat(8001),
        nowMs: NOW,
      }),
    ).toMatchObject({ ok: false, reason: 'bad-input' });
  });
});

describe('stand memory', () => {
  it('only grows, is bounded by peers, and reads back strictly', () => {
    let m = EMPTY_STANDS;
    m = rememberStand(m, 'b', 'plan', { a: 3, b: 1 });
    m = rememberStand(m, 'b', 'plan', { a: 2, c: 4 });
    expect(m.b?.plan).toEqual({ a: 3, b: 1, c: 4 });
    for (let i = 0; i < 300; i += 1) m = rememberStand(m, `p${i}`, 'plan', { a: 1 }, 256);
    expect(Object.keys(m).length).toBeLessThanOrEqual(256);
    expect(m.p299).toBeDefined();
    expect(m.b).toBeUndefined();
    expect(readStandMemory(JSON.parse(JSON.stringify(m)))).toEqual(m);
    for (const bad of [
      null,
      [],
      'x',
      { b: [] },
      { b: { 'bad set': {} } },
      { b: { plan: { a: -1 } } },
      { b: { plan: { a: 1.5 } } },
    ]) {
      expect(readStandMemory(bad)).toBeUndefined();
    }
    expect(readStandMemory(JSON.parse('{"__proto__":{"plan":{}}}'))).toBeUndefined();
  });
});

describe('the payload reader', () => {
  const valid = (text: string): Uint8Array => new TextEncoder().encode(text);
  const base = `{"m":"${fileMark(APP)}","sets":{},"post":[],"notice":null}`;
  const read = (b: Uint8Array) => readExchangePayload(APP, b, {}, () => true);

  it('reads the empty payload and refuses every other spelling', () => {
    expect(read(valid(base))).toBeDefined();
    for (const bad of [
      base.replace('"notice":null', '"notice":1'),
      base.replace('"post":[],', ''),
      base.replace('}', ',"x":1}').replace('}', '}'),
      base.replace('"sets":{}', '"sets":{"bad name":{}}'),
      base.replace('"sets":{}', '"sets":{"a":{"stand":1,"pieces":[]}}'),
      base.replace('"post":[]', '"post":[1]'),
      `{"m":"${fileMark(APP)}","m":"x","sets":{},"post":[],"notice":null}`,
      base.replace('"notice":null', `"notice":"${'x'.repeat(8001)}"`),
      base.replace(fileMark(APP), 'other-xfile:1'),
      '',
      '[]',
    ]) {
      expect(read(valid(bad)), bad).toBeUndefined();
    }
  });

  it('never throws on 3000 seeded damages of a real payload', async () => {
    const w = await world(['A', 'B']);
    const [a, b] = w.members as [Member, Member];
    const made = await makeExchangeFile(cfgOf(a), {
      to: b.id,
      replica: a.replica,
      held: { sets: { [PLAN]: put(emptyReplica(a.id), PLAN, 'r1', 'v') } },
      notice: 'n',
      nowMs: NOW,
    });
    if (!made.ok) throw new Error(made.reason);
    const { openFile } = await import('../../src/core/index.ts');
    const opened = await openFile({
      appId: APP,
      own: { device: b.id, agreement: b.keys.agreement },
      from: { device: a.id, dh: a.intro.dh },
      file: made.file,
    });
    if (!opened.ok) throw new Error(opened.reason);
    const original = opened.payload;
    expect(read(original)).toBeDefined();
    const r = prng(11);
    for (let i = 0; i < 3000; i += 1) {
      const copy = Uint8Array.from(original);
      for (let k = 0; k < 1 + Math.floor(r() * 3); k += 1) {
        copy[Math.floor(r() * copy.length)] = Math.floor(r() * 256);
      }
      const cut = r() < 0.3 ? copy.subarray(0, Math.floor(r() * copy.length)) : copy;
      expect(() => read(cut)).not.toThrow();
    }
  });
});

void generateDeviceKeys;
void publicKeys;
void merge;
