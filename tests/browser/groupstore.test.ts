// The group state at rest in the key store, on the in-memory IndexedDB.
import { describe, expect, it } from 'vitest';
import {
  BROWSER_LIMITS,
  RECORD_NAMES,
  generateWrapKey,
  getGroupState,
  groupStateRecordName,
  loadOrCreateWrapKey,
  maxSealedStateChars,
  openKeyStore,
  putGroupState,
  readGroupState,
  readRecord,
  storeGroupState,
  type GroupState,
  type KeyStore,
} from '../../src/index.ts';
import { FakeIdb } from './fake-idb.ts';

const APP = 'syncdemo';
const DB = { name: 'group-at-rest' };
const random = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

async function opened(idb = new FakeIdb()): Promise<{ idb: FakeIdb; store: KeyStore }> {
  const r = await openKeyStore(idb, DB);
  if (!r.ok) throw new Error(r.reason);
  return { idb, store: r.value };
}

async function stateOf(set: string, epoch = 1): Promise<GroupState> {
  const key = Buffer.from(random(32)).toString('base64url');
  const text = storeGroupState(APP, {
    dataSet: set,
    floor: 0,
    keys: [{ epoch, author: 'dev-a', key, audience: ['dev-a'], kid: '' }],
  });
  const s = await readGroupState(APP, text);
  if (!s) throw new Error('state');
  return s;
}

describe('wrap key', () => {
  it('is generated non-extractable, AES-256-GCM, encrypt and decrypt only', async () => {
    const r = await generateWrapKey();
    if (!r.ok) throw new Error(r.reason);
    expect(r.value.extractable).toBe(false);
    expect(r.value.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect([...r.value.usages].sort()).toEqual(['decrypt', 'encrypt']);
    for (const fmt of ['raw', 'jwk'] as const)
      await expect(crypto.subtle.exportKey(fmt, r.value)).rejects.toThrow();
  });

  it('answers with codes when WebCrypto is missing or fails', async () => {
    expect(await generateWrapKey({} as never)).toEqual({ ok: false, reason: 'unsupported' });
    expect(
      await generateWrapKey({
        subtle: {
          generateKey: () => {
            throw new Error('x');
          },
        },
      } as never),
    ).toEqual({ ok: false, reason: 'failed' });
    // a holder that returns an extractable key is not trusted
    const ext = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
      'encrypt',
      'decrypt',
    ]);
    expect(await generateWrapKey({ subtle: { generateKey: async () => ext } } as never)).toEqual({
      ok: false,
      reason: 'failed',
    });
  });

  it('is kept by the store as a structured-cloned key and read back usable', async () => {
    const { idb, store } = await opened();
    const made = await loadOrCreateWrapKey(store);
    if (!made.ok) throw new Error(made.reason);
    expect(made.value.created).toBe(true);
    const raw = idb.raw(DB.name, RECORD_NAMES.groupWrapKey) as Record<string, unknown>;
    expect(Object.keys(raw).sort()).toEqual(['key', 'kind', 'v']);
    const again = await loadOrCreateWrapKey(store);
    if (!again.ok) throw new Error(again.reason);
    expect(again.value.created).toBe(false);
    const iv = new Uint8Array(12);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      made.value.key,
      new Uint8Array(5),
    );
    expect(
      (await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, again.value.key, ct)).byteLength,
    ).toBe(5);
  });

  it('an extractable key, a key of another kind and a planted record are refused', async () => {
    const { idb, store } = await opened();
    const ext = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
      'encrypt',
      'decrypt',
    ]);
    expect(await store.putWrapKey('w', ext)).toEqual({
      ok: false,
      reason: 'extractable-private-key',
    });
    const hmac = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, [
      'sign',
    ]);
    expect(await store.putWrapKey('w', hmac)).toEqual({ ok: false, reason: 'bad-value' });
    expect(await store.putWrapKey('w', null as never)).toEqual({ ok: false, reason: 'bad-value' });
    expect(await store.putWrapKey('bad name', ext)).toEqual({ ok: false, reason: 'bad-name' });
    const good = await generateWrapKey();
    if (!good.ok) throw new Error('key');
    await store.putWrapKey('w', good.value);
    for (const planted of [
      { v: 1, kind: 'wrapkey', key: ext },
      { v: 1, kind: 'wrapkey', key: 'AAAA' },
      { v: 1, kind: 'wrapkey', key: good.value, extra: 1 },
      { v: 1, kind: 'wrapkey' },
    ]) {
      idb.plant(DB.name, 'w', planted);
      expect(await store.getWrapKey('w')).toEqual({ ok: false, reason: 'corrupt' });
    }
    idb.plant(DB.name, 'w', { v: 2, kind: 'wrapkey', key: good.value });
    expect(await store.getWrapKey('w')).toEqual({ ok: false, reason: 'unsupported-version' });
    await store.putText('t', 'x');
    expect(await store.getWrapKey('t')).toEqual({ ok: false, reason: 'wrong-kind' });
    await store.putWrapKey('w2', good.value);
    expect(await store.getText('w2')).toEqual({ ok: false, reason: 'wrong-kind' });
  });
});

describe('sealed records', () => {
  it('hold more than a text record, up to sealedMax, and no more', async () => {
    const { store } = await opened();
    const big = 'x'.repeat(BROWSER_LIMITS.textMax + 1);
    expect(await store.putText('t', big)).toEqual({ ok: false, reason: 'bad-value' });
    expect(await store.putSealed('s', big)).toEqual({ ok: true, value: null });
    expect(await store.getSealed('s')).toEqual({ ok: true, value: big });
    expect(await store.putSealed('s', 'x'.repeat(BROWSER_LIMITS.sealedMax + 1))).toEqual({
      ok: false,
      reason: 'bad-value',
    });
    expect(await store.getText('s')).toEqual({ ok: false, reason: 'wrong-kind' });
    expect(readRecord({ v: 1, kind: 'sealed', text: 5 }, 'sealed')).toEqual({
      ok: false,
      reason: 'corrupt',
    });
    expect(readRecord({ v: 1, kind: 'sealed', text: 'x', more: 1 }, 'sealed')).toEqual({
      ok: false,
      reason: 'corrupt',
    });
  });

  it('the largest sealed state under the default limits fits in sealedMax', () => {
    expect(maxSealedStateChars()).toBeLessThanOrEqual(BROWSER_LIMITS.sealedMax);
  });
});

describe('store and load of the sealed state', () => {
  it('one record per data set, nothing readable in it, survives a new connection', async () => {
    const idb = new FakeIdb();
    const { store } = await opened(idb);
    const made = await loadOrCreateWrapKey(store);
    if (!made.ok) throw new Error(made.reason);
    const key = made.value.key;
    const a = await stateOf('alpha');
    const b = await stateOf('beta');
    expect(await getGroupState(store, key, 'alpha', { appId: APP })).toEqual({
      ok: true,
      value: undefined,
    });
    expect(await putGroupState(store, key, a, { appId: APP, random })).toEqual({
      ok: true,
      value: null,
    });
    expect(await putGroupState(store, key, b, { appId: APP, random })).toEqual({
      ok: true,
      value: null,
    });
    const rawA = JSON.stringify(idb.raw(DB.name, groupStateRecordName(APP, 'alpha')));
    expect(rawA).not.toContain(a.keys[0]!.key);
    expect(groupStateRecordName(APP, 'alpha')).not.toBe(groupStateRecordName(APP, 'beta'));
    expect(groupStateRecordName(APP, 'alpha')).not.toBe(groupStateRecordName('otherapp', 'alpha'));
    store.close();
    const again = await opened(idb);
    const key2 = await loadOrCreateWrapKey(again.store);
    if (!key2.ok) throw new Error(key2.reason);
    expect(key2.value.created).toBe(false);
    expect(await getGroupState(again.store, key2.value.key, 'alpha', { appId: APP })).toEqual({
      ok: true,
      value: a,
    });
    expect(await getGroupState(again.store, key2.value.key, 'beta', { appId: APP })).toEqual({
      ok: true,
      value: b,
    });
  });

  it('a replaced wrap key, a planted record and a record of another set give codes', async () => {
    const { idb, store } = await opened();
    const key = (await generateWrapKey()) as { ok: true; value: CryptoKey };
    const other = (await generateWrapKey()) as { ok: true; value: CryptoKey };
    const a = await stateOf('alpha');
    await putGroupState(store, key.value, a, { appId: APP, random });
    expect(await getGroupState(store, other.value, 'alpha', { appId: APP })).toEqual({
      ok: false,
      reason: 'cannot-open',
    });
    // the sealed text of alpha put under the record of beta: refused as another data set
    const alphaText = (await store.getSealed(groupStateRecordName(APP, 'alpha'))) as {
      ok: true;
      value: string;
    };
    await store.putSealed(groupStateRecordName(APP, 'beta'), alphaText.value);
    expect(await getGroupState(store, key.value, 'beta', { appId: APP })).toEqual({
      ok: false,
      reason: 'wrong-data-set',
    });
    idb.plant(DB.name, groupStateRecordName(APP, 'alpha'), { v: 1, kind: 'text', text: 'x' });
    expect(await getGroupState(store, key.value, 'alpha', { appId: APP })).toEqual({
      ok: false,
      reason: 'wrong-kind',
    });
    // refusals of the sealing layer come through as their codes, and nothing is written
    const before = await store.getSealed(groupStateRecordName(APP, 'gamma'));
    expect(
      await putGroupState(store, key.value, await stateOf('gamma'), {
        appId: APP,
        random: () => new Uint8Array(1),
      }),
    ).toEqual({ ok: false, reason: 'bad-random' });
    expect(await store.getSealed(groupStateRecordName(APP, 'gamma'))).toEqual(before);
  });

  it('rollback of the record is NOT noticed: the older sealed state opens', async () => {
    const { store } = await opened();
    const k = (await generateWrapKey()) as { ok: true; value: CryptoKey };
    const old = await stateOf('alpha', 1);
    const fresh = await stateOf('alpha', 2);
    const name = groupStateRecordName(APP, 'alpha');
    await putGroupState(store, k.value, old, { appId: APP, random });
    const oldText = (await store.getSealed(name)) as { ok: true; value: string };
    await putGroupState(store, k.value, fresh, { appId: APP, random });
    await store.putSealed(name, oldText.value);
    expect(await getGroupState(store, k.value, 'alpha', { appId: APP })).toEqual({
      ok: true,
      value: old,
    });
  });
});
