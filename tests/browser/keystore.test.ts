import { describe, expect, it } from 'vitest';
import {
  RECORD_NAMES,
  RELAY_LIMITS,
  KeyStoreError,
  openKeyStore,
  readRecord,
  relayCredentialStore,
  generateDeviceKeys,
  publicKeys,
  signText,
  verifyText,
  importPublicKey,
  type KeyStore,
} from '../../src/index.ts';
import { FakeIdb } from './fake-idb.ts';

const DB = { name: 'device-sync-test' };

async function opened(idb = new FakeIdb()): Promise<{ idb: FakeIdb; store: KeyStore }> {
  const r = await openKeyStore(idb, DB);
  if (!r.ok) throw new Error(`open failed: ${r.reason}`);
  return { idb, store: r.value };
}

describe('openKeyStore', () => {
  it('opens, creates the one store and remembers nothing yet', async () => {
    const { idb, store } = await opened();
    expect([...(idb.dbs.get(DB.name)?.stores.keys() ?? [])]).toEqual(['records']);
    expect(await store.getText('x')).toEqual({ ok: true, value: undefined });
    expect(await store.getKeys('k')).toEqual({ ok: true, value: undefined });
  });

  it('IndexedDB unavailable: no factory, or a factory that throws (private mode)', async () => {
    expect(await openKeyStore(undefined, DB)).toEqual({ ok: false, reason: 'unavailable' });
    const idb = new FakeIdb();
    idb.faults.openThrows = 'SecurityError';
    expect(await openKeyStore(idb, DB)).toEqual({ ok: false, reason: 'unavailable' });
    idb.faults = { openError: 'UnknownError' };
    expect(await openKeyStore(idb, DB)).toEqual({ ok: false, reason: 'unavailable' });
    idb.faults = { openError: 'QuotaExceededError' };
    expect(await openKeyStore(idb, DB)).toEqual({ ok: false, reason: 'quota' });
  });

  it('refuses a bad database name', async () => {
    for (const name of ['', ' x', 'a/b', '-x', 'x'.repeat(101)])
      expect(await openKeyStore(new FakeIdb(), { name })).toEqual({
        ok: false,
        reason: 'bad-name',
      });
  });

  it('a database written by a newer version is refused, not damaged', async () => {
    const idb = new FakeIdb();
    const req = idb.open(DB.name, 2);
    await new Promise((r) => {
      req.onupgradeneeded = () => undefined;
      req.onsuccess = () => r(null);
    });
    (req.result as { close(): void }).close();
    expect(await openKeyStore(idb, DB)).toEqual({ ok: false, reason: 'unsupported-version' });
  });

  it('a foreign database of the same name without our store is refused', async () => {
    const idb = new FakeIdb();
    const req = idb.open(DB.name, 1);
    await new Promise((r) => {
      req.onupgradeneeded = () => undefined; // creates no store
      req.onsuccess = () => r(null);
    });
    (req.result as { close(): void }).close();
    expect(await openKeyStore(idb, DB)).toEqual({ ok: false, reason: 'foreign-database' });
    expect(idb.connections(DB.name)).toBe(0);
  });

  it('blocked: answers `blocked`, and a late success leaves no connection behind', async () => {
    const idb = new FakeIdb();
    // A stubborn old tab on a database that still needs its first upgrade is not possible at version 1;
    // the layer reacts to the event itself, so drive the event directly.
    const real = idb.open.bind(idb);
    idb.open = (name, version) => {
      const req = real(name, version);
      queueMicrotask(() => req.onblocked?.({}));
      return req;
    };
    // The block event comes before the success event of the fake (both are ticks, block first).
    const r = await openKeyStore(idb, DB);
    expect(r).toEqual({ ok: false, reason: 'blocked' });
    await new Promise((res) => setTimeout(res, 20));
    expect(idb.connections(DB.name)).toBe(0);
  });
});

describe('text records', () => {
  it('stores and reads back; overwrite; remove (also of a record that is not there)', async () => {
    const { store } = await opened();
    expect(await store.putText(RECORD_NAMES.deviceId, 'device-1')).toEqual({
      ok: true,
      value: null,
    });
    expect(await store.getText(RECORD_NAMES.deviceId)).toEqual({ ok: true, value: 'device-1' });
    await store.putText(RECORD_NAMES.deviceId, 'device-2');
    expect(await store.getText(RECORD_NAMES.deviceId)).toEqual({ ok: true, value: 'device-2' });
    expect(await store.remove(RECORD_NAMES.deviceId)).toEqual({ ok: true, value: null });
    expect(await store.getText(RECORD_NAMES.deviceId)).toEqual({ ok: true, value: undefined });
    expect(await store.remove('never-there')).toEqual({ ok: true, value: null });
  });

  it('survives a reopen (a second store on the same data)', async () => {
    const { idb, store } = await opened();
    await store.putText('t', 'kept');
    store.close();
    const again = await opened(idb);
    expect(await again.store.getText('t')).toEqual({ ok: true, value: 'kept' });
  });

  it('refuses bad names and bad values with codes and writes nothing', async () => {
    const { idb, store } = await opened();
    expect(await store.putText('a b', 'x')).toEqual({ ok: false, reason: 'bad-name' });
    expect(await store.getText('')).toEqual({ ok: false, reason: 'bad-name' });
    expect(await store.remove('../x')).toEqual({ ok: false, reason: 'bad-name' });
    expect(await store.putText('t', 5 as unknown as string)).toEqual({
      ok: false,
      reason: 'bad-value',
    });
    expect(await store.putText('t', 'x'.repeat(8193))).toEqual({ ok: false, reason: 'bad-value' });
    expect(idb.raw(DB.name, 't')).toBeUndefined();
    expect((await store.putText('t', 'x'.repeat(8192))).ok).toBe(true);
  });

  it('is stored as one versioned record', async () => {
    const { idb, store } = await opened();
    await store.putText('t', 'hello');
    expect(idb.raw(DB.name, 't')).toEqual({ v: 1, kind: 'text', text: 'hello' });
  });
});

describe('strict reading of what is stored (never throws)', () => {
  const kinds: Array<[string, unknown, string]> = [
    ['a string', 'text', 'corrupt'],
    ['a number', 7, 'corrupt'],
    ['null', null, 'corrupt'],
    ['an array', [], 'corrupt'],
    ['no version', { kind: 'text', text: 'x' }, 'corrupt'],
    ['version 0', { v: 0, kind: 'text', text: 'x' }, 'corrupt'],
    ['version as text', { v: '1', kind: 'text', text: 'x' }, 'corrupt'],
    ['a newer version', { v: 2, kind: 'text', text: 'x' }, 'unsupported-version'],
    ['an unknown kind', { v: 1, kind: 'blob', text: 'x' }, 'corrupt'],
    ['an extra member', { v: 1, kind: 'text', text: 'x', extra: 1 }, 'corrupt'],
    ['a missing member', { v: 1, kind: 'text' }, 'corrupt'],
    ['text that is not text', { v: 1, kind: 'text', text: 5 }, 'corrupt'],
    ['text over the limit', { v: 1, kind: 'text', text: 'x'.repeat(8193) }, 'corrupt'],
    ['a keys record', { v: 1, kind: 'keys', signing: {}, agreement: {} }, 'corrupt'],
  ];
  for (const [label, value, reason] of kinds) {
    it(`${label}: ${reason}`, async () => {
      const { idb, store } = await opened();
      await store.putText('t', 'x');
      idb.plant(DB.name, 't', value);
      expect(await store.getText('t')).toEqual({ ok: false, reason });
      expect(readRecord(value, 'text')).toEqual({ ok: false, reason });
    });
  }

  it('a record of the other kind is `wrong-kind`; the record is not touched', async () => {
    const { idb, store } = await opened();
    await store.putText('t', 'x');
    expect(await store.getKeys('t')).toEqual({ ok: false, reason: 'wrong-kind' });
    expect(idb.raw(DB.name, 't')).toEqual({ v: 1, kind: 'text', text: 'x' });
  });

  it('a corrupt record can still be removed and replaced', async () => {
    const { idb, store } = await opened();
    await store.putText('t', 'x');
    idb.plant(DB.name, 't', { junk: true });
    expect((await store.getText('t')).ok).toBe(false);
    expect((await store.putText('t', 'fresh')).ok).toBe(true);
    expect(await store.getText('t')).toEqual({ ok: true, value: 'fresh' });
  });

  it('prototype tricks in a stored value are refused', () => {
    const v = JSON.parse('{"v":1,"kind":"text","text":"x","__proto__":{"a":1}}');
    expect(readRecord(v, 'text').ok).toBe(false);
    class Fake {
      v = 1;
      kind = 'text';
      text = 'x';
    }
    expect(readRecord(new Fake(), 'text')).toEqual({ ok: false, reason: 'corrupt' });
  });
});

describe('key records', () => {
  it('stores CryptoKey objects (no JWK), reads them back usable for signing and ECDH', async () => {
    const { idb, store } = await opened();
    const keys = await generateDeviceKeys();
    expect(await store.putKeys(RECORD_NAMES.deviceKeys, keys)).toEqual({ ok: true, value: null });
    // What is stored is structured-cloned keys, not exported text:
    const raw = idb.raw(DB.name, RECORD_NAMES.deviceKeys) as Record<string, any>;
    expect(Object.keys(raw).sort()).toEqual(['agreement', 'kind', 'signing', 'v']);
    expect(raw['signing'].privateKey.type).toBe('private');
    expect(raw['signing'].privateKey.extractable).toBe(false);
    expect(JSON.stringify(raw)).not.toContain('"d"');

    const r = await store.getKeys(RECORD_NAMES.deviceKeys);
    if (!r.ok || !r.value) throw new Error('read failed');
    const pub = await publicKeys(r.value);
    expect(pub).toEqual(await publicKeys(keys));
    // sign with the restored private key, verify with the point
    const sig = await signText(r.value.signing.privateKey, 'some text');
    const vk = await importPublicKey(pub.sig, 'sig');
    expect(await verifyText(vk as CryptoKey, 'some text', sig)).toBe(true);
    // ECDH with the restored private key gives the same secret as the original
    const other = await generateDeviceKeys();
    const a = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: other.agreement.publicKey },
      r.value.agreement.privateKey,
      256,
    );
    const b = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: other.agreement.publicKey },
      keys.agreement.privateKey,
      256,
    );
    expect(new Uint8Array(a)).toEqual(new Uint8Array(b));
  });

  it('the private key cannot be exported from what was read', async () => {
    const { store } = await opened();
    await store.putKeys('k', await generateDeviceKeys());
    const r = await store.getKeys('k');
    if (!r.ok || !r.value) throw new Error('read failed');
    await expect(crypto.subtle.exportKey('jwk', r.value.signing.privateKey)).rejects.toThrow();
  });

  it('refuses to store an extractable private key (a backup copy would exist)', async () => {
    const { idb, store } = await opened();
    const leaky = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    const ok = await generateDeviceKeys();
    expect(await store.putKeys('k', { signing: leaky, agreement: ok.agreement })).toEqual({
      ok: false,
      reason: 'extractable-private-key',
    });
    const leakyDh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ]);
    expect(await store.putKeys('k', { signing: ok.signing, agreement: leakyDh })).toEqual({
      ok: false,
      reason: 'extractable-private-key',
    });
    expect(idb.raw(DB.name, 'k')).toBeUndefined();
  });

  it('refuses values that are not device keys (bad-value), keys of the wrong kind included', async () => {
    const { store } = await opened();
    const keys = await generateDeviceKeys();
    expect(await store.putKeys('k', {} as never)).toEqual({ ok: false, reason: 'bad-value' });
    expect(await store.putKeys('k', null as never)).toEqual({ ok: false, reason: 'bad-value' });
    expect(
      await store.putKeys('k', { signing: keys.agreement, agreement: keys.agreement }),
    ).toEqual({
      ok: false,
      reason: 'bad-value',
    });
    expect(await store.putKeys('k', { signing: keys.signing, agreement: keys.signing })).toEqual({
      ok: false,
      reason: 'bad-value',
    });
    const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
    ]);
    expect(
      await store.putKeys('k', {
        signing: { privateKey: aes, publicKey: aes } as never,
        agreement: keys.agreement,
      }),
    ).toEqual({ ok: false, reason: 'bad-value' });
  });

  it('a stored record whose private key is extractable is corrupt, not returned', async () => {
    const { idb, store } = await opened();
    const keys = await generateDeviceKeys();
    await store.putKeys('k', keys);
    const leaky = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    const rec = idb.raw(DB.name, 'k') as Record<string, any>;
    idb.plant(DB.name, 'k', {
      ...rec,
      signing: { privateKey: leaky.privateKey, publicKey: leaky.publicKey },
    });
    expect(await store.getKeys('k')).toEqual({ ok: false, reason: 'corrupt' });
  });

  it('damaged key records are corrupt (members, shapes, curves)', async () => {
    const { idb, store } = await opened();
    const keys = await generateDeviceKeys();
    await store.putKeys('k', keys);
    const good = idb.raw(DB.name, 'k') as Record<string, any>;
    const p384 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, [
      'sign',
      'verify',
    ]);
    const damaged: unknown[] = [
      { ...good, extra: 1 },
      { v: 1, kind: 'keys', signing: good['signing'] },
      { ...good, signing: { privateKey: good['signing'].privateKey } },
      { ...good, signing: { ...good['signing'], x: 1 } },
      { ...good, signing: { privateKey: 'x', publicKey: 'y' } },
      { ...good, signing: { privateKey: p384.privateKey, publicKey: p384.publicKey } },
      { ...good, agreement: good['signing'] },
      { ...good, signing: null },
    ];
    for (const d of damaged) {
      idb.plant(DB.name, 'k', d);
      expect(await store.getKeys('k')).toEqual({ ok: false, reason: 'corrupt' });
    }
    idb.plant(DB.name, 'k', good);
    expect((await store.getKeys('k')).ok).toBe(true);
  });
});

describe('failures of the database', () => {
  it('quota on a write is `quota` and the old value stays', async () => {
    const { idb, store } = await opened();
    await store.putText('t', 'old');
    idb.faults.commitError = 'QuotaExceededError';
    expect(await store.putText('t', 'new')).toEqual({ ok: false, reason: 'quota' });
    expect(await store.getText('t')).toEqual({ ok: true, value: 'old' });
  });

  it('any other abort is `aborted` or `failed`, never an exception', async () => {
    const { store } = await opened();
    store as unknown as object;
    const idb = new FakeIdb();
    const o = await opened(idb);
    idb.faults.commitError = 'AbortError';
    expect(await o.store.putText('t', 'x')).toEqual({ ok: false, reason: 'aborted' });
    idb.faults.commitError = 'UnknownError';
    expect(await o.store.putText('t', 'x')).toEqual({ ok: false, reason: 'aborted' });
  });

  it('a concurrent upgrade by another tab closes this connection; later calls say `closed`', async () => {
    const { idb, store } = await opened();
    await store.putText('t', 'x');
    const up = idb.open(DB.name, 2);
    await new Promise((r) => {
      up.onupgradeneeded = () => undefined;
      up.onsuccess = () => r(null);
    });
    expect(store.isOpen()).toBe(false);
    expect(await store.getText('t')).toEqual({ ok: false, reason: 'closed' });
    expect(await store.putText('t', 'y')).toEqual({ ok: false, reason: 'closed' });
    expect(await store.remove('t')).toEqual({ ok: false, reason: 'closed' });
  });

  it('close() is idempotent and later calls say `closed`', async () => {
    const { idb, store } = await opened();
    store.close();
    store.close();
    expect(idb.connections(DB.name)).toBe(0);
    expect(await store.getKeys('k')).toEqual({ ok: false, reason: 'closed' });
  });

  it('a write that completes is written: the answer comes after the commit, not after the request', async () => {
    const { idb, store } = await opened();
    // The fake aborts at commit time; a layer that answered on the request would call this a success.
    idb.faults.commitError = 'QuotaExceededError';
    const r = await store.putText('t', 'x');
    expect(r.ok).toBe(false);
    expect(idb.raw(DB.name, 't')).toBeUndefined();
  });
});

describe('wipe', () => {
  it('deletes every record and the database, and closes the store', async () => {
    const { idb, store } = await opened();
    await store.putText('a', '1');
    await store.putKeys('k', await generateDeviceKeys());
    expect(await store.wipe()).toEqual({ ok: true, value: null });
    expect(idb.dbs.has(DB.name)).toBe(false);
    expect(store.isOpen()).toBe(false);
    expect(await store.getText('a')).toEqual({ ok: false, reason: 'closed' });
    // a fresh open finds nothing: the app sees "device lost"
    const again = await opened(idb);
    expect(await again.store.getKeys('k')).toEqual({ ok: true, value: undefined });
  });

  it('with another tab holding the database: the records are gone even though the delete is blocked', async () => {
    const idb = new FakeIdb();
    const { store } = await opened(idb);
    await store.putText('a', '1');
    idb.faults.ignoreVersionChange = true;
    const tab = await idb.otherTab(DB.name);
    const r = await store.wipe();
    expect(r.ok).toBe(true); // clear succeeded; the delete is only blocked
    expect(idb.raw(DB.name, 'a')).toBeUndefined();
    tab.close();
  });

  it('when both the clear and the delete fail, it says so', async () => {
    const idb = new FakeIdb();
    const { store } = await opened(idb);
    idb.faults.commitError = 'QuotaExceededError';
    idb.faults.ignoreVersionChange = true;
    const tab = await idb.otherTab(DB.name);
    const r = await store.wipe();
    expect(r).toEqual({ ok: false, reason: 'blocked' });
    tab.close();
  });
});

describe('relayCredentialStore (the RelayClient interface)', () => {
  it('get / set / remove one text record', async () => {
    const { store } = await opened();
    const c = relayCredentialStore(store);
    expect(await c.get()).toBeUndefined();
    await c.set('{"v":1}');
    expect(await c.get()).toBe('{"v":1}');
    await store.putText('other', 'x');
    await c.remove();
    expect(await c.get()).toBeUndefined();
    expect(await store.getText('other')).toEqual({ ok: true, value: 'x' });
  });

  it('keeps a credential of the relay limit size', async () => {
    const { store } = await opened();
    const c = relayCredentialStore(store);
    expect(RELAY_LIMITS).toBeDefined();
    await c.set('x'.repeat(2_000));
    expect(await c.get()).toBe('x'.repeat(2_000));
  });

  it('failures are thrown as a KeyStoreError with the code (the client reports `storage`)', async () => {
    const { idb, store } = await opened();
    const c = relayCredentialStore(store);
    idb.faults.commitError = 'QuotaExceededError';
    await expect(c.set('x')).rejects.toMatchObject({ code: 'quota' });
    await expect(c.set('x')).resolves.toBeUndefined();
    idb.plant(DB.name, RECORD_NAMES.relayCredential, { junk: 1 });
    const err = await Promise.resolve(c.get()).catch((e) => e);
    expect(err).toBeInstanceOf(KeyStoreError);
    expect((err as KeyStoreError).code).toBe('corrupt');
    store.close();
    await expect(c.get()).rejects.toMatchObject({ code: 'closed' });
    await expect(c.remove()).rejects.toMatchObject({ code: 'closed' });
  });

  it('a RelayClient with this store treats a vanished store as not enrolled', async () => {
    const { RelayClient } = await import('../../src/index.ts');
    const { store } = await opened();
    const client = new RelayClient({
      baseUrl: 'https://relay.example',
      appId: 'demo',
      fetch: async () => new Response('{}', { status: 500 }),
      store: relayCredentialStore(store),
      clock: () => 0,
    });
    expect(await client.state()).toBe('none');
    await store.wipe();
    expect(await client.state()).toBe('none');
    expect(await client.deviceId()).toBeUndefined();
  });
});
