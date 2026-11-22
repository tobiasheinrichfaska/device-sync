// The fake is part of the evidence: these cases pin down what it does, so a keystore test that passes
// against it means something.
import { describe, expect, it } from 'vitest';
import type { IdbDatabaseLike, IdbFactoryLike } from '../../src/browser/index.ts';
import { FakeIdb } from './fake-idb.ts';

// A real IDBFactory fits the structural type (compile-time check; never run).
export const realFits = (f: IDBFactory): IdbFactoryLike => f;
export const realDbFits = (d: IDBDatabase): IdbDatabaseLike => d;

async function open(idb: FakeIdb, name = 'a', version = 1): Promise<IdbDatabaseLike> {
  const req = idb.open(name, version);
  return new Promise((resolve, reject) => {
    req.onupgradeneeded = () => {
      const db = req.result as IdbDatabaseLike;
      if (!db.objectStoreNames.contains('records')) db.createObjectStore('records');
    };
    req.onsuccess = () => resolve(req.result as IdbDatabaseLike);
    req.onerror = () => reject(req.error);
  });
}

function tx(db: IdbDatabaseLike, mode: 'readonly' | 'readwrite', f: (os: any) => any) {
  return new Promise<{ done: 'complete' | 'abort'; result: unknown; error: unknown }>((resolve) => {
    const t = db.transaction('records', mode);
    let result: unknown;
    t.oncomplete = () => resolve({ done: 'complete', result, error: undefined });
    t.onabort = () => resolve({ done: 'abort', result, error: t.error });
    const r = f(t.objectStore('records'));
    r.onsuccess = () => (result = r.result);
  });
}

describe('the fake IndexedDB', () => {
  it('persists a committed write and clones the value', async () => {
    const idb = new FakeIdb();
    const db = await open(idb);
    const value = { n: 1 };
    expect((await tx(db, 'readwrite', (os) => os.put(value, 'k'))).done).toBe('complete');
    value.n = 2;
    const r = await tx(db, 'readonly', (os) => os.get('k'));
    expect(r.result).toEqual({ n: 1 });
    expect(r.result).not.toBe(value);
  });

  it('a value that cannot be cloned is an error and writes nothing', async () => {
    const idb = new FakeIdb();
    const db = await open(idb);
    const r = await tx(db, 'readwrite', (os) => os.put({ f: () => 1 }, 'k')).catch((e) => e);
    // put throws synchronously inside the op: the transaction aborts with DataCloneError
    expect((r as { done: string }).done).toBe('abort');
    expect(idb.raw('a', 'k')).toBeUndefined();
  });

  it('an aborted transaction leaves no trace', async () => {
    const idb = new FakeIdb();
    const db = await open(idb);
    idb.faults.commitError = 'QuotaExceededError';
    const r = await tx(db, 'readwrite', (os) => os.put('x', 'k'));
    expect(r.done).toBe('abort');
    expect((r.error as { name: string }).name).toBe('QuotaExceededError');
    expect(idb.raw('a', 'k')).toBeUndefined();
  });

  it('a read-only transaction refuses writes', async () => {
    const db = await open(new FakeIdb());
    expect(() =>
      db.transaction('records', 'readonly').objectStore('records').put(1, 'k'),
    ).toThrow();
  });

  it('a closed connection refuses new transactions; a missing store is NotFound', async () => {
    const db = await open(new FakeIdb());
    expect(() => db.transaction('nope', 'readonly')).toThrow();
    db.close();
    expect(() => db.transaction('records', 'readonly')).toThrow();
  });

  it('opening an older version than stored fails with VersionError', async () => {
    const idb = new FakeIdb();
    await open(idb, 'a', 2);
    await expect(open(idb, 'a', 1)).rejects.toMatchObject({ name: 'VersionError' });
  });

  it('an upgrade asks other connections to close; one that does not makes it `blocked`', async () => {
    const idb = new FakeIdb();
    const tab = await idb.otherTab('a');
    const polite = idb.open('a', 2);
    await new Promise((r) => {
      polite.onsuccess = () => r(null);
      polite.onupgradeneeded = () => undefined;
    });
    expect(tab.closed).toBe(true);

    const idb2 = new FakeIdb();
    idb2.faults.ignoreVersionChange = true;
    const stubborn = await idb2.otherTab('a');
    const req = idb2.open('a', 2);
    const blocked = await new Promise<boolean>((resolve) => {
      req.onblocked = () => resolve(true);
      req.onsuccess = () => resolve(false);
    });
    expect(blocked).toBe(true);
    stubborn.close();
  });

  it('deleteDatabase waits for open connections (blocked), then removes the data', async () => {
    const idb = new FakeIdb();
    const db = await open(idb);
    await tx(db, 'readwrite', (os) => os.put('x', 'k'));
    idb.faults.ignoreVersionChange = true;
    db.onversionchange = null;
    const del = idb.deleteDatabase('a');
    const blocked = await new Promise<boolean>((resolve) => {
      del.onblocked = () => resolve(true);
      del.onsuccess = () => resolve(false);
    });
    expect(blocked).toBe(true);
    db.close();
    await new Promise((r) => (del.onsuccess = () => r(null)));
    expect(idb.dbs.has('a')).toBe(false);
  });

  it('open can throw or fail on demand', async () => {
    const idb = new FakeIdb();
    idb.faults.openThrows = 'SecurityError';
    expect(() => idb.open('a', 1)).toThrow();
    idb.faults = { openError: 'UnknownError' };
    await expect(open(idb)).rejects.toMatchObject({ name: 'UnknownError' });
  });
});
