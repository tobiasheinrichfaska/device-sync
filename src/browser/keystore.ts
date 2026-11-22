import type { DeviceKeys } from '../core/keys.ts';
import { BROWSER_LIMITS, fail, isName, pass, type BrowserResult } from './limits.ts';
import {
  errorName,
  type IdbDatabaseLike,
  type IdbFactoryLike,
  type IdbObjectStoreLike,
  type IdbRequestLike,
} from './idb.ts';

/** The one object store of the database. */
export const STORE_NAME = 'records';

/** Names this package's own callers use (any other valid name works too). */
export const RECORD_NAMES = {
  deviceKeys: 'device-keys',
  deviceId: 'device-id',
  relayCredential: 'relay-credential',
} as const;

export type StoreReason =
  | 'unavailable'
  | 'blocked'
  | 'quota'
  | 'aborted'
  | 'closed'
  | 'bad-name'
  | 'bad-value'
  | 'extractable-private-key'
  | 'corrupt'
  | 'wrong-kind'
  | 'unsupported-version'
  | 'foreign-database'
  | 'failed';

export type StoreResult<T> = BrowserResult<T, StoreReason>;

export interface KeyStore {
  /** The device's key pairs, or undefined when there is no record of that name. */
  getKeys(name: string): Promise<StoreResult<DeviceKeys | undefined>>;
  /** Stores the pairs as structured-cloned `CryptoKey` objects (never as JWK). */
  putKeys(name: string, keys: DeviceKeys): Promise<StoreResult<null>>;
  getText(name: string): Promise<StoreResult<string | undefined>>;
  putText(name: string, text: string): Promise<StoreResult<null>>;
  /** Removes one record (no error when it does not exist). */
  remove(name: string): Promise<StoreResult<null>>;
  /** Deletes every record and then the database itself. The store is closed afterwards. */
  wipe(): Promise<StoreResult<null>>;
  /** Closes the connection; every later call answers `closed`. */
  close(): void;
  /** False once closed, by `close`, `wipe` or a version change from another tab. */
  isOpen(): boolean;
}

// ── records ──────────────────────────────────────────────────────────────────────────────────────

const plain = (v: unknown): v is Record<string, unknown> => {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
};

const sameMembers = (o: Record<string, unknown>, names: readonly string[]): boolean => {
  const keys = Object.keys(o);
  return keys.length === names.length && names.every((n) => Object.hasOwn(o, n));
};

interface KeyShape {
  readonly type: 'private' | 'public';
  readonly name: 'ECDSA' | 'ECDH';
  /** Required usage; none for a public ECDH key (WebCrypto gives it no usages). */
  readonly usage: string | undefined;
}

/** Duck type of a P-256 `CryptoKey`. A private half must not be extractable. */
function keyProblem(k: unknown, want: KeyShape): 'bad' | 'extractable' | undefined {
  if (typeof k !== 'object' || k === null) return 'bad';
  const key = k as {
    type?: unknown;
    extractable?: unknown;
    algorithm?: { name?: unknown; namedCurve?: unknown };
    usages?: unknown;
  };
  if (key.type !== want.type || typeof key.extractable !== 'boolean') return 'bad';
  if (key.algorithm?.name !== want.name || key.algorithm?.namedCurve !== 'P-256') return 'bad';
  if (!Array.isArray(key.usages)) return 'bad';
  if (want.usage !== undefined && !key.usages.includes(want.usage)) return 'bad';
  if (want.type === 'private' && key.extractable) return 'extractable';
  return undefined;
}

const SHAPES = {
  signing: {
    privateKey: { type: 'private', name: 'ECDSA', usage: 'sign' },
    publicKey: { type: 'public', name: 'ECDSA', usage: 'verify' },
  },
  agreement: {
    privateKey: { type: 'private', name: 'ECDH', usage: 'deriveBits' },
    publicKey: { type: 'public', name: 'ECDH', usage: undefined },
  },
} as const satisfies Record<string, Record<string, KeyShape>>;

/** Checks the four keys of `DeviceKeys` (a value the caller made). */
function keysProblem(keys: unknown): 'bad' | 'extractable' | undefined {
  if (typeof keys !== 'object' || keys === null) return 'bad';
  const k = keys as Record<string, Record<string, unknown> | undefined>;
  for (const pair of ['signing', 'agreement'] as const) {
    for (const half of ['privateKey', 'publicKey'] as const) {
      const shape = SHAPES[pair][half];
      const p = keyProblem(k[pair]?.[half], shape);
      if (p) return p;
    }
  }
  return undefined;
}

/**
 * Strict reader of one stored value. Anything that is not exactly a record of this schema is `corrupt`
 * (a foreign write, a damaged value, an extractable private key); a newer record version is
 * `unsupported-version`; a record of the other kind is `wrong-kind`.
 */
export function readRecord(
  value: unknown,
  kind: 'text' | 'keys',
): StoreResult<string | DeviceKeys> {
  if (!plain(value)) return fail('corrupt');
  const v = value['v'];
  if (typeof v === 'number' && Number.isInteger(v) && v > BROWSER_LIMITS.recordVersion)
    return fail('unsupported-version');
  if (v !== BROWSER_LIMITS.recordVersion) return fail('corrupt');
  const k = value['kind'];
  if (k !== 'text' && k !== 'keys') return fail('corrupt');
  if (k === 'text') {
    if (!sameMembers(value, ['v', 'kind', 'text'])) return fail('corrupt');
    const text = value['text'];
    if (typeof text !== 'string' || text.length > BROWSER_LIMITS.textMax) return fail('corrupt');
    return k === kind ? pass(text) : fail('wrong-kind');
  }
  if (!sameMembers(value, ['v', 'kind', 'signing', 'agreement'])) return fail('corrupt');
  const out: Record<string, CryptoKeyPair> = {};
  for (const pair of ['signing', 'agreement'] as const) {
    const p = value[pair];
    if (!plain(p) || !sameMembers(p, ['privateKey', 'publicKey'])) return fail('corrupt');
    if (keyProblem(p['privateKey'], SHAPES[pair].privateKey)) return fail('corrupt');
    if (keyProblem(p['publicKey'], SHAPES[pair].publicKey)) return fail('corrupt');
    out[pair] = {
      privateKey: p['privateKey'] as CryptoKey,
      publicKey: p['publicKey'] as CryptoKey,
    };
  }
  if (kind !== 'keys') return fail('wrong-kind');
  return pass({
    signing: out['signing'] as CryptoKeyPair,
    agreement: out['agreement'] as CryptoKeyPair,
  });
}

// ── errors ───────────────────────────────────────────────────────────────────────────────────────

function reasonOf(e: unknown, fallback: StoreReason): StoreReason {
  switch (errorName(e)) {
    case 'QuotaExceededError':
      return 'quota';
    case 'VersionError':
      return 'unsupported-version';
    case 'AbortError':
      return 'aborted';
    case 'DataCloneError':
    case 'DataError':
      return 'bad-value';
    case 'InvalidStateError':
    case 'TransactionInactiveError':
      return 'closed';
    default:
      return fallback;
  }
}

// ── open ─────────────────────────────────────────────────────────────────────────────────────────

export interface KeyStoreOptions {
  /** Name of the IndexedDB database (the app chooses it; one database per app and device). */
  readonly name: string;
}

/**
 * Opens (creating when needed) the database and returns the store. `idb` is the app's `indexedDB`, or
 * undefined where there is none: then the answer is `unavailable`. Never throws.
 */
export async function openKeyStore(
  idb: IdbFactoryLike | undefined,
  options: KeyStoreOptions,
): Promise<StoreResult<KeyStore>> {
  if (!isName(options?.name)) return fail('bad-name');
  if (!idb || typeof idb.open !== 'function') return fail('unavailable');
  const name = options.name;

  const opened = await new Promise<StoreResult<IdbDatabaseLike>>((resolve) => {
    let settled = false;
    const settle = (r: StoreResult<IdbDatabaseLike>): void => {
      if (settled) {
        // A late success after `blocked` must not leave a connection that blocks the other tab for good.
        if (r.ok) r.value.close();
        return;
      }
      settled = true;
      resolve(r);
    };
    let req;
    try {
      req = idb.open(name, BROWSER_LIMITS.schemaVersion);
    } catch (e) {
      settle(fail(reasonOf(e, 'unavailable')));
      return;
    }
    req.onupgradeneeded = () => {
      try {
        const db = req.result as IdbDatabaseLike;
        if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME);
      } catch (e) {
        settle(fail(reasonOf(e, 'failed')));
      }
    };
    req.onsuccess = () => {
      const db = req.result as IdbDatabaseLike;
      if (!settled && !db.objectStoreNames.contains(STORE_NAME)) {
        db.close();
        settle(fail('foreign-database'));
        return;
      }
      settle(pass(db));
    };
    req.onerror = () => settle(fail(reasonOf(req.error, 'unavailable')));
    req.onblocked = () => settle(fail('blocked'));
  });
  if (!opened.ok) return opened;
  return pass(wrap(idb, name, opened.value));
}

// ── the store ────────────────────────────────────────────────────────────────────────────────────

function wrap(idb: IdbFactoryLike, dbName: string, db: IdbDatabaseLike): KeyStore {
  let open = true;
  const closeDb = (): void => {
    if (!open) return;
    open = false;
    try {
      db.close();
    } catch {
      // already closed
    }
  };
  // Another tab upgrades or deletes the database: our connection must go, or that tab waits for ever.
  db.onversionchange = closeDb;
  db.onclose = () => {
    open = false;
  };

  /** One transaction; resolves when it has COMPLETED (written), with the result of the request. */
  function transact(
    mode: 'readonly' | 'readwrite',
    body: (os: IdbObjectStoreLike) => IdbRequestLike,
  ): Promise<StoreResult<unknown>> {
    return new Promise((resolve) => {
      if (!open) return resolve(fail('closed'));
      let done = false;
      const finish = (r: StoreResult<unknown>): void => {
        if (done) return;
        done = true;
        resolve(r);
      };
      let tx;
      try {
        tx = db.transaction(STORE_NAME, mode);
      } catch (e) {
        return finish(fail(reasonOf(e, 'closed')));
      }
      let result: unknown;
      tx.oncomplete = () => finish(pass(result));
      tx.onabort = () => finish(fail(reasonOf(tx.error, 'aborted')));
      tx.onerror = () => {
        // The abort event follows; this only records the first cause.
        if (!done && errorName(tx.error) === 'QuotaExceededError') finish(fail('quota'));
      };
      try {
        const req = body(tx.objectStore(STORE_NAME));
        req.onsuccess = () => {
          result = req.result;
        };
        req.onerror = () => {
          // Say why first; then do not let a failed request commit the rest of the transaction.
          finish(fail(reasonOf(req.error, 'failed')));
          try {
            tx.abort();
          } catch {
            // already finished
          }
        };
      } catch (e) {
        finish(fail(reasonOf(e, 'failed')));
        try {
          tx.abort();
        } catch {
          // already finished
        }
      }
    });
  }

  const read = async (
    name: string,
    kind: 'text' | 'keys',
  ): Promise<StoreResult<string | DeviceKeys | undefined>> => {
    if (!isName(name)) return fail('bad-name');
    const r = await transact('readonly', (os) => os.get(name));
    if (!r.ok) return r;
    if (r.value === undefined) return pass(undefined);
    return readRecord(r.value, kind);
  };

  const write = async (name: string, value: unknown): Promise<StoreResult<null>> => {
    const r = await transact('readwrite', (os) => os.put(value, name));
    return r.ok ? pass(null) : r;
  };

  return {
    isOpen: () => open,
    close: closeDb,
    async getKeys(name) {
      const r = await read(name, 'keys');
      return r as StoreResult<DeviceKeys | undefined>;
    },
    async putKeys(name, keys) {
      if (!isName(name)) return fail('bad-name');
      const p = keysProblem(keys);
      if (p === 'bad') return fail('bad-value');
      if (p === 'extractable') return fail('extractable-private-key');
      return write(name, {
        v: BROWSER_LIMITS.recordVersion,
        kind: 'keys',
        signing: { privateKey: keys.signing.privateKey, publicKey: keys.signing.publicKey },
        agreement: { privateKey: keys.agreement.privateKey, publicKey: keys.agreement.publicKey },
      });
    },
    async getText(name) {
      const r = await read(name, 'text');
      return r as StoreResult<string | undefined>;
    },
    async putText(name, text) {
      if (!isName(name)) return fail('bad-name');
      if (typeof text !== 'string' || text.length > BROWSER_LIMITS.textMax)
        return fail('bad-value');
      return write(name, { v: BROWSER_LIMITS.recordVersion, kind: 'text', text });
    },
    async remove(name) {
      if (!isName(name)) return fail('bad-name');
      const r = await transact('readwrite', (os) => os.delete(name));
      return r.ok ? pass(null) : r;
    },
    async wipe() {
      // Clear first: the data is gone even if another tab keeps the database from being deleted.
      const cleared = await transact('readwrite', (os) => os.clear());
      closeDb();
      const deleted = await new Promise<StoreResult<null>>((resolve) => {
        let req;
        try {
          req = idb.deleteDatabase(dbName);
        } catch (e) {
          return resolve(fail(reasonOf(e, 'failed')));
        }
        req.onsuccess = () => resolve(pass(null));
        req.onerror = () => resolve(fail(reasonOf(req.error, 'failed')));
        req.onblocked = () => resolve(fail('blocked'));
      });
      return cleared.ok || deleted.ok ? pass(null) : deleted;
    },
  };
}
