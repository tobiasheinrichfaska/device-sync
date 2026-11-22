// A small in-memory IndexedDB for tests: databases with a version and named stores of key/value pairs,
// transactions that commit or abort as a whole, structured clone on write, versionchange / blocked,
// deleteDatabase, and switches to make things fail. Events fire asynchronously (a microtask or a tick) after
// the handlers have been set, as in a browser. It is only as faithful as the cases tests/browser/fake-idb
// .test.ts checks.
import type {
  IdbDatabaseLike,
  IdbDeleteRequestLike,
  IdbFactoryLike,
  IdbObjectStoreLike,
  IdbOpenRequestLike,
  IdbRequestLike,
  IdbTransactionLike,
} from '../../src/browser/index.ts';

type Handler = ((ev: unknown) => unknown) | null;
const err = (name: string): { name: string } => ({ name });
const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

interface Db {
  version: number;
  stores: Map<string, Map<string, unknown>>;
  conns: Set<Conn>;
  waiting: Array<() => void>;
}

export interface Faults {
  /** `open` itself throws this error name (private mode in some browsers). */
  openThrows?: string;
  /** The open request fails with this error name. */
  openError?: string;
  /** The next commit of a readwrite transaction aborts with this error name (nothing is written). */
  commitError?: string;
  /** Another tab never closes its connection on versionchange (to provoke `blocked`). */
  ignoreVersionChange?: boolean;
}

class Req implements IdbOpenRequestLike, IdbDeleteRequestLike {
  result: unknown;
  error: unknown;
  onsuccess: Handler = null;
  onerror: Handler = null;
  onblocked: Handler = null;
  onupgradeneeded: Handler = null;
}

class Conn implements IdbDatabaseLike {
  onversionchange: Handler = null;
  onclose: Handler = null;
  closed = false;
  inUpgrade = false;
  constructor(
    readonly fake: FakeIdb,
    readonly db: Db,
  ) {}
  get objectStoreNames() {
    return { contains: (n: string) => this.db.stores.has(n) };
  }
  createObjectStore(name: string): unknown {
    if (!this.inUpgrade) throw err('InvalidStateError');
    if (this.db.stores.has(name)) throw err('ConstraintError');
    this.db.stores.set(name, new Map());
    return {};
  }
  transaction(store: string, mode: 'readonly' | 'readwrite'): IdbTransactionLike {
    if (this.closed) throw err('InvalidStateError');
    if (!this.db.stores.has(store)) throw err('NotFoundError');
    return new Tx(this, store, mode);
  }
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.db.conns.delete(this);
    for (const w of this.db.waiting.splice(0)) w();
  }
}

class Tx implements IdbTransactionLike {
  error: unknown;
  oncomplete: Handler = null;
  onabort: Handler = null;
  onerror: Handler = null;
  private ops: Array<() => void> = [];
  private working: Map<string, unknown>;
  private finished = false;
  constructor(
    private conn: Conn,
    private store: string,
    private mode: 'readonly' | 'readwrite',
  ) {
    this.working = new Map(conn.db.stores.get(store));
    void this.run();
  }
  private async run(): Promise<void> {
    await tick();
    while (this.ops.length && !this.finished) this.ops.shift()?.();
    if (this.finished) return;
    const f = this.conn.fake.faults;
    if (this.mode === 'readwrite' && f.commitError) {
      const name = f.commitError;
      delete f.commitError;
      this.fail(err(name));
      return;
    }
    if (this.mode === 'readwrite') this.conn.db.stores.set(this.store, this.working);
    this.finished = true;
    this.oncomplete?.({});
  }
  private fail(e: unknown): void {
    if (this.finished) return;
    this.finished = true;
    this.error = e;
    this.onabort?.({});
  }
  abort(): void {
    if (this.finished) throw err('InvalidStateError');
    this.finished = true;
    this.onabort?.({});
  }
  objectStore(name: string): IdbObjectStoreLike {
    if (name !== this.store) throw err('NotFoundError');
    const add = <T>(fn: () => T): IdbRequestLike => {
      if (this.finished) throw err('TransactionInactiveError');
      const r: { result?: unknown; error?: unknown; onsuccess: Handler; onerror: Handler } = {
        onsuccess: null,
        onerror: null,
      };
      this.ops.push(() => {
        try {
          r.result = fn();
        } catch (e) {
          r.error = e;
          r.onerror?.({});
          this.fail(e);
          return;
        }
        r.onsuccess?.({});
      });
      return r as IdbRequestLike;
    };
    const writable = (): void => {
      if (this.mode !== 'readwrite') throw err('ReadOnlyError');
    };
    return {
      get: (k) => add(() => structuredClone(this.working.get(k))),
      put: (v, k) => {
        writable();
        return add(() => {
          this.working.set(k, structuredClone(v));
          return k;
        });
      },
      delete: (k) => {
        writable();
        return add(() => void this.working.delete(k));
      },
      clear: () => {
        writable();
        return add(() => void this.working.clear());
      },
    };
  }
}

export class FakeIdb implements IdbFactoryLike {
  readonly dbs = new Map<string, Db>();
  faults: Faults = {};
  opens = 0;

  open(name: string, version = 1): IdbOpenRequestLike {
    if (this.faults.openThrows) throw err(this.faults.openThrows);
    this.opens++;
    const req = new Req();
    void (async () => {
      await tick();
      if (this.faults.openError) {
        req.error = err(this.faults.openError);
        req.onerror?.({});
        return;
      }
      let db = this.dbs.get(name);
      if (db && db.version > version) {
        req.error = err('VersionError');
        req.onerror?.({});
        return;
      }
      if (db && db.version < version) {
        // Other connections must let go first.
        for (const c of [...db.conns]) c.onversionchange?.({});
        await tick();
        if (db.conns.size > 0) {
          req.onblocked?.({});
          await new Promise<void>((r) => (db as Db).waiting.push(r));
        }
      }
      const fresh = !db || db.version < version;
      db ??= { version: 0, stores: new Map(), conns: new Set(), waiting: [] };
      this.dbs.set(name, db);
      const conn = new Conn(this, db);
      db.conns.add(conn);
      req.result = conn;
      if (fresh) {
        db.version = version;
        conn.inUpgrade = true;
        req.onupgradeneeded?.({});
        conn.inUpgrade = false;
      }
      req.onsuccess?.({});
    })();
    return req;
  }

  deleteDatabase(name: string): IdbDeleteRequestLike {
    const req = new Req();
    void (async () => {
      await tick();
      const db = this.dbs.get(name);
      if (db && db.conns.size > 0) {
        for (const c of [...db.conns]) c.onversionchange?.({});
        await tick();
        if (db.conns.size > 0) {
          req.onblocked?.({});
          await new Promise<void>((r) => db.waiting.push(r));
        }
      }
      this.dbs.delete(name);
      req.onsuccess?.({});
    })();
    return req;
  }

  /** Test access: the raw stored value, bypassing the layer. */
  raw(db: string, key: string): unknown {
    return this.dbs.get(db)?.stores.get('records')?.get(key);
  }
  /** Test access: writes a raw value as a foreign script would. */
  plant(db: string, key: string, value: unknown): void {
    this.dbs.get(db)?.stores.get('records')?.set(key, structuredClone(value));
  }
  connections(db: string): number {
    return this.dbs.get(db)?.conns.size ?? 0;
  }
  /** A tab that holds a connection and reacts to versionchange according to `faults`. */
  async otherTab(name: string): Promise<Conn> {
    const req = this.open(name, 1);
    return new Promise((resolve) => {
      req.onsuccess = () => {
        const c = req.result as Conn;
        c.onversionchange = () => {
          if (!this.faults.ignoreVersionChange) c.close();
        };
        resolve(c);
      };
      req.onupgradeneeded = () => {
        const c = req.result as Conn;
        if (!c.objectStoreNames.contains('records')) c.createObjectStore('records');
      };
    });
  }
}
