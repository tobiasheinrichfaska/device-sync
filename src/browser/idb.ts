// The part of IndexedDB this layer uses, as structural types: a real `IDBFactory` fits (checked at compile
// time in tests/browser/idb-types.test.ts) and so does the small fake of the tests. Handlers take `any` so
// that the DOM's `(ev: Event) => any` handlers are assignable; this layer calls none of them with data.
/* eslint-disable @typescript-eslint/no-explicit-any */
type Handler = ((ev: any) => any) | null;

export interface IdbRequestLike {
  readonly result?: any;
  readonly error?: any;
  onsuccess: Handler;
  onerror: Handler;
}

export interface IdbOpenRequestLike extends IdbRequestLike {
  onblocked: Handler;
  onupgradeneeded: Handler;
}

export interface IdbDeleteRequestLike extends IdbRequestLike {
  onblocked: Handler;
}

export interface IdbObjectStoreLike {
  get(key: string): IdbRequestLike;
  put(value: unknown, key: string): IdbRequestLike;
  delete(key: string): IdbRequestLike;
  clear(): IdbRequestLike;
}

export interface IdbTransactionLike {
  readonly error?: any;
  oncomplete: Handler;
  onabort: Handler;
  onerror: Handler;
  objectStore(name: string): IdbObjectStoreLike;
  abort(): void;
}

export interface IdbDatabaseLike {
  readonly objectStoreNames: { contains(name: string): boolean };
  onversionchange: Handler;
  onclose: Handler;
  createObjectStore(name: string): unknown;
  transaction(store: string, mode: 'readonly' | 'readwrite'): IdbTransactionLike;
  close(): void;
}

export interface IdbFactoryLike {
  open(name: string, version?: number): IdbOpenRequestLike;
  deleteDatabase(name: string): IdbDeleteRequestLike;
}

/** The name of an error object (a `DOMException` or anything shaped like one), or undefined. */
export function errorName(e: unknown): string | undefined {
  if (typeof e !== 'object' || e === null) return undefined;
  const n = (e as { name?: unknown }).name;
  return typeof n === 'string' ? n : undefined;
}
