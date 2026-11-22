/** Numbers of the browser layer. */
export const BROWSER_LIMITS = {
  /** Longest name of a record, of a database, of a lock or of a channel. */
  nameMax: 100,
  /** Longest text record (the relay credential is about 600 characters). */
  textMax: 8_192,
  /** Version of the IndexedDB schema (one object store). */
  schemaVersion: 1,
  /** Version member of every stored record. */
  recordVersion: 1,
  /** Largest camera frame side, in pixels. */
  frameSideMax: 4_096,
  /** Most samples in one audio buffer. */
  samplesMax: 1_048_576,
  /** Shortest interval between two camera frames, ms. */
  frameIntervalMinMs: 10,
} as const;

export type BrowserLimits = typeof BROWSER_LIMITS;

/** Result of a browser helper: a value or a code (never an exception for a refusal). */
export type BrowserResult<T, R extends string> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly reason: R };

export const fail = <R extends string>(reason: R): { readonly ok: false; readonly reason: R } => ({
  ok: false,
  reason,
});
export const pass = <T>(value: T): { readonly ok: true; readonly value: T } => ({
  ok: true,
  value,
});

/** A name that is safe as a record, database, lock or channel name (a lock name may not start with "-"). */
export function isName(text: unknown): text is string {
  return (
    typeof text === 'string' &&
    text.length > 0 &&
    text.length <= BROWSER_LIMITS.nameMax &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(text)
  );
}
