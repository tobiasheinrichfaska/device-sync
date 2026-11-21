import { resolveLimits, type Limits } from './limits.ts';
import type { Change, ChangeKind, VersionVector } from './types.ts';

/**
 * A message of the exchange:
 * `stand` (the sender's version vector), `changes` (a piece of changes, `last` marks the final
 * piece) and `done` (the sender's stand and fingerprint after taking what it received).
 */
export type SyncMessage =
  | { readonly t: 'stand'; readonly vector: VersionVector }
  | { readonly t: 'changes'; readonly changes: readonly Change[]; readonly last: boolean }
  | { readonly t: 'done'; readonly vector: VersionVector; readonly fingerprint: string };

export interface ParseOptions {
  /** Partial override of the defaults in `LIMITS`. */
  readonly limits?: Partial<Limits>;
  /** What a device id looks like in this app; the default accepts `DEFAULT_DEVICE_ID`. */
  readonly deviceId?: (id: string) => boolean;
}

/** Permissive default for device ids; an app passes its own (e.g. exactly 16 hex digits). */
export const DEFAULT_DEVICE_ID = /^[A-Za-z0-9._-]{1,80}$/;

const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const CONTROL = /\p{Cc}/u;
const KINDS: readonly string[] = ['set', 'delete', 'redacted'] satisfies ChangeKind[];
const CHECK = /^[A-Za-z0-9_-]{43}$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const FINGERPRINT = /^[0-9a-f]{8}$/;
const CHANGE_MEMBERS: ReadonlySet<string> = new Set([
  'device',
  'seq',
  'clock',
  'collection',
  'id',
  'kind',
  'fields',
  'knew',
  'time',
  'by',
  'check',
  'sig',
]);

/** A plain data object (from JSON, or an object literal): no class instance, no Date, no Map. */
function isPlain(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

/** Safe integers only: past 2^53 a clock no longer counts up. */
const count = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

/** 1..max characters, no control character. */
const text = (v: unknown, max: number): v is string =>
  typeof v === 'string' && v.length >= 1 && v.length <= max && !CONTROL.test(v);

/** A key that would reach the prototype of the object it is stored in. */
const name = (v: unknown, max: number): v is string => text(v, max) && !FORBIDDEN.has(v);

/** Only the members named; `undefined`-valued ones count as absent. */
const onlyMembers = (o: Record<string, unknown>, allowed: ReadonlySet<string>): boolean =>
  Object.keys(o).every((k) => allowed.has(k) || o[k] === undefined);

interface Budget {
  nodes: number;
}

/** A copy of a field value, or undefined when it breaks a limit or is not plain JSON. */
function cleanValue(v: unknown, depth: number, limits: Limits, budget: Budget): unknown {
  // Every node is at least one character of JSON, so this also bounds the work on a huge value.
  if (++budget.nodes > limits.maxValueChars) return undefined;
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v === 'string') return v.length <= limits.maxText ? v : undefined;
  if (depth >= limits.maxDepth) return undefined;
  if (Array.isArray(v)) {
    if (v.length > limits.maxEntries) return undefined;
    const out: unknown[] = [];
    for (let i = 0; i < v.length; i += 1) {
      const item = cleanValue(v[i], depth + 1, limits, budget);
      if (item === undefined) return undefined;
      out.push(item);
    }
    return out;
  }
  if (!isPlain(v)) return undefined;
  const keys = Object.keys(v);
  if (keys.length > limits.maxEntries) return undefined;
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    if (!name(key, limits.maxName)) return undefined;
    const item = cleanValue(v[key], depth + 1, limits, budget);
    if (item === undefined) return undefined;
    out[key] = item;
  }
  return out;
}

function fieldsOf(raw: unknown, limits: Limits): Record<string, unknown> | undefined {
  if (!isPlain(raw)) return undefined;
  const keys = Object.keys(raw);
  if (keys.length === 0 || keys.length > limits.maxFields) return undefined;
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    if (!name(key, limits.maxName)) return undefined;
    const value = cleanValue(raw[key], 0, limits, { nodes: 0 });
    if (value === undefined) return undefined;
    if (JSON.stringify(value).length > limits.maxValueChars) return undefined;
    out[key] = value;
  }
  return out;
}

function vectorOf(
  raw: unknown,
  limits: Limits,
  deviceId: (id: string) => boolean,
): VersionVector | undefined {
  if (!isPlain(raw)) return undefined;
  const keys = Object.keys(raw);
  if (keys.length > limits.maxDevices) return undefined;
  const out: Record<string, number> = {};
  for (const device of keys) {
    const seq = raw[device];
    if (FORBIDDEN.has(device) || deviceId(device) !== true || !count(seq)) return undefined;
    out[device] = seq;
  }
  return out;
}

function changeOf(raw: unknown, limits: Limits, deviceId: (id: string) => boolean) {
  if (!isPlain(raw) || !onlyMembers(raw, CHANGE_MEMBERS)) return undefined;
  const { device, seq, clock, collection, id, kind } = raw;
  if (
    typeof device !== 'string' ||
    FORBIDDEN.has(device) ||
    deviceId(device) !== true ||
    !count(seq) ||
    seq < 1 ||
    !count(clock) ||
    clock < 1 ||
    !text(collection, limits.maxId) ||
    !text(id, limits.maxId) ||
    typeof kind !== 'string' ||
    !KINDS.includes(kind)
  ) {
    return undefined;
  }
  // What the author knew travels along: without it no device could tell a conflict.
  const knew = raw.knew === undefined ? undefined : vectorOf(raw.knew, limits, deviceId);
  if (raw.knew !== undefined && !knew) return undefined;
  const { time, by } = raw;
  if (time !== undefined && !count(time)) return undefined;
  if (by !== undefined && !text(by, limits.maxName)) return undefined;
  // A signature never comes without the check value; a check value alone is an erased write.
  const { check, sig } = raw;
  if (check !== undefined && (typeof check !== 'string' || !CHECK.test(check))) return undefined;
  if (sig !== undefined && (typeof sig !== 'string' || !SIG.test(sig) || check === undefined)) {
    return undefined;
  }
  const base = {
    device,
    seq,
    clock,
    collection,
    id,
    kind: kind as ChangeKind,
    ...(knew ? { knew } : {}),
    ...(time !== undefined ? { time } : {}),
    ...(by !== undefined ? { by } : {}),
    ...(check !== undefined ? { check } : {}),
    ...(sig !== undefined ? { sig } : {}),
  } satisfies Change;
  if (kind !== 'set') return raw.fields === undefined ? base : undefined;
  const fields = fieldsOf(raw.fields, limits);
  return fields ? { ...base, fields } : undefined;
}

function messageOf(
  raw: unknown,
  limits: Limits,
  deviceId: (id: string) => boolean,
): SyncMessage | undefined {
  if (!isPlain(raw)) return undefined;
  if (raw.t === 'stand') {
    if (!onlyMembers(raw, new Set(['t', 'vector']))) return undefined;
    const vector = vectorOf(raw.vector, limits, deviceId);
    return vector ? { t: 'stand', vector } : undefined;
  }
  if (raw.t === 'done') {
    if (!onlyMembers(raw, new Set(['t', 'vector', 'fingerprint']))) return undefined;
    const vector = vectorOf(raw.vector, limits, deviceId);
    const fingerprint = raw.fingerprint;
    return vector && typeof fingerprint === 'string' && FINGERPRINT.test(fingerprint)
      ? { t: 'done', vector, fingerprint }
      : undefined;
  }
  if (raw.t === 'changes') {
    if (!onlyMembers(raw, new Set(['t', 'changes', 'last']))) return undefined;
    const list = raw.changes;
    if (!Array.isArray(list) || list.length > limits.maxChanges) return undefined;
    if (typeof raw.last !== 'boolean') return undefined;
    const changes: Change[] = [];
    let chars = 0;
    for (let i = 0; i < list.length; i += 1) {
      const change = changeOf(list[i], limits, deviceId);
      if (!change) return undefined;
      // The size of what is accepted is bounded, not only the shape of each part.
      chars += JSON.stringify(change).length;
      if (chars > limits.maxMessageChars) return undefined;
      changes.push(change);
    }
    return { t: 'changes', changes, last: raw.last };
  }
  return undefined;
}

/** Never throws, whatever comes in (a throwing getter, a revoked proxy, a hostile predicate). */
function guarded<T>(run: () => T | undefined): T | undefined {
  try {
    return run();
  } catch {
    return undefined;
  }
}

/**
 * One change, strictly read: exactly the members of a change, each of the right type and within the
 * limits; anything else is undefined. The result is a fresh object (nothing shared with the input).
 */
export function parseChange(raw: unknown, options: ParseOptions = {}): Change | undefined {
  return guarded(() =>
    changeOf(
      raw,
      resolveLimits(options.limits),
      options.deviceId ?? ((s) => DEFAULT_DEVICE_ID.test(s)),
    ),
  );
}

/** A version vector (stand), strictly read: at most `maxDevices` devices, counts are safe integers. */
export function parseVector(raw: unknown, options: ParseOptions = {}): VersionVector | undefined {
  return guarded(() =>
    vectorOf(
      raw,
      resolveLimits(options.limits),
      options.deviceId ?? ((s) => DEFAULT_DEVICE_ID.test(s)),
    ),
  );
}

/** A message of the exchange, strictly read; anything else (and any member too many) is undefined. */
export function parseSyncMessage(
  raw: unknown,
  options: ParseOptions = {},
): SyncMessage | undefined {
  return guarded(() =>
    messageOf(
      raw,
      resolveLimits(options.limits),
      options.deviceId ?? ((s) => DEFAULT_DEVICE_ID.test(s)),
    ),
  );
}
