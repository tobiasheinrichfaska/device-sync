// A replica at rest: the strict reader of what `replicaToStored` wrote, and a size-guarded store
// result. The stored form carries only what cannot be derived (device, clock, vector, the log, the
// snapshot base, the approval state); the collections and the conflict notices are REBUILT from the
// log on reading, so a stored value that disagrees with its log cannot exist. The reader is the
// guard against writing a number twice after a half-restored store: this device's own numbers must
// be 1..n without a gap and the stored vector must name exactly n (docs/channel.md, "Replica at rest").
import { hasDuplicateKeys } from '../core/json.ts';
import { readApprovalState } from './approval.ts';
import { merge, mergeRetained, byDeviceThenSeq } from './merge.ts';
import { parseChange, parseVector, type ParseOptions } from './parse.ts';
import type { ApprovalState, Change, Replica, VersionVector } from './types.ts';
import { count, dict, isPlain } from './validate.ts';
import { emptyReplica } from './replica.ts';

export const REPLICA_VERSION = 1;

/** Bounds of the reader and of the store result (own, safe, non-negative integers only). */
export const REPLICA_AT_REST = Object.freeze({
  /** Most changes in a stored log; more is refused (`too-many-changes`), never cut. */
  maxChanges: 1_000_000,
  /** Longest stored text (UTF-16 units) `readReplicaText` and `storeReplica` take. */
  maxChars: 256_000_000,
});

export interface StoredReplica {
  readonly v: number;
  readonly device: string;
  readonly clock: number;
  readonly vector: VersionVector;
  readonly log: readonly Change[];
  readonly base?: Readonly<Record<string, number>>;
  readonly approval?: ApprovalState;
}

/** The members that are stored (JSON-ready; `JSON.stringify` of it is the stored text). */
export function replicaToStored(replica: Replica): StoredReplica {
  return {
    v: REPLICA_VERSION,
    device: replica.device,
    clock: replica.clock,
    vector: replica.vector,
    log: replica.log,
    ...(replica.base && Object.keys(replica.base).length > 0 ? { base: replica.base } : {}),
    ...(replica.approval && replica.approval.entries.length > 0
      ? { approval: replica.approval }
      : {}),
  };
}

export type ReadReplicaFailure =
  | 'not-an-object'
  | 'unknown-member'
  | 'bad-version'
  | 'wrong-device'
  | 'bad-clock'
  | 'bad-vector'
  | 'bad-base'
  | 'bad-log'
  | 'too-many-changes'
  | 'too-large'
  | 'bad-change'
  | 'duplicate-change'
  | 'gap'
  | 'own-numbers'
  | 'vector-mismatch'
  | 'bad-approval'
  | 'approval-overlap';

export type ReadReplicaResult =
  | { readonly ok: true; readonly replica: Replica }
  | { readonly ok: false; readonly reason: ReadReplicaFailure };

export interface ReadReplicaOptions extends ParseOptions {
  /** The device that reads it: a store of another device is refused (`wrong-device`). */
  readonly device: string;
  readonly maxChanges?: number;
  readonly maxChars?: number;
}

const MEMBERS = new Set(['v', 'device', 'clock', 'vector', 'log', 'base', 'approval']);

/**
 * A replica from stored JSON (any value; never throws). Strict: exactly the stored members, no
 * prototype keys, every change read by the parser, no number twice, the log without a gap
 * (condensed devices excepted, see `base`), this device's own numbers 1..n with the vector naming n,
 * the vector equal to the one the log makes, the clock not below any change, the approval state read
 * by `readApprovalState` and disjoint from the log. Signatures are NOT checked again: this is local
 * state that was judged before it was stored (a store an attacker can write to is not protected
 * here). Fresh copies; the collections and notices are derived.
 */
export function readReplica(raw: unknown, options: ReadReplicaOptions): ReadReplicaResult {
  try {
    return read(raw, options);
  } catch {
    return { ok: false, reason: 'bad-log' };
  }
}

/** Like `readReplica` for the stored text: bounded before it parses, duplicate keys refused. */
export function readReplicaText(text: unknown, options: ReadReplicaOptions): ReadReplicaResult {
  const max = options.maxChars ?? REPLICA_AT_REST.maxChars;
  if (typeof text !== 'string') return { ok: false, reason: 'not-an-object' };
  if (text.length > max) return { ok: false, reason: 'too-large' };
  try {
    if (hasDuplicateKeys(text)) return { ok: false, reason: 'unknown-member' };
    return readReplica(JSON.parse(text) as unknown, options);
  } catch {
    return { ok: false, reason: 'not-an-object' };
  }
}

const fail = (reason: ReadReplicaFailure): ReadReplicaResult => ({ ok: false, reason });

function read(raw: unknown, options: ReadReplicaOptions): ReadReplicaResult {
  if (!isPlain(raw)) return fail('not-an-object');
  if (Object.keys(raw).some((k) => !MEMBERS.has(k))) return fail('unknown-member');
  for (const k of ['v', 'device', 'clock', 'vector', 'log'])
    if (!Object.hasOwn(raw, k)) return fail('unknown-member');
  if (raw.v !== REPLICA_VERSION) return fail('bad-version');
  const { device } = options;
  if (raw.device !== device) return fail('wrong-device');
  const idOk = options.deviceId ?? ((s: string) => /^[A-Za-z0-9._-]{1,80}$/.test(s));
  if (!idOk(device)) return fail('wrong-device');
  if (!count(raw.clock)) return fail('bad-clock');
  const vector = parseVector(raw.vector, options);
  if (!vector) return fail('bad-vector');
  const base = Object.hasOwn(raw, 'base') ? parseVector(raw.base, options) : undefined;
  if (Object.hasOwn(raw, 'base') && (!base || Object.keys(base).length === 0)) {
    return fail('bad-base');
  }
  const rawLog = raw.log;
  if (!Array.isArray(rawLog)) return fail('bad-log');
  const maxChanges = options.maxChanges ?? REPLICA_AT_REST.maxChanges;
  if (rawLog.length > maxChanges) return fail('too-many-changes');

  const log: Change[] = [];
  const keys = new Set<string>();
  const top = dict<number>();
  let maxClock = 0;
  for (const entry of rawLog as unknown[]) {
    const change = parseChange(entry, options);
    if (!change) return fail('bad-change');
    const key = `${change.device}\u0000${change.seq}`;
    if (keys.has(key)) return fail('duplicate-change');
    keys.add(key);
    log.push(change);
    top[change.device] = Math.max(top[change.device] ?? 0, change.seq);
    maxClock = Math.max(maxClock, change.clock);
  }
  const clock = raw.clock as number;
  if (clock < maxClock) return fail('bad-clock');

  // Numbers above the condensed part (all of them without a base) are 1..n or base+1..n, no gap, and
  // the vector names the highest.
  const lower = (d: string): number => (base ? (base[d] ?? 0) : 0);
  const held = dict<Set<number>>();
  for (const c of log) (held[c.device] ??= new Set()).add(c.seq);
  for (const d of new Set([...Object.keys(top), ...Object.keys(vector)])) {
    const n = vector[d] ?? 0;
    if ((top[d] ?? 0) !== n) return fail(d === device ? 'own-numbers' : 'vector-mismatch');
    const from = lower(d);
    if (from > n) return fail('bad-base');
    for (let i = from + 1; i <= n; i += 1) {
      if (!held[d]?.has(i)) return fail(d === device ? 'own-numbers' : 'gap');
    }
    if (base && from > 0 && !held[d]?.has(from)) return fail('bad-base');
  }
  if (base) {
    for (const d of Object.keys(base)) if (!Object.hasOwn(vector, d)) return fail('bad-base');
  }

  let replica: Replica;
  if (base) {
    replica = mergeRetained(
      emptyReplica(device),
      [...log].sort(byDeviceThenSeq),
      vector,
      clock,
      base,
    );
  } else {
    const merged = merge(emptyReplica(device), log);
    if (merged.held.length > 0 || merged.applied !== log.length) return fail('gap');
    const same =
      Object.keys(merged.replica.vector).length === Object.keys(vector).length &&
      Object.entries(vector).every(([d, n]) => merged.replica.vector[d] === n);
    if (!same) return fail('vector-mismatch');
    replica = { ...merged.replica, clock: Math.max(merged.replica.clock, clock) };
  }

  if (Object.hasOwn(raw, 'approval')) {
    const read = readApprovalState(raw.approval, options);
    if (!read.ok) return fail('bad-approval');
    for (const entry of read.state.entries) {
      if (keys.has(`${entry.change.device}\u0000${entry.change.seq}`)) {
        return fail('approval-overlap');
      }
    }
    replica = { ...replica, approval: read.state };
  }
  return { ok: true, replica };
}

export type StoreReplicaResult =
  | { readonly ok: true; readonly chars: number }
  | { readonly ok: false; readonly reason: 'too-large' | 'write-failed'; readonly chars: number };

/**
 * Writes the replica as text with `write`. Unlike a mailbox a replica is somebody's data and is never
 * halved: a text over `maxChars` is not written (`too-large`, nothing changes in the store) and a
 * failing write (a full store) is `write-failed`; in both cases the old stored state stays as it was
 * and the caller still holds the replica. Never throws.
 */
export async function storeReplica(
  write: (text: string) => Promise<void> | void,
  replica: Replica,
  options: { readonly maxChars?: number } = {},
): Promise<StoreReplicaResult> {
  let text: string;
  try {
    text = JSON.stringify(replicaToStored(replica));
  } catch {
    return { ok: false, reason: 'write-failed', chars: 0 };
  }
  if (text.length > (options.maxChars ?? REPLICA_AT_REST.maxChars)) {
    return { ok: false, reason: 'too-large', chars: text.length };
  }
  try {
    await write(text);
    return { ok: true, chars: text.length };
  } catch {
    return { ok: false, reason: 'write-failed', chars: text.length };
  }
}
