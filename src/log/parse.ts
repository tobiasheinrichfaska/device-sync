import { resolveLimits, type Limits } from './limits.ts';
import type { Change, ChangeKind, VersionVector } from './types.ts';
import { FORBIDDEN_NAMES, checkFields, count, dict, isPlain, label, name } from './validate.ts';

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

const KINDS: readonly string[] = ['set', 'delete', 'redacted'] satisfies ChangeKind[];
const CHECK = /^[A-Za-z0-9_-]{43}$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const FINGERPRINT = /^[0-9a-f]{32}$/;
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

/** Only the members named; `undefined`-valued ones count as absent. */
const onlyMembers = (o: Record<string, unknown>, allowed: ReadonlySet<string>): boolean =>
  Object.keys(o).every((k) => allowed.has(k) || o[k] === undefined);

function fieldsOf(raw: unknown, limits: Limits): Record<string, unknown> | undefined {
  if (isPlain(raw) && Object.keys(raw).length === 0) return undefined;
  const checked = checkFields(raw, limits);
  return checked.ok ? checked.value : undefined;
}

function vectorOf(
  raw: unknown,
  limits: Limits,
  deviceId: (id: string) => boolean,
): VersionVector | undefined {
  if (!isPlain(raw)) return undefined;
  const keys = Object.keys(raw);
  if (keys.length > limits.maxDevices) return undefined;
  const out = dict<number>();
  for (const device of keys) {
    const seq = raw[device];
    if (FORBIDDEN_NAMES.has(device) || deviceId(device) !== true || !count(seq)) return undefined;
    out[device] = seq;
  }
  return out;
}

function changeOf(raw: unknown, limits: Limits, deviceId: (id: string) => boolean) {
  if (!isPlain(raw) || !onlyMembers(raw, CHANGE_MEMBERS)) return undefined;
  const { device, seq, clock, collection, id, kind } = raw;
  if (
    typeof device !== 'string' ||
    FORBIDDEN_NAMES.has(device) ||
    deviceId(device) !== true ||
    !count(seq) ||
    seq < 1 ||
    !count(clock) ||
    clock < 1 ||
    !name(collection, limits.maxId) ||
    !name(id, limits.maxId) ||
    typeof kind !== 'string' ||
    !KINDS.includes(kind)
  ) {
    return undefined;
  }
  // What the author knew travels along: without it no device could tell a conflict, so a `set` or
  // `delete` without it is refused (an erased write needs none).
  const knew = raw.knew === undefined ? undefined : vectorOf(raw.knew, limits, deviceId);
  if (raw.knew !== undefined && !knew) return undefined;
  if (kind !== 'redacted' && !knew) return undefined;
  const { time, by } = raw;
  if (time !== undefined && !count(time)) return undefined;
  if (by !== undefined && !label(by, limits.maxName)) return undefined;
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

/**
 * A message as the text a transport hands over: refused at once when it is not a string or longer
 * than twice `maxMessageChars` (room for white space and the members around the changes), before any
 * JSON is read; otherwise parsed and read strictly as `parseSyncMessage`. Never throws.
 */
export function parseSyncMessageText(
  text: unknown,
  options: ParseOptions = {},
): SyncMessage | undefined {
  return guarded(() => {
    if (typeof text !== 'string') return undefined;
    if (text.length > resolveLimits(options.limits).maxMessageChars * 2) return undefined;
    return parseSyncMessage(JSON.parse(text), options);
  });
}
