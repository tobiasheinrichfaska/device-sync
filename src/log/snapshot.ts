import { base64url, canonical, marker, sha256Text, verifyText, signText } from '../core/index.ts';
import { hasDuplicateKeys } from '../core/json.ts';
import { heldIn } from './chain.ts';
import { changeLink } from './check.ts';
import { resolveLimits, type Limits } from './limits.ts';
import { mergeRetained } from './merge.ts';
import { parseChange, parseVector, type ParseOptions } from './parse.ts';
import { fingerprint } from './protocol.ts';
import { judgeRetained, type JudgeOptions, type Rejection } from './signing.ts';
import type { Change, DeviceId, Replica, VersionVector } from './types.ts';
import { dict, isPlain, label, own } from './validate.ts';
import { seen } from './vector.ts';

/** Version of the snapshot format (part of the signed text). */
export const SNAPSHOT_VERSION = 1;

/**
 * A condensed state: the change log reduced to what the data and the conflict notices still need,
 * and the stand that says what the reduction covers (see `docs/snapshot.md`). Plain JSON.
 */
export interface Snapshot {
  readonly v: typeof SNAPSHOT_VERSION;
  /** The data set the changes belong to (as in a change signature). */
  readonly set: string;
  /** The device that made it, and whose signature is on it. */
  readonly producer: DeviceId;
  /** The producer's Lamport clock when it made the snapshot. */
  readonly clock: number;
  /** What the snapshot covers: per device the highest number it stands for. */
  readonly vector: VersionVector;
  /** The producer's `fingerprint` of its data, so a device starting from nothing can check the result. */
  readonly fingerprint: string;
  /**
   * The retained changes, real and signed, ordered by device and number: per field the last write of
   * each device and the writes that settle other devices' writes, the first final deletion of each
   * deleted record, and for every device the change at its place in the vector (the tail).
   */
  readonly changes: readonly Change[];
  /** The producer's signature over the head of the snapshot and the links of its changes. */
  readonly sig: string;
}

/** What the trust hook is shown before anything is checked. */
export interface SnapshotInfo {
  readonly set: string;
  readonly clock: number;
  readonly vector: VersionVector;
  readonly fingerprint: string;
  /** Number of retained changes. */
  readonly changes: number;
}

const FINGERPRINT = /^[0-9a-f]{32}$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const MEMBERS: ReadonlySet<string> = new Set([
  'v',
  'set',
  'producer',
  'clock',
  'vector',
  'fingerprint',
  'changes',
  'sig',
]);

const byDeviceThenSeq = (a: Change, b: Change): number =>
  a.device < b.device ? -1 : a.device > b.device ? 1 : a.seq - b.seq;

const recordKey = (c: Change): string => JSON.stringify([c.collection, c.id]);

/**
 * The text a producer signs: marker (app, `snapshot`, format version), then the canonical form of
 * version, data set, producer, clock, vector, fingerprint and the digest of the links of the retained
 * changes (a link is a hash of a change's whole signed head, so the list pins exactly these changes).
 */
export function snapshotSigningText(
  appId: string,
  snapshot: Omit<Snapshot, 'sig'>,
  dataSet: string,
): string {
  if (typeof dataSet !== 'string' || dataSet.length === 0) {
    throw new TypeError('snapshotSigningText: the data set must be a non-empty string');
  }
  const links = snapshot.changes.map((c) => changeLink(c) ?? '');
  const body = canonical({
    v: SNAPSHOT_VERSION,
    set: dataSet,
    producer: snapshot.producer,
    clock: snapshot.clock,
    vector: snapshot.vector,
    fingerprint: snapshot.fingerprint,
    digest: base64url(sha256Text(canonical(links))),
  });
  return `${marker(appId, 'snapshot', SNAPSHOT_VERSION)}|${body}`;
}

export type SnapshotFailure =
  /** A change of the log carries no signature yet: sign this device's changes first. */
  | 'unsigned'
  /** The log lacks the change at a device's place in the vector (a hand-built replica). */
  | 'missing-history'
  /** An erased change whose record's deletion is not in the log (a rejected change of an approval hook). */
  | 'erased-without-deletion'
  | 'too-large';

export type SnapshotResult =
  | { readonly ok: true; readonly snapshot: Snapshot }
  | { readonly ok: false; readonly reason: SnapshotFailure };

export interface SnapshotOptions {
  readonly appId: string;
  readonly dataSet: string;
  /** The producer's signing key (the one the others know this device by). */
  readonly signingKey: CryptoKey;
  readonly limits?: Partial<Limits>;
}

/**
 * The changes a condensed log keeps (see `Snapshot.changes`), or the reason it cannot be made.
 * Everything a replica derives from its log (values, winners, notices, what a later change knew) is
 * the same from the retained changes as from the whole log: per field the retained writes hold every
 * device's last write (what the winners and heads are made of) and, for each such write, the write
 * with the highest `knew` of its device if that one covers it (what settles a conflict).
 */
export function condense(replica: Replica): readonly Change[] | SnapshotFailure {
  interface Field {
    last: Map<DeviceId, Change>;
    best: Map<DeviceId, { n: number; change: Change }>;
  }
  interface Rec {
    fields: Map<string, Field>;
    firstDelete?: Change;
  }
  const records = new Map<string, Rec>();
  for (const change of replica.log) {
    if (change.kind === 'redacted') continue;
    const key = recordKey(change);
    let rec = records.get(key);
    if (!rec) records.set(key, (rec = { fields: new Map() }));
    if (change.kind === 'delete') {
      rec.firstDelete ??= change;
      continue;
    }
    for (const name of Object.keys(change.fields ?? {})) {
      let field = rec.fields.get(name);
      if (!field) rec.fields.set(name, (field = { last: new Map(), best: new Map() }));
      field.last.set(change.device, change);
      for (const [device, n] of Object.entries(change.knew ?? {})) {
        if (n > (field.best.get(device)?.n ?? 0)) field.best.set(device, { n, change });
      }
    }
  }
  const keep = new Set<Change>();
  for (const [key, rec] of records) {
    const [collection, id] = JSON.parse(key) as [string, string];
    if (own(own(replica.collections, collection), id)?.deleted) {
      if (rec.firstDelete) keep.add(rec.firstDelete);
      continue;
    }
    for (const field of rec.fields.values()) {
      for (const change of field.last.values()) keep.add(change);
      for (const [device, { n, change }] of field.best) {
        const last = field.last.get(device);
        if (last && n >= last.seq) keep.add(change);
      }
    }
  }
  const held = heldIn(replica.log);
  for (const [device, seq] of Object.entries(replica.vector)) {
    if (seq < 1) continue;
    const tail = held.get(`${device}#${seq}`);
    if (!tail) return 'missing-history';
    keep.add(tail);
  }
  const out = [...keep].sort(byDeviceThenSeq);
  const deletions = new Set(out.filter((c) => c.kind === 'delete').map(recordKey));
  for (const change of out) {
    if (!change.sig || !change.check) return 'unsigned';
    if (change.kind === 'redacted' && !deletions.has(recordKey(change))) {
      return 'erased-without-deletion';
    }
  }
  // Everything in the log must be signed, not only what is kept: the vector stands for all of it.
  if (replica.log.some((c) => !c.sig)) return 'unsigned';
  return out;
}

/**
 * Makes a snapshot of a replica (any device can; the receiver decides whether it trusts this one).
 * Every change of the log must be signed already (`signOwnChanges`, `insertSignatures`). The
 * replica may itself have started from a snapshot.
 */
export async function snapshot(
  replica: Replica,
  options: SnapshotOptions,
): Promise<SnapshotResult> {
  const limits = resolveLimits(options.limits);
  const retained = condense(replica);
  if (typeof retained === 'string') return { ok: false, reason: retained };
  if (retained.length > limits.maxSnapshotChanges) return { ok: false, reason: 'too-large' };
  const body: Omit<Snapshot, 'sig'> = {
    v: SNAPSHOT_VERSION,
    set: options.dataSet,
    producer: replica.device,
    clock: replica.clock,
    vector: { ...replica.vector },
    fingerprint: fingerprint(replica),
    changes: retained,
  };
  const made: Snapshot = {
    ...body,
    sig: await signText(
      options.signingKey,
      snapshotSigningText(options.appId, body, options.dataSet),
    ),
  };
  if (JSON.stringify(made).length > limits.maxSnapshotChars)
    return { ok: false, reason: 'too-large' };
  return { ok: true, snapshot: made };
}

function readSnapshot(raw: unknown, options: ParseOptions): Snapshot | undefined {
  const limits = resolveLimits(options.limits);
  if (!isPlain(raw) || !Object.keys(raw).every((k) => MEMBERS.has(k))) return undefined;
  const { v, set, producer, clock, fingerprint: print, sig } = raw;
  const deviceOk = options.deviceId ?? ((s: string) => /^[A-Za-z0-9._-]{1,80}$/.test(s));
  if (v !== SNAPSHOT_VERSION || !label(set, limits.maxName)) return undefined;
  if (typeof producer !== 'string' || deviceOk(producer) !== true) return undefined;
  if (!Number.isSafeInteger(clock) || (clock as number) < 0) return undefined;
  if (typeof print !== 'string' || !FINGERPRINT.test(print)) return undefined;
  if (typeof sig !== 'string' || !SIG.test(sig)) return undefined;
  const vector = parseVector(raw.vector, options);
  if (!vector) return undefined;
  const list = raw.changes;
  if (!Array.isArray(list) || list.length > limits.maxSnapshotChanges) return undefined;
  const changes: Change[] = [];
  const at = new Map<string, Change>();
  let chars = 0;
  for (const item of list) {
    const change = parseChange(item, options);
    if (!change || !change.sig || !change.check) return undefined;
    chars += JSON.stringify(change).length;
    if (chars > limits.maxSnapshotChars) return undefined;
    const last = changes[changes.length - 1];
    if (last && byDeviceThenSeq(last, change) >= 0) return undefined;
    // What the vector stands for: nothing beyond it, no clock beyond the snapshot's, no knowledge of
    // numbers the snapshot does not cover.
    if (change.seq > seen(vector, change.device) || change.clock > (clock as number))
      return undefined;
    if (Object.entries(change.knew ?? {}).some(([d, n]) => n > seen(vector, d))) return undefined;
    changes.push(change);
    at.set(`${change.device}#${change.seq}`, change);
  }
  for (const change of changes) {
    const before = at.get(`${change.device}#${change.seq - 1}`);
    if (before && changeLink(before) !== change.prev) return undefined;
  }
  // The tail of every device is there: its link is what the next change of that device chains to.
  for (const [device, seq] of Object.entries(vector)) {
    if (seq >= 1 && !at.has(`${device}#${seq}`)) return undefined;
  }
  const deletions = new Set(changes.filter((c) => c.kind === 'delete').map(recordKey));
  if (changes.some((c) => c.kind === 'redacted' && !deletions.has(recordKey(c)))) return undefined;
  return {
    v: SNAPSHOT_VERSION,
    set: set as string,
    producer,
    clock: clock as number,
    vector,
    fingerprint: print,
    changes,
    sig,
  };
}

/** A snapshot, strictly read: exactly its members, every change strictly read and consistent; never throws. */
export function parseSnapshot(raw: unknown, options: ParseOptions = {}): Snapshot | undefined {
  try {
    return readSnapshot(raw, options);
  } catch {
    return undefined;
  }
}

/** A snapshot as text: refused when over twice `maxSnapshotChars` or with a key twice; never throws. */
export function parseSnapshotText(text: unknown, options: ParseOptions = {}): Snapshot | undefined {
  try {
    if (typeof text !== 'string') return undefined;
    if (text.length > resolveLimits(options.limits).maxSnapshotChars * 2) return undefined;
    const raw: unknown = JSON.parse(text);
    if (hasDuplicateKeys(text)) return undefined;
    return readSnapshot(raw, options);
  } catch {
    return undefined;
  }
}

export interface CatchUpOptions extends ParseOptions {
  /** App id, data set, key source and the receiver's rules (`mayWrite`, `allowFinalDelete`, ...). */
  readonly judge: JudgeOptions;
  /**
   * REQUIRED. Whether this device may be believed about the condensed part (see `docs/snapshot.md`):
   * `false` refuses the snapshot. The hook sees only what the snapshot says, before any signature is
   * checked; a snapshot is accepted on its producer's word for what the retained changes do not show.
   */
  readonly trustProducer: (producer: DeviceId, info: SnapshotInfo, replica: Replica) => boolean;
}

export type CatchUpFailure =
  | 'unreadable'
  | 'untrusted-producer'
  /** The key of the producer cannot be found. */
  | 'unknown-producer'
  | 'bad-producer-signature'
  /** A retained change is not true (see `rejection`) or no key is known for its author. */
  | 'forged'
  | 'unknown-author'
  /** A replica that started from nothing does not end with the data the producer signed. */
  | 'inconsistent';

export type CatchUpResult =
  | {
      readonly ok: true;
      readonly replica: Replica;
      /** Retained changes this replica did not hold and took in. */
      readonly added: number;
      /** The result was compared with the producer's fingerprint (only for a replica that held nothing). */
      readonly fingerprintChecked: boolean;
    }
  | { readonly ok: false; readonly reason: CatchUpFailure; readonly rejection?: Rejection };

/**
 * Starts a replica from a snapshot (or moves one forward). `snapshot` is the snapshot as read from
 * the wire (an object or its text). The producer must be trusted (`trustProducer`), its signature
 * must verify, and every retained change is judged like a received one (signature, check value, hash
 * chain, `mayWrite`, `allowFinalDelete`, `fieldRules`); one false change refuses the whole snapshot
 * and the replica is returned untouched by the caller (nothing is taken). What the retained changes
 * do not show cannot be checked: see `docs/snapshot.md`. A replica keeps the changes it holds; the
 * snapshot adds what it lacks and raises the stand, and the result remembers which numbers are
 * condensed (`Replica.base`).
 */
export async function catchUp(
  replica: Replica,
  snapshotValue: unknown,
  options: CatchUpOptions,
): Promise<CatchUpResult> {
  const snap =
    typeof snapshotValue === 'string'
      ? parseSnapshotText(snapshotValue, options)
      : parseSnapshot(snapshotValue, options);
  if (!snap) return { ok: false, reason: 'unreadable' };
  let trusted = false;
  try {
    trusted =
      options.trustProducer(
        snap.producer,
        {
          set: snap.set,
          clock: snap.clock,
          vector: snap.vector,
          fingerprint: snap.fingerprint,
          changes: snap.changes.length,
        },
        replica,
      ) === true;
  } catch {
    trusted = false;
  }
  if (!trusted) return { ok: false, reason: 'untrusted-producer' };
  // What this replica lacks, and the stand it reaches.
  const news = snap.changes.filter((c) => c.seq > seen(replica.vector, c.device));
  const vector = dict<number>();
  const base = dict<number>();
  for (const [device, n] of Object.entries(replica.vector)) vector[device] = n;
  for (const [device, n] of Object.entries(snap.vector)) {
    if (n > seen(replica.vector, device)) {
      vector[device] = n;
      base[device] = n;
    }
  }
  const taken = (): Replica => mergeRetained(replica, news, vector, snap.clock, base);
  const judge: JudgeOptions =
    options.fieldRules && !options.judge.fieldRules
      ? { ...options.judge, fieldRules: options.fieldRules }
      : options.judge;
  // A key source that checks what it reads may be shown the replica with the snapshot in it: the
  // device list inside the snapshot then makes its authors (and the producer) known.
  const keyState = judge.keys.selfVerifying === true ? taken() : replica;
  const context = { ...judge, state: replica, keyState };
  const producerKey = await judge.keys.keyFor(snap.producer, keyState);
  if (!producerKey) return { ok: false, reason: 'unknown-producer' };
  let signed = false;
  try {
    signed = await verifyText(
      producerKey,
      snapshotSigningText(judge.appId, snap, snap.set),
      snap.sig,
    );
  } catch {
    signed = false;
  }
  // The snapshot names its data set; it must be the one this device judges.
  if (!signed || snap.set !== judge.dataSet) return { ok: false, reason: 'bad-producer-signature' };
  const verdicts = await judgeRetained(context, snap.changes);
  for (let i = 0; i < verdicts.length; i += 1) {
    const verdict = verdicts[i];
    if (verdict?.verdict === 'false') {
      return {
        ok: false,
        reason: 'forged',
        rejection: {
          change: snap.changes[i] as Change,
          reason: verdict.reason ?? 'not-allowed',
          ...(verdict.detail !== undefined ? { detail: verdict.detail } : {}),
        },
      };
    }
    if (verdict?.verdict === 'pending') return { ok: false, reason: 'unknown-author' };
  }
  const result = keyState === replica ? taken() : keyState;
  const fresh = replica.log.length === 0 && Object.keys(replica.vector).length === 0;
  if (fresh && fingerprint(result) !== snap.fingerprint)
    return { ok: false, reason: 'inconsistent' };
  return { ok: true, replica: result, added: news.length, fingerprintChecked: fresh };
}
