import { importPublicKey } from '../core/index.ts';
import {
  findRecord,
  isHidden,
  visibleRecords,
  write,
  type DeviceId,
  type KeySource,
  type Origin,
  type Replica,
} from '../log/index.ts';
import { DEVICE_COLLECTION, deriveAsync, deriveSync, entryIndex } from './derive.ts';
import { resolveValidators } from './ids.ts';
import type {
  DeviceEntry,
  DeviceStatus,
  Introduction,
  KnownDevice,
  Trust,
  TrustOptions,
} from './types.ts';
import { parseIntroduction } from './wire.ts';

export { DEVICE_COLLECTION };

/** `TrustOptions` plus the devices met in person: what the local writing functions decide against. */
export interface LocalTrustOptions extends TrustOptions {
  /** The devices met in person (default none: then only this device's own entries vouch). */
  readonly direct?: readonly KnownDevice[];
}

/**
 * The list `JudgeOptions.neverErase` needs: entries of the device list are never finally deleted
 * (a removal is the field `removed`), so a forwarder cannot erase a device's history.
 */
export const deviceNeverErase = (collection: string = DEVICE_COLLECTION): readonly string[] => [
  collection,
];

export type DeviceError =
  | 'bad-id'
  | 'bad-name'
  | 'bad-role'
  | 'bad-relay-id'
  | 'bad-value'
  | 'private-role'
  | 'record-deleted'
  | 'other-keys'
  | 'removed'
  | 'not-entered'
  | 'write-refused';

export type DeviceResult =
  | { readonly ok: true; readonly replica: Replica }
  | { readonly ok: false; readonly reason: DeviceError };

const collectionOf = (o: TrustOptions): string => o.collection ?? DEVICE_COLLECTION;

function put(
  replica: Replica,
  o: TrustOptions,
  device: string,
  fields: Record<string, unknown>,
  origin: Origin,
): DeviceResult {
  const out = write(replica, collectionOf(o), device, fields, origin);
  return out.ok ? { ok: true, replica: out.replica } : { ok: false, reason: 'write-refused' };
}

/**
 * Enters a device this device took in. It decides against the DERIVED state (what the log vouches
 * for, `docs/wire-format.md` "Trust derivation"), not against the raw entry: what a device that does
 * not vouch wrote into the entry counts for nothing, so it neither blocks this write nor makes it
 * unnecessary. Nothing is written when the entry already stands as wanted for the vouching devices.
 * Other keys than the vouched ones are refused (`other-keys`); a device that is removed stays
 * removed (`removed`): the same id is never admitted again, a re-admission is a NEW device id.
 * `private` is written only when true, or when the vouched entry has a differing flag.
 */
export function addDevice(
  replica: Replica,
  o: LocalTrustOptions,
  who: Introduction,
  role: string | undefined,
  origin: Origin,
  extra: { readonly private?: boolean; readonly relayId?: string } = {},
): DeviceResult {
  const valid = resolveValidators(o.valid);
  if (!parseIntroduction(who, valid)) {
    return { ok: false, reason: valid.deviceId(who.device) ? 'bad-name' : 'bad-id' };
  }
  if (role !== undefined && !valid.role(role)) return { ok: false, reason: 'bad-role' };
  const isPrivate = extra.private === true;
  if (isPrivate && role !== undefined && !valid.privateRoles(role)) {
    return { ok: false, reason: 'private-role' };
  }
  if (extra.relayId !== undefined && !valid.relayId(extra.relayId)) {
    return { ok: false, reason: 'bad-relay-id' };
  }
  const old = findRecord(replica, collectionOf(o), who.device);
  if (old?.deleted) return { ok: false, reason: 'record-deleted' };
  const wanted: Record<string, unknown> = { name: who.name, sig: who.sig, dh: who.dh };
  if (role !== undefined) wanted.role = role;
  if (extra.relayId !== undefined) wanted.relayId = extra.relayId;
  // What stands: the entry as vouched (this device's own record is its own, read as written).
  let stands: Record<string, unknown> | undefined;
  if (who.device === replica.device) {
    const raw = (field: string): unknown => old?.fields[field]?.value;
    if (raw('removed') === true) return { ok: false, reason: 'removed' };
    if (raw('sig') !== undefined) {
      stands = Object.fromEntries(
        ['name', 'sig', 'dh', 'role', 'relayId', 'private'].map((f) => [f, raw(f)]),
      );
    }
  } else {
    const derived = deriveSync(replica, o.direct ?? [], o);
    if (derived.trust.removed.includes(who.device)) return { ok: false, reason: 'removed' };
    const entry = derived.logEntries.get(who.device);
    if (entry) {
      stands = {
        name: entry.name,
        sig: entry.sig,
        dh: entry.dh,
        role: entry.roleVouched,
        relayId: entry.relayId,
        private: entry.private,
      };
    }
  }
  if (stands && (stands.sig !== who.sig || stands.dh !== who.dh)) {
    return { ok: false, reason: 'other-keys' };
  }
  if (stands ? isPrivate !== (stands.private === true) : isPrivate) wanted.private = isPrivate;
  const changed = Object.fromEntries(
    Object.entries(wanted).filter(([k, v]) => !stands || stands[k] !== v),
  );
  if (Object.keys(changed).length === 0) return { ok: true, replica };
  return put(replica, o, who.device, changed, origin);
}

/** The value of a field when this device wrote the newest one (what it would not need to write again). */
const ownWord = (
  replica: Replica,
  record: NonNullable<ReturnType<typeof findRecord>>,
  field: string,
): unknown => {
  const current = record.fields[field];
  return current?.device === replica.device ? current.value : undefined;
};

/** Writes a new name into the entry of a device (the others take it when a voucher wrote it). */
export function renameDevice(
  replica: Replica,
  o: TrustOptions,
  device: string,
  name: string,
  origin: Origin,
): DeviceResult {
  if (typeof name !== 'string' || name !== name.trim() || !resolveValidators(o.valid).name(name)) {
    return { ok: false, reason: 'bad-name' };
  }
  const old = findRecord(replica, collectionOf(o), device);
  if (!old || old.deleted || isHidden(old)) return { ok: false, reason: 'not-entered' };
  if (ownWord(replica, old, 'name') === name) return { ok: true, replica };
  return put(replica, o, device, { name }, origin);
}

/** Sets or clears the "private device" flag; a missing field counts as false. */
export function setDevicePrivate(
  replica: Replica,
  o: TrustOptions,
  device: string,
  value: boolean,
  origin: Origin,
): DeviceResult {
  if (typeof value !== 'boolean') return { ok: false, reason: 'bad-value' };
  const old = findRecord(replica, collectionOf(o), device);
  if (!old || old.deleted || isHidden(old)) return { ok: false, reason: 'not-entered' };
  const role = old.fields.role?.value;
  if (value && typeof role === 'string' && !resolveValidators(o.valid).privateRoles(role)) {
    return { ok: false, reason: 'private-role' };
  }
  const mine = ownWord(replica, old, 'private');
  if (mine === value || (mine === undefined && old.fields.private === undefined && !value)) {
    return { ok: true, replica };
  }
  return put(replica, o, device, { private: value }, origin);
}

/**
 * Removes a device: it loses its standing as a voucher and as a device that can be introduced
 * through the chain (what it already has stays with it). It stays CHECKABLE: its signed changes,
 * earlier and later ones, still verify. This layer does not stop a removed device from writing:
 * the app stops exchanging with it, restricts it with `mayWrite`, treats what it wrote as untrusted
 * (`deviceStatus`) and rotates its group keys. Writes `removed: true`. Nothing is written when this
 * device's own word is already "removed" (what the device itself or a non-voucher wrote into the
 * entry counts for nothing, so it does not make the removal unnecessary).
 */
export function removeDevice(
  replica: Replica,
  o: TrustOptions,
  device: string,
  origin: Origin,
): DeviceResult {
  const old = findRecord(replica, collectionOf(o), device);
  if (!old || old.deleted) return { ok: true, replica };
  const mine = entryIndex(replica, collectionOf(o))
    .targets.get(device)
    ?.get('removed')
    ?.find((w) => w.device === replica.device);
  if (mine?.value === true) return { ok: true, replica };
  return put(replica, o, device, { removed: true }, origin);
}

/**
 * The entries of the device list as they stand in the log (strictly read; a damaged record is left
 * out): a DISPLAY of raw entries. `removed` and `role` here are what some device wrote last, whoever
 * it was; they say nothing about trust. Ask `deviceStatus` or `computeTrust` for the derived state.
 */
export function listDevices(replica: Replica, o: TrustOptions): DeviceEntry[] {
  const valid = resolveValidators(o.valid);
  return visibleRecords(replica, collectionOf(o)).flatMap((r): DeviceEntry[] => {
    const intro = parseIntroduction(
      {
        device: r.id,
        name: r.fields.name?.value,
        sig: r.fields.sig?.value,
        dh: r.fields.dh?.value,
      },
      valid,
    );
    if (!intro) return [];
    const role = r.fields.role?.value;
    const relayId = r.fields.relayId?.value;
    return [
      {
        ...intro,
        ...(typeof role === 'string' && valid.role(role) ? { role } : {}),
        ...(typeof relayId === 'string' && valid.relayId(relayId) ? { relayId } : {}),
        removed: r.fields.removed?.value === true,
        private: r.fields.private?.value === true,
      },
    ];
  });
}

/**
 * Whom this device trusts, derived from the log (never stored). The rules (potential trust from the
 * devices met in person, effective removals in rank order, key consistency among the vouchers
 * that were not removed, reachability) are in `docs/wire-format.md`, "Trust derivation". The result depends on the set of
 * changes in the log and on `direct`, never on the order records were created or arrived in.
 */
export async function computeTrust(
  replica: Replica,
  direct: readonly KnownDevice[],
  o: TrustOptions,
): Promise<Trust> {
  return (await deriveAsync(replica, direct, o)).trust;
}

/** The derived state of one device id: trusted, checkable, removed and why. */
export async function deviceStatus(
  replica: Replica,
  device: DeviceId,
  o: LocalTrustOptions,
): Promise<DeviceStatus> {
  const t = await computeTrust(replica, o.direct ?? [], o);
  const trusted = t.trusted.some((d) => d.device === device);
  const removed = t.removed.includes(device);
  const reasons = [...(t.reasons.get(device) ?? [])];
  if (!trusted && reasons.length === 0) reasons.push('not-vouched');
  return { trusted, checkable: t.checkableById.has(device), removed, reasons };
}

export interface DeviceKeySourceOptions extends TrustOptions {
  /** The devices met in person; a function is asked on every new replica state. */
  readonly direct: readonly KnownDevice[] | (() => readonly KnownDevice[]);
  /** This device's own public signing key, for the changes it holds itself. */
  readonly own?: { readonly device: DeviceId; readonly publicKey: CryptoKey };
}

/**
 * A `KeySource` for `readChanges` / `judgeChanges`: the key of every device whose signatures can be
 * checked (`Trust.checkable`: the trusted devices and the removed ones, whose signed changes keep
 * verifying; the key source says who can be checked, not who may write), in the replica as it would
 * be with everything taken so far, so a change that enters a device makes that device's later
 * changes of the same batch checkable. Unknown devices give undefined: their changes stay `pending`.
 * The derivation runs once per replica state and every answer is a lookup in it. The device list is
 * never finally deleted (`neverErase`).
 */
export function deviceKeySource(o: DeviceKeySourceOptions): KeySource {
  const cache = new WeakMap<Replica, Promise<Trust>>();
  const keys = new Map<string, Promise<CryptoKey | undefined>>();
  const keyOf = (sig: string): Promise<CryptoKey | undefined> => {
    let key = keys.get(sig);
    if (!key) keys.set(sig, (key = importPublicKey(sig, 'sig')));
    return key;
  };
  const trustOf = (state: Replica): Promise<Trust> => {
    let trust = cache.get(state);
    if (!trust) {
      const direct = typeof o.direct === 'function' ? o.direct() : o.direct;
      cache.set(state, (trust = computeTrust(state, direct, o)));
    }
    return trust;
  };
  return {
    async keyFor(device, state) {
      if (o.own && device === o.own.device) return o.own.publicKey;
      const found = (await trustOf(state)).checkableById.get(device);
      return found ? keyOf(found.sig) : undefined;
    },
    neverErase: [collectionOf(o)],
    // every entry it reads is signature-checked by the derivation (own writes excepted, which settle keeps out)
    selfVerifying: true,
  };
}
