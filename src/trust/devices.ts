import { importPublicKey, verifyText } from '../core/index.ts';
import {
  changeCheckValue,
  changeSigningText,
  fieldHistory,
  findRecord,
  isHidden,
  liveRecords,
  visibleRecords,
  write,
  type DeviceId,
  type KeySource,
  type Origin,
  type Replica,
} from '../log/index.ts';
import { resolveValidators } from './ids.ts';
import { byName } from './known.ts';
import type {
  DeviceEntry,
  Introduction,
  KnownDevice,
  Trust,
  TrustedDevice,
  TrustOptions,
} from './types.ts';
import { parseIntroduction } from './wire.ts';

/** Default name of the reserved collection that holds the device list. */
export const DEVICE_COLLECTION = 'device';
/** The fields whose values count only as a voucher wrote them. */
const FIELDS = ['name', 'sig', 'dh', 'role', 'relayId', 'removed', 'private'] as const;
type Field = (typeof FIELDS)[number];

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
 * Enters a device this device took in (nothing is written when it stands so already). Another key
 * for an entered id is refused unless the device was removed ("remove first, then meet again").
 * `private` is written only when true, or when the entry already has a differing flag.
 */
export function addDevice(
  replica: Replica,
  o: TrustOptions,
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
  const was = (field: Field): unknown => old?.fields[field]?.value;
  if (was('sig') !== undefined && (was('sig') !== who.sig || was('dh') !== who.dh)) {
    if (was('removed') !== true) return { ok: false, reason: 'other-keys' };
  }
  const wanted: Record<string, unknown> = { name: who.name, sig: who.sig, dh: who.dh };
  if (role !== undefined) wanted.role = role;
  if (extra.relayId !== undefined) wanted.relayId = extra.relayId;
  if (was('removed') === true) wanted.removed = false;
  if (isPrivate || (was('private') !== undefined && was('private') !== extra.private)) {
    wanted.private = isPrivate;
  }
  const changed = Object.fromEntries(
    Object.entries(wanted).filter(([k, v]) => was(k as Field) !== v),
  );
  if (Object.keys(changed).length === 0) return { ok: true, replica };
  return put(replica, o, who.device, changed, origin);
}

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
  if (old.fields.name?.value === name) return { ok: true, replica };
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
  if ((old.fields.private?.value === true) === value) return { ok: true, replica };
  return put(replica, o, device, { private: value }, origin);
}

/** Removes a device: no device trusts it any more (what it already has stays with it). */
export function removeDevice(
  replica: Replica,
  o: TrustOptions,
  device: string,
  origin: Origin,
): DeviceResult {
  const old = findRecord(replica, collectionOf(o), device);
  if (!old || old.deleted || old.fields.removed?.value === true) return { ok: true, replica };
  return put(replica, o, device, { removed: true }, origin);
}

/** The entered devices as they stand (strictly read; a damaged record is left out). */
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
 * Whom this device trusts, derived from the log (never stored):
 * - the devices met in person (`direct`, as given, removed ones left out);
 * - then every entered device whose name and keys vouching trusted devices wrote: of each field
 *   counts the newest value this device or a vouching trusted device wrote with a signature that
 *   checks. What any other device wrote counts for nothing, and never what a device wrote into its
 *   own entry (it could undo its removal or name its own role);
 * - step by step, so a chain A -> B -> C works;
 * - `removed` = true so vouched ends trust, also a direct one, and what the removed device vouched
 *   for no longer counts through it. A removal ends trust from now on: the removed device's keys
 *   stay in `checkable`, so what it wrote before can still be checked.
 * Hidden ("deleted") entries end no trust: anybody could write that.
 */
export async function computeTrust(
  replica: Replica,
  direct: readonly KnownDevice[],
  o: TrustOptions,
): Promise<Trust> {
  const valid = resolveValidators(o.valid);
  const collection = collectionOf(o);
  const own = replica.device;
  const roleCounts = o.roleCounts ?? (() => true);
  const ids = liveRecords(replica, collection)
    .map((r) => r.id)
    .filter((id) => id !== own);
  const history = new Map(
    [...ids, own].map((id) => [
      id,
      new Map(FIELDS.map((f) => [f, fieldHistory(replica, collection, id, f)])),
    ]),
  );
  const keys = new Map<string, Promise<CryptoKey | undefined>>();
  const keyOf = (sig: string): Promise<CryptoKey | undefined> => {
    let key = keys.get(sig);
    if (!key) keys.set(sig, (key = importPublicKey(sig, 'sig')));
    return key;
  };
  const verdicts = new Map<string, Promise<boolean>>();
  const signedRight = (device: DeviceId, seq: number, sig: string): Promise<boolean> => {
    const memo = `${device}#${seq}#${sig}`;
    let verdict = verdicts.get(memo);
    if (!verdict) {
      verdict = (async () => {
        const change = replica.log.find((c) => c.device === device && c.seq === seq);
        if (!change || change.kind !== 'set' || !change.sig || !change.check) return false;
        if (changeCheckValue(change) !== change.check) return false;
        const key = await keyOf(sig);
        if (!key) return false;
        return verifyText(key, changeSigningText(o.appId, change, o.dataSet), change.sig);
      })();
      verdicts.set(memo, verdict);
    }
    return verdict;
  };

  const value = async (
    id: string,
    field: Field,
    vouchers: ReadonlyMap<string, string>,
  ): Promise<{ readonly value: unknown } | undefined> => {
    for (const w of history.get(id)?.get(field) ?? []) {
      if (w.device === id) continue;
      if (w.device === own) return { value: w.value };
      const sig = vouchers.get(w.device);
      if (sig !== undefined && (await signedRight(w.device, w.seq, sig))) return { value: w.value };
    }
    return undefined;
  };

  /** The entry as vouched; undefined without a vouched name and keys. */
  const vouched = async (
    id: string,
    vouchers: ReadonlyMap<string, string>,
  ): Promise<TrustedDevice | undefined> => {
    const v = async (f: Field) => (await value(id, f, vouchers))?.value;
    const intro = parseIntroduction(
      { device: id, name: await v('name'), sig: await v('sig'), dh: await v('dh') },
      valid,
    );
    if (!intro) return undefined;
    const role = await v('role');
    const relayId = await v('relayId');
    const roleOk = typeof role === 'string' && valid.role(role);
    return {
      ...intro,
      ...(roleOk && roleCounts(role, replica) ? { role } : {}),
      ...(roleOk ? { roleVouched: role } : {}),
      ...(typeof relayId === 'string' && valid.relayId(relayId) ? { relayId } : {}),
      removed: (await v('removed')) === true,
      private: (await v('private')) === true,
    };
  };

  const hull = async (gone: ReadonlySet<string>) => {
    const result = new Map<string, TrustedDevice>();
    const vouchers = new Map<string, string>();
    const refresh = (): void => {
      vouchers.clear();
      const all = [...result.values()];
      for (const b of all) if (o.voucher.canVouch(b, all)) vouchers.set(b.device, b.sig);
    };
    for (const b of direct) {
      if (gone.has(b.device)) continue;
      const roleOk = b.role !== undefined && valid.role(b.role);
      const { role: _role, ...rest } = b;
      result.set(b.device, {
        ...rest,
        ...(roleOk && roleCounts(b.role as string, replica) ? { role: b.role as string } : {}),
        ...(roleOk ? { roleVouched: b.role as string } : {}),
        removed: false,
        private: false,
      });
    }
    refresh();
    for (let more = true; more;) {
      more = false;
      for (const id of ids) {
        if (gone.has(id)) continue;
        const e = await vouched(id, vouchers);
        if (!e || e.removed) continue;
        const there = result.get(id);
        if (there) {
          // known already: other keys are another device (ignored); a role learned now counts from here on
          if (there.sig !== e.sig || there.dh !== e.dh || !e.role || there.role) continue;
          result.set(id, { ...there, role: e.role, roleVouched: e.role });
          refresh();
          more = true;
          continue;
        }
        result.set(id, e);
        refresh();
        more = true;
      }
    }
    return { result, vouchers };
  };

  let gone = new Set<string>();
  for (;;) {
    const { result, vouchers } = await hull(gone);
    const next = new Set(gone);
    for (const id of ids) {
      if (!next.has(id) && (await value(id, 'removed', vouchers))?.value === true) next.add(id);
    }
    if (next.size === gone.size) {
      const removedEntries: TrustedDevice[] = [];
      for (const id of gone) {
        const met = direct.find((b) => b.device === id);
        if (met) {
          const { role, ...rest } = met;
          removedEntries.push({
            ...rest,
            ...(role !== undefined ? { role } : {}),
            removed: true,
            private: false,
          });
        } else {
          const e = await vouched(id, vouchers);
          if (e) removedEntries.push({ ...e, removed: true });
        }
      }
      const trusted = [...result.values()].sort(byName);
      return {
        trusted,
        checkable: [...trusted, ...removedEntries].sort(byName),
        removed: [...gone].sort(),
        selfRemoved: (await value(own, 'removed', vouchers))?.value === true,
      };
    }
    gone = next;
  }
}

export interface DeviceKeySourceOptions extends TrustOptions {
  /** The devices met in person; a function is asked on every new replica state. */
  readonly direct: readonly KnownDevice[] | (() => readonly KnownDevice[]);
  /** This device's own public signing key, for the changes it holds itself. */
  readonly own?: { readonly device: DeviceId; readonly publicKey: CryptoKey };
}

/**
 * A `KeySource` for `readChanges` / `judgeChanges`: the key of every device whose signatures can be
 * checked (`Trust.checkable`) in the replica as it would be with everything taken so far, so a change
 * that enters a device makes that device's later changes of the same batch checkable. Unknown
 * devices give undefined: their changes stay `pending`. The derivation runs once per replica state.
 * Whether a checkable device may *write* something is the app's `mayWrite` rule (a removed device
 * stays checkable).
 */
export function deviceKeySource(o: DeviceKeySourceOptions): KeySource {
  const cache = new WeakMap<Replica, Promise<Trust>>();
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
      const found = (await trustOf(state)).checkable.find((d) => d.device === device);
      return found ? importPublicKey(found.sig, 'sig') : undefined;
    },
  };
}
