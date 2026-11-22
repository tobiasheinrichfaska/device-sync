// The derived trust as a synchronous view, for rights hooks. A hook of the log layer is synchronous
// and runs on changes whose signatures were just verified, so the derivation may count the log as
// judged (`deriveSync`): nothing is verified a second time. `rightsView` is the `view` member of
// `JudgeOptions.rights` (see `docs/rights.md`): built once per judged batch from the replica with every
// verified change of the batch merged, so a device the batch introduces has its role.
import type { Replica } from '../log/index.ts';
import { deriveSync } from './derive.ts';
import type { KnownDevice, Trust, TrustOptions } from './types.ts';

/** What a rights hook may ask about a device. Every answer comes from the derivation, never from a raw entry. */
export interface TrustView {
  readonly trust: Trust;
  /**
   * The role of a device whose signatures can be checked (`Trust.checkable`: trusted, or removed or
   * fallen out with keys that were vouched for), as it was vouched for: also for a device that is
   * removed now, which keeps the role it had for what it wrote before. `undefined` for an unknown
   * device or one with a key conflict.
   */
  roleOf(device: string): string | undefined;
  /** The device is trusted now (not removed, vouched for through the chain or met in person). */
  trusted(device: string): boolean;
  /** The device fell out of trust: checkable but not trusted (removed, or vouched only through a removed device). */
  fallenOut(device: string): boolean;
}

/**
 * Synchronous trust of a replica, for decisions about changes that were judged (see `deriveSync`). Do
 * not call it on a replica that holds changes nobody verified: the derivation would believe them.
 */
export function computeTrustSync(
  replica: Replica,
  direct: readonly KnownDevice[],
  o: TrustOptions,
): Trust {
  return deriveSync(replica, direct, o).trust;
}

/** The view of one replica. */
export function trustView(
  replica: Replica,
  direct: readonly KnownDevice[],
  o: TrustOptions,
): TrustView {
  const trust = computeTrustSync(replica, direct, o);
  const trustedIds = new Set(trust.trusted.map((d) => d.device));
  return {
    trust,
    roleOf: (device) => {
      const entry = trust.checkableById.get(device);
      return entry ? (entry.role ?? entry.roleVouched) : undefined;
    },
    trusted: (device) => trustedIds.has(device),
    fallenOut: (device) => trust.checkableById.has(device) && !trustedIds.has(device),
  };
}

/**
 * The `view` of `JudgeOptions.rights` from the trust layer: `rights: { view: rightsView(direct, o), ... }`.
 * `direct` may be a function (asked once per batch). The type parameter lets the hooks that follow
 * see a `TrustView`.
 */
export const rightsView =
  (
    direct: readonly KnownDevice[] | (() => readonly KnownDevice[]),
    o: TrustOptions,
  ): ((batch: Replica) => TrustView) =>
  (batch) =>
    trustView(batch, typeof direct === 'function' ? direct() : direct, o);
