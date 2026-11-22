// The only place the sync layer touches the group layer. It speaks to the group layer through its
// public API (`needsRotation`, `rotateGroup`, `issueGrants`, `GroupTrust`) so that a change there
// (for example a signature parameter on grants) is a change of this file alone.
//
// The sync step reports who was removed (`SyncReport.newlyRemoved`) and hands over the trust it
// derived; the app asks here whether the group key must be replaced and, if so, rotates and queues
// the grants. A grant travels as a sealed file through the same relay path (`queueFile`), so it
// reaches only devices that are peers at the moment it is sent.
import {
  isRotationLead,
  issueGrants,
  needsRotation,
  rotateGroup,
  type GroupOwn,
  type GroupRefusal,
  type GroupState,
  type GroupTrust,
  type IssuedGrant,
  type RandomBytes,
  type RotationNeed,
} from '../group/index.ts';
import type { Trust } from '../trust/index.ts';

/** The part of `Trust` the group layer takes (`Trust` fits as it is). */
export const groupTrustOf = (trust: Trust): GroupTrust => ({
  trusted: trust.trusted,
  removed: trust.removed,
  selfRemoved: trust.selfRemoved,
});

export interface RotationStatus extends RotationNeed {
  /** This device holds the current key and has the lowest id of the trusted holders: it should act first. */
  readonly lead: boolean;
}

/** What the current key still needs after the removals this trust shows (see `needsRotation`). */
export function rotationStatus(state: GroupState, trust: Trust, own: string): RotationStatus {
  const gt = groupTrustOf(trust);
  return { ...needsRotation(state, gt), lead: isRotationLead(state, gt, own) };
}

export type RotationOutcome =
  | {
      readonly ok: true;
      readonly state: GroupState;
      /** One sealed file per trusted device; hand each to `queueFile`. */
      readonly grants: readonly IssuedGrant[];
      readonly rotated: { readonly epoch: number; readonly kid: string };
    }
  | { readonly ok: false; readonly reason: GroupRefusal | 'not-needed' | 'not-lead' };

export interface RotateAfterRemovalParams {
  readonly appId: string;
  readonly own: GroupOwn;
  readonly trust: Trust;
  readonly state: GroupState;
  readonly random: RandomBytes;
  /** Rotate even when this device is not the lead (the lead is offline). Default false. */
  readonly force?: boolean;
}

/**
 * Makes the next key for the trusted devices only, when the current key was given to a removed
 * device (`needsRotation`). Refuses with `not-needed` when nothing calls for it and with `not-lead`
 * when another trusted holder has the lower id (pass `force` when that device is gone: concurrent
 * rotations converge, see docs/group.md).
 */
export async function rotateAfterRemoval(p: RotateAfterRemovalParams): Promise<RotationOutcome> {
  const status = rotationStatus(p.state, p.trust, p.own.device);
  if (!status.needed) return { ok: false, reason: 'not-needed' };
  if (!status.lead && p.force !== true) return { ok: false, reason: 'not-lead' };
  const out = await rotateGroup({
    appId: p.appId,
    own: p.own,
    trust: groupTrustOf(p.trust),
    state: p.state,
    random: p.random,
  });
  if (!out.ok) return out;
  if (!('rotated' in out) || out.rotated === undefined) return { ok: false, reason: 'bad-input' };
  return { ok: true, state: out.state, grants: out.grants, rotated: out.rotated };
}

/** Passes the held key on to trusted devices that were missed (`needsRotation(...).missing`). */
export async function grantToMissing(
  p: Omit<RotateAfterRemovalParams, 'force'> & { readonly which?: 'current' | 'all' },
): Promise<
  | { readonly ok: true; readonly state: GroupState; readonly grants: readonly IssuedGrant[] }
  | { readonly ok: false; readonly reason: GroupRefusal | 'not-needed' }
> {
  const { missing } = rotationStatus(p.state, p.trust, p.own.device);
  if (missing.length === 0) return { ok: false, reason: 'not-needed' };
  const out = await issueGrants({
    appId: p.appId,
    own: p.own,
    trust: groupTrustOf(p.trust),
    state: p.state,
    random: p.random,
    to: missing,
    which: p.which ?? 'current',
  });
  return out.ok ? { ok: true, state: out.state, grants: out.grants } : out;
}
