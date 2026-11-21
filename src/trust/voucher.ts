import type { Voucher } from './types.ts';

/** Every trusted device vouches, and may invite any role. */
export function vouchAll(): Voucher {
  return { canVouch: () => true, mayInvite: () => true };
}

/** Only a device with one of these roles vouches and may invite (any role). */
export function vouchRoles(roles: readonly string[]): Voucher {
  const allowed = new Set(roles);
  const has = (role: string | undefined): boolean => role !== undefined && allowed.has(role);
  return {
    canVouch: (device) => has(device.role),
    mayInvite: (inviter) => has(inviter.role),
  };
}

/** Every trusted device that has a (counting) role vouches; one without a role does not. */
export function vouchAnyRole(): Voucher {
  return {
    canVouch: (device) => device.role !== undefined,
    mayInvite: (inviter) => inviter.role !== undefined,
  };
}
