import type { RelayInvitationContext, Validators } from './types.ts';

/** Default device id: `device-` and 32 lower-case hex digits (128 random bits). */
export const DEVICE_ID = /^device-[0-9a-f]{32}$/;
/** Default display name: 1 to 40 letters, digits, spaces, dot, underscore, hyphen. */
export const DEVICE_NAME = /^[\p{L}\p{N} ._-]{1,40}$/u;
/** Default role: starts with a lower-case letter, then up to 79 of `a-z 0-9 : _ -`. */
export const ROLE = /^[a-z][a-z0-9:_-]{0,79}$/;
const CONTROL = /\p{Cc}/u;
/** The longest relay invitation text an invitation link carries (an `e2` is about 250 characters). */
export const MAX_RELAY_INVITATION = 400;

/** A new device id from 16 random bytes (the caller supplies the randomness). */
export function newDeviceId(random: Uint8Array): string {
  if (!(random instanceof Uint8Array) || random.length !== 16) {
    throw new TypeError('a device id needs 16 random bytes');
  }
  let hex = '';
  for (const b of random) hex += b.toString(16).padStart(2, '0');
  return `device-${hex}`;
}

/** A predicate made safe: a throw is false; `|` never passes (it separates the signed and MACed texts). */
const safe =
  (test: (s: string) => boolean, separatorFree: boolean) =>
  (s: string): boolean => {
    if (typeof s !== 'string' || (separatorFree && s.includes('|'))) return false;
    try {
      return test(s) === true;
    } catch {
      return false;
    }
  };

/** The app's predicates on top of the defaults. */
export function resolveValidators(given?: Partial<Validators>): Validators {
  return {
    deviceId: safe(given?.deviceId ?? ((s) => DEVICE_ID.test(s)), true),
    name: safe(given?.name ?? ((s) => DEVICE_NAME.test(s)), true),
    role: safe(given?.role ?? ((s) => ROLE.test(s)), true),
    relayId: safe(
      given?.relayId ?? ((s) => s.length >= 1 && s.length <= 80 && !CONTROL.test(s)),
      false,
    ),
    privateRoles: safe(given?.privateRoles ?? (() => true), false),
    relayInvitation: (s: string, context: RelayInvitationContext): boolean => {
      if (typeof s !== 'string' || s.length === 0 || s.length > MAX_RELAY_INVITATION) return false;
      try {
        return (given?.relayInvitation ?? (() => false))(s, context) === true;
      } catch {
        return false;
      }
    },
  };
}
