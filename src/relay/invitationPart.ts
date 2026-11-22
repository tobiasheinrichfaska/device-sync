// The relay's invitation inside an invitation link of the trust layer (`Invitation.relayInvitation`):
// an `e2` (docs/relay-protocol.md, "Revision 2") that the new device takes in at the relay as its
// access. The trust layer only asks a validator whether the text is acceptable for the invitation's
// role and inviter; this is the usual validator. It reads the text strictly and compares what the
// relay will do with it (the role it sets, the device that made it) with what the log invitation says:
// when they disagree the whole invitation is refused, because the relay sets the new device's role
// from the `e2`, and an `e2` for the office inside the link of a member's device would make an
// office device out of it.
import { readInvitationR2, RELAY_ROLE, relayRoleOf } from './admission.ts';

export interface RelayInvitationRules {
  /** The app the `e2` must be for. */
  readonly appId: string;
  /**
   * The relay role the app's role maps to. Default `relayRoleOf`: the same text where the relay can
   * hold it, else `ohne` (never more rights than the app meant).
   */
  readonly relayRole?: (role: string) => string;
}

/**
 * A validator for `Validators.relayInvitation`: the text is an `e2` for this app whose role is the relay
 * role of the invitation's role and, when the link names the inviter's relay id, whose inviter is that
 * device. Never throws.
 */
export function relayInvitationValidator(
  rules: RelayInvitationRules,
): (
  text: string,
  context: { readonly role: string; readonly inviterRelayId: string | undefined },
) => boolean {
  return (text, context) => {
    try {
      const e = readInvitationR2(text);
      if (!e || e.app !== rules.appId) return false;
      const wanted = (rules.relayRole ?? relayRoleOf)(context.role);
      if (typeof wanted !== 'string' || !RELAY_ROLE.test(wanted) || e.role !== wanted) return false;
      return context.inviterRelayId === undefined || e.inviter === context.inviterRelayId;
    } catch {
      return false;
    }
  };
}
