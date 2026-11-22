import type { DeviceId } from '../log/index.ts';

/** What a device says about itself: its id, a display name and its two public keys. */
export interface Introduction {
  readonly device: DeviceId;
  readonly name: string;
  readonly sig: string;
  readonly dh: string;
}

/** One entry of the device list as it stands in the log (strictly read). */
export interface DeviceEntry extends Introduction {
  /** What the device is for; opaque to the package (the app's `role` predicate decides what is valid). */
  readonly role?: string;
  /** The id the relay gave the device at enrolment (opaque; the app's `relayId` predicate checks it). */
  readonly relayId?: string;
  /** A removed device is trusted no more (not as a voucher, not as introduced); its entry stays and its signatures still verify. */
  readonly removed: boolean;
  /** The "private device" flag. */
  readonly private: boolean;
}

/** A device this device met in person (its own list, kept on this device only). */
export interface KnownDevice extends Introduction {
  readonly role?: string;
  readonly relayId?: string;
  /** Date it was taken in, `YYYY-MM-DD`. */
  readonly since: string;
  /** The check code of the device (five groups of four digits, see `checkCode`). */
  readonly checkCode: string;
}

/** A device the trust derivation counts: a met one or one a voucher entered. */
export interface TrustedDevice extends DeviceEntry {
  /** The role as it was vouched for, also when it counts no more (`roleCounts` said no). */
  readonly roleVouched?: string;
  /** Date from the own list; missing for a device known only through others. */
  readonly since?: string;
}

/** Why a device is not (fully) trusted, or what was left out of its entry. */
export type TrustReason =
  /** Vouching devices wrote more than one signing or agreement key for it: not trusted through the chain. */
  | 'key-conflict'
  /** A device met in person: a voucher wrote other keys than the ones learned in person (ignored). */
  | 'key-mismatch'
  /** Vouching devices wrote more than one relay id: the relay id is dropped, the device stays trusted. */
  | 'relay-conflict'
  /** A removal counts (see `docs/wire-format.md`, "Trust derivation", rule 3). The device stays checkable. */
  | 'removed'
  /** Nobody trusted vouches for it (or not completely). */
  | 'not-vouched';

/** The derived state of one device id (`deviceStatus`). */
export interface DeviceStatus {
  readonly trusted: boolean;
  /** Its signatures can be checked: trusted, or removed with keys that were vouched for. */
  readonly checkable: boolean;
  /** An effective removal exists: no standing as a voucher or as a device introduced through the chain. */
  readonly removed: boolean;
  readonly reasons: readonly TrustReason[];
}

/** The result of `computeTrust`. */
export interface Trust {
  /** Trusted devices: the met ones and those a voucher entered (removed ones left out). */
  readonly trusted: readonly TrustedDevice[];
  /** Devices whose signatures can be checked: the trusted ones and the removed ones whose keys were vouched for. */
  readonly checkable: readonly TrustedDevice[];
  /** Ids with an effective removal (this device itself excluded, see `selfRemoved`), sorted. */
  readonly removed: readonly DeviceId[];
  /** A removal of this device itself counts. */
  readonly selfRemoved: boolean;
  /** The checkable devices by id. */
  readonly checkableById: ReadonlyMap<DeviceId, TrustedDevice>;
  /** Per device the reasons worth reporting (only devices that have some). */
  readonly reasons: ReadonlyMap<DeviceId, readonly TrustReason[]>;
}

/** Who may vouch for other devices, and who may invite which role. The package hard-wires no role. */
export interface Voucher {
  /**
   * Whether a trusted device vouches (its entries for other devices count). `entries` = the devices
   * of the derivation so far (a live view: do not keep it), `device` among them. Asked when a device
   * joins and again when its entry changes; answer from the entry (role), not from the list.
   */
  canVouch(device: DeviceEntry, entries: readonly DeviceEntry[]): boolean;
  /** Whether this inviter may invite a device with this role. Missing: only a device that can vouch. */
  mayInvite?(inviter: DeviceEntry, role: string): boolean;
}

/** The app's predicates; each default is used for what is not given. A predicate that throws counts as false. */
export interface Validators {
  /** A device id; default `DEVICE_ID`. */
  readonly deviceId: (id: string) => boolean;
  /** A display name; default `DEVICE_NAME`. */
  readonly name: (name: string) => boolean;
  /** A role; default `ROLE`. */
  readonly role: (role: string) => boolean;
  /** A relay id; default: 1 to 80 characters without control characters. */
  readonly relayId: (id: string) => boolean;
  /**
   * Roles a private device may hold. Default: all. An app that wants its highest role never on a
   * private device says so here (a domain rule of the earlier implementations, left to the app).
   */
  readonly privateRoles: (role: string) => boolean;
  /**
   * The relay's own invitation carried inside the invitation link (`relayInvitation`): whether this text
   * is acceptable for an invitation of this role and this inviter. An invitation whose relay part is not
   * is refused as a whole. Default: nothing is acceptable, so an app that does not use the relay's
   * invitation never takes the member (`relayInvitationValidator` of the relay layer is the usual one).
   */
  readonly relayInvitation: (text: string, context: RelayInvitationContext) => boolean;
}

/** What a validator of the relay part may compare it with: the role of the log invitation and the inviter's relay id. */
export interface RelayInvitationContext {
  readonly role: string;
  /** The inviter's relay id as the invitation carries it (`relayId`), when it does. */
  readonly inviterRelayId: string | undefined;
}

/** What the strict parsers and the code/invitation functions need. */
export interface ProtocolOptions {
  readonly appId: string;
  readonly valid?: Partial<Validators>;
}

/** What the device list in the log and the derivation need. */
export interface TrustOptions extends ProtocolOptions {
  /** The data set the changes belong to (a signature names it, see `judgeChanges`). */
  readonly dataSet: string;
  /** Name of the reserved collection of the device list; default `DEVICE_COLLECTION`. */
  readonly collection?: string;
  readonly voucher: Voucher;
  /** Whether a role still counts in this replica (e.g. the person it names still exists); default always. */
  readonly roleCounts?: (role: string, replica: import('../log/index.ts').Replica) => boolean;
}
