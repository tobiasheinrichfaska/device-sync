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
  /** A removed device is trusted no more; its entry stays. */
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

/** The result of `computeTrust`. */
export interface Trust {
  /** Trusted devices: the met ones and those a voucher entered (removed ones left out). */
  readonly trusted: readonly TrustedDevice[];
  /** Devices whose signatures can be checked: the trusted ones and the removed ones whose keys were vouched for. */
  readonly checkable: readonly TrustedDevice[];
  /** Ids whose removal counts. */
  readonly removed: readonly DeviceId[];
  /** A trusted vouching device removed this device itself. */
  readonly selfRemoved: boolean;
}

/** Who may vouch for other devices, and who may invite which role. The package hard-wires no role. */
export interface Voucher {
  /**
   * Whether a trusted device vouches (its entries for other devices count). `entries` = the trusted
   * devices so far, `device` among them. Asked again on every pass of the derivation.
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
