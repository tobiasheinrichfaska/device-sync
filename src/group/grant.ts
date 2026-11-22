// Making, distributing and accepting keys. A grant is an encrypted file (core layer) for ONE named
// device: it authenticates the sender by the static agreement keys, so who may send a grant is the
// trust layer's decision (`GroupTrust`). Randomness is a parameter; there is no clock.
import { base64url, fromBase64url } from '../core/encoding.ts';
import { openFile, readFileHeader, sealFile } from '../core/file.ts';
import { compareUtf8, isDeviceText } from '../core/secure.ts';
import { KEY_BYTES, deriveKeyId } from './derive.ts';
import { MAX_EPOCH, maxGrantChars, resolveGroupLimits, type GroupLimits } from './limits.ts';
import { addKey, highestEpoch, preferredKey, type AddRefusal } from './state.ts';
import {
  grantText,
  isSetText,
  parseGrant,
  parseRequest,
  requestText,
  type GroupKey,
  type GroupState,
} from './wire.ts';

const utf8 = new TextEncoder();

/** The part of the trust layer's `Trust` this layer needs: who is trusted (with the agreement key) and who is removed. */
export interface GroupTrust {
  readonly trusted: readonly { readonly device: string; readonly dh: string }[];
  readonly removed: readonly string[];
  readonly selfRemoved?: boolean;
}

export interface GroupOwn {
  readonly device: string;
  readonly agreement: CryptoKeyPair;
}

/** Random bytes, as a parameter (a test passes a seeded one). Must return exactly `n` bytes. */
export type RandomBytes = (n: number) => Uint8Array;

export type GroupRefusal =
  | 'bad-input'
  | 'bad-own'
  | 'bad-random'
  | 'self-removed'
  | 'epoch-exhausted'
  | 'too-many-devices'
  | 'not-a-grant'
  | 'not-a-request'
  | 'wrong-recipient'
  | 'sender-not-trusted'
  | 'cannot-open'
  | 'bad-payload'
  | 'wrong-data-set'
  | 'author-removed'
  | 'not-in-audience'
  | 'bad-recipient'
  | 'no-key'
  | AddRefusal;

export interface IssuedGrant {
  readonly to: string;
  /** The bytes of the encrypted file: any transport (a session message, an envelope payload) carries them. */
  readonly file: Uint8Array;
}

const filePayloadBytes = (lim: GroupLimits): number => maxGrantChars(lim) * 3;

async function sealPayload(
  appId: string,
  own: GroupOwn,
  to: { device: string; dh: string },
  text: string,
  random: RandomBytes,
  lim: GroupLimits,
): Promise<{ ok: true; file: Uint8Array } | { ok: false; reason: GroupRefusal }> {
  let iv: Uint8Array;
  try {
    iv = random(12);
  } catch {
    return { ok: false, reason: 'bad-random' };
  }
  const sealed = await sealFile({
    appId,
    own,
    to,
    payload: utf8.encode(text),
    random: iv,
    limits: { maxPlaintextBytes: filePayloadBytes(lim) },
  });
  if (sealed.ok) return sealed;
  const reason = sealed.reason;
  if (reason === 'bad-recipient' || reason === 'same-key' || reason === 'same-device') {
    return { ok: false, reason: 'bad-recipient' };
  }
  return { ok: false, reason: reason === 'bad-random' ? 'bad-random' : 'bad-own' };
}

/** Opens a file for this device from a device the trust layer trusts; the payload is bytes. */
async function openPayload(
  appId: string,
  own: GroupOwn,
  trust: GroupTrust,
  file: Uint8Array,
  lim: GroupLimits,
  notAFile: GroupRefusal,
): Promise<{ ok: true; from: string; text: string } | { ok: false; reason: GroupRefusal }> {
  const limits = { maxPlaintextBytes: filePayloadBytes(lim) };
  const header = readFileHeader(appId, file, limits);
  if (!header) return { ok: false, reason: notAFile };
  if (header.to !== own.device) return { ok: false, reason: 'wrong-recipient' };
  // Before any key agreement: the sender must be a trusted, not removed device.
  const sender = trust.trusted.find((d) => d.device === header.from);
  if (!sender || trust.removed.includes(header.from)) {
    return { ok: false, reason: 'sender-not-trusted' };
  }
  const opened = await openFile({
    appId,
    own,
    from: { device: sender.device, dh: sender.dh },
    file,
    limits,
  });
  if (!opened.ok)
    return { ok: false, reason: opened.reason === 'bad-own' ? 'bad-own' : 'cannot-open' };
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(opened.payload);
  } catch {
    return { ok: false, reason: 'bad-payload' };
  }
  return { ok: true, from: header.from, text };
}

const sortedIds = (ids: Iterable<string>): string[] => [...new Set(ids)].sort(compareUtf8);

export type IssueResult =
  | {
      readonly ok: true;
      readonly state: GroupState;
      readonly grants: readonly IssuedGrant[];
      /** Recipients a grant could not be made for (their key is unusable). */
      readonly skipped: readonly string[];
    }
  | { readonly ok: false; readonly reason: GroupRefusal };

export interface RotateParams {
  readonly appId: string;
  readonly own: GroupOwn;
  readonly trust: GroupTrust;
  readonly state: GroupState;
  readonly random: RandomBytes;
  readonly limits?: Partial<GroupLimits>;
}

export interface RotateResult {
  readonly epoch: number;
  readonly kid: string;
}

/**
 * Makes the key of the next epoch (the highest held plus one; epoch 1 for an empty state) and one
 * grant for every trusted device. The removed devices are not in `trust.trusted`, so they get no
 * grant and are not in the audience. Use it to start a group, after a removal and on request.
 */
export async function rotateGroup(
  params: RotateParams,
): Promise<
  (IssueResult & { readonly rotated?: RotateResult }) | { ok: false; reason: GroupRefusal }
> {
  const { appId, own, trust, state, random } = params;
  const lim = resolveGroupLimits(params.limits);
  if (!isDeviceText(own?.device) || !isSetText(state?.dataSet))
    return { ok: false, reason: 'bad-input' };
  if (trust.selfRemoved === true || trust.removed.includes(own.device)) {
    return { ok: false, reason: 'self-removed' };
  }
  const epoch = highestEpoch(state) + 1;
  if (epoch > MAX_EPOCH) return { ok: false, reason: 'epoch-exhausted' };
  const recipients = trust.trusted.filter(
    (d) => d.device !== own.device && !trust.removed.includes(d.device),
  );
  const audience = sortedIds([own.device, ...recipients.map((d) => d.device)]);
  if (audience.length > lim.maxAudience) return { ok: false, reason: 'too-many-devices' };
  let key: Uint8Array;
  try {
    key = random(KEY_BYTES);
  } catch {
    return { ok: false, reason: 'bad-random' };
  }
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) {
    return { ok: false, reason: 'bad-random' };
  }
  const record: GroupKey = {
    epoch,
    author: own.device,
    kid: await deriveKeyId(appId, state.dataSet, epoch, key),
    key: base64url(key),
    audience,
  };
  const added = addKey(state, record, lim);
  if (!added.ok) return added;
  const grants: IssuedGrant[] = [];
  const skipped: string[] = [];
  for (const to of recipients) {
    const text = grantText(appId, {
      set: state.dataSet,
      epoch,
      author: own.device,
      key: record.key,
      audience,
    });
    const sealed = await sealPayload(appId, own, to, text, random, lim);
    if (sealed.ok) grants.push({ to: to.device, file: sealed.file });
    else if (sealed.reason === 'bad-random') return { ok: false, reason: 'bad-random' };
    else skipped.push(to.device);
  }
  return { ok: true, state: added.state, grants, skipped, rotated: { epoch, kid: record.kid } };
}

export interface IssueParams extends Omit<RotateParams, 'state'> {
  readonly state: GroupState;
  /** The devices to give the keys to (each must be trusted and not removed). */
  readonly to: readonly string[];
  /** `current`: the key `preferredKey` names. `all`: every retained key (a new device that reads old data). */
  readonly which: 'current' | 'all';
}

/**
 * Passes keys this device holds on to trusted devices that lack them (a device that joined, or one
 * that missed a grant). The audience of each forwarded key grows by the recipient, so a device that
 * checks `needsRotation` sees it was given the key. Returns the state with the grown audiences.
 */
export async function issueGrants(params: IssueParams): Promise<IssueResult> {
  const { appId, own, trust, random } = params;
  let { state } = params;
  const lim = resolveGroupLimits(params.limits);
  if (!isDeviceText(own?.device)) return { ok: false, reason: 'bad-input' };
  if (trust.selfRemoved === true || trust.removed.includes(own.device)) {
    return { ok: false, reason: 'self-removed' };
  }
  const current = preferredKey(state);
  if (!current) return { ok: false, reason: 'no-key' };
  const targets = sortedIds(params.to);
  const recipients = targets.map((id) => trust.trusted.find((d) => d.device === id));
  if (recipients.some((r) => !r || r.device === own.device || trust.removed.includes(r.device))) {
    return { ok: false, reason: 'bad-recipient' };
  }
  const keys = params.which === 'all' ? state.keys : [current];
  const grants: IssuedGrant[] = [];
  const skipped: string[] = [];
  for (const to of recipients as { device: string; dh: string }[]) {
    for (const held of keys) {
      const audience = sortedIds([...held.audience, to.device]);
      if (audience.length > lim.maxAudience) return { ok: false, reason: 'audience-full' };
      const text = grantText(appId, {
        set: state.dataSet,
        epoch: held.epoch,
        author: held.author,
        key: held.key,
        audience,
      });
      const sealed = await sealPayload(appId, own, to, text, random, lim);
      if (!sealed.ok) {
        if (sealed.reason === 'bad-random') return { ok: false, reason: 'bad-random' };
        skipped.push(to.device);
        continue;
      }
      grants.push({ to: to.device, file: sealed.file });
      const merged = addKey(state, { ...held, audience }, lim);
      if (merged.ok) state = merged.state;
    }
  }
  return { ok: true, state, grants, skipped };
}

export interface AcceptParams {
  readonly appId: string;
  readonly own: GroupOwn;
  readonly trust: GroupTrust;
  readonly state: GroupState;
  readonly file: Uint8Array;
  readonly limits?: Partial<GroupLimits>;
}

export type AcceptResult =
  | {
      readonly ok: true;
      readonly state: GroupState;
      readonly key: GroupKey;
      readonly change: 'added' | 'audience' | 'same';
      /** The device that sent the file (it may differ from `key.author`: forwarded keys). */
      readonly from: string;
    }
  | { readonly ok: false; readonly reason: GroupRefusal };

/**
 * Takes a grant. Checks, in this order: the file is a file of this app for this device (strict
 * read, bounded); the sender is trusted and not removed (before any key agreement); the file opens;
 * the payload is a grant for this data set; the author is not removed; sender, author and this
 * device are in the audience; then the state's own rules (floor, epoch jump, caps). A replayed grant
 * of a held key changes nothing.
 */
export async function acceptGrant(params: AcceptParams): Promise<AcceptResult> {
  const { appId, own, trust, state, file } = params;
  const lim = resolveGroupLimits(params.limits);
  if (!isDeviceText(own?.device) || !isSetText(state?.dataSet))
    return { ok: false, reason: 'bad-input' };
  const opened = await openPayload(appId, own, trust, file, lim, 'not-a-grant');
  if (!opened.ok) return opened;
  const grant = parseGrant(appId, opened.text, lim);
  if (!grant) return { ok: false, reason: 'bad-payload' };
  if (grant.set !== state.dataSet) return { ok: false, reason: 'wrong-data-set' };
  if (trust.removed.includes(grant.author)) return { ok: false, reason: 'author-removed' };
  if (
    !grant.audience.includes(own.device) ||
    !grant.audience.includes(opened.from) ||
    !grant.audience.includes(grant.author)
  ) {
    return { ok: false, reason: 'not-in-audience' };
  }
  const key: GroupKey = {
    epoch: grant.epoch,
    author: grant.author,
    kid: await deriveKeyId(appId, grant.set, grant.epoch, fromBase64url(grant.key)),
    key: grant.key,
    audience: grant.audience,
  };
  const added = addKey(state, key, lim);
  if (!added.ok) return added;
  return { ok: true, state: added.state, key, change: added.change, from: opened.from };
}

export interface RotationNeed {
  readonly needed: boolean;
  /** Trusted devices that are not in the audience of the current key: give them the key (`issueGrants`). */
  readonly missing: readonly string[];
  /** Removed devices that were given the current key: rotate (`rotateGroup`). */
  readonly removedHolders: readonly string[];
}

/**
 * What the current key still needs. `needed` is true when a removed device was given it or no key is
 * held at all. The audience is the author's own claim: it finds honest mistakes (a removal that came
 * after the rotation, a device that was missed), it does not find a device a compromised author gave
 * the key to in secret.
 */
export function needsRotation(state: GroupState, trust: GroupTrust): RotationNeed {
  const current = preferredKey(state);
  if (!current) return { needed: true, missing: [], removedHolders: [] };
  const removedHolders = sortedIds(current.audience.filter((id) => trust.removed.includes(id)));
  const missing = sortedIds(
    trust.trusted
      .map((d) => d.device)
      .filter((id) => !current.audience.includes(id) && !trust.removed.includes(id)),
  );
  return { needed: removedHolders.length > 0, missing, removedHolders };
}

/**
 * Whether this device is the one that should rotate now: the trusted device that holds the current
 * key and has the lowest id in UTF-8 order. A hint that spares the group a rotation by every device
 * at once; if that device is offline another may rotate anyway (concurrent rotations converge).
 */
export function isRotationLead(state: GroupState, trust: GroupTrust, own: string): boolean {
  const current = preferredKey(state);
  if (!current || trust.removed.includes(own)) return false;
  const holders = current.audience.filter(
    (id) =>
      !trust.removed.includes(id) && (id === own || trust.trusted.some((d) => d.device === id)),
  );
  return holders.length > 0 && holders[0] === own;
}

// --- rotation request -------------------------------------------------------------------------

export interface RequestSealParams {
  readonly appId: string;
  readonly own: GroupOwn;
  readonly to: { readonly device: string; readonly dh: string };
  readonly state: GroupState;
  readonly random: RandomBytes;
  readonly limits?: Partial<GroupLimits>;
}

/** Asks one device that holds the key to rotate it. The request names the highest epoch this device holds. */
export async function sealRotationRequest(
  params: RequestSealParams,
): Promise<{ ok: true; file: Uint8Array } | { ok: false; reason: GroupRefusal }> {
  const lim = resolveGroupLimits(params.limits);
  const { appId, own, to, state, random } = params;
  if (!isDeviceText(own?.device) || !isSetText(state?.dataSet))
    return { ok: false, reason: 'bad-input' };
  const text = requestText(appId, { set: state.dataSet, epoch: highestEpoch(state) });
  return sealPayload(appId, own, to, text, random, lim);
}

export type RequestResult =
  | {
      readonly ok: true;
      readonly from: string;
      readonly epoch: number;
      /** The requester holds an epoch below this device's: it is behind, not asking for a rotation. */
      readonly stale: boolean;
    }
  | { readonly ok: false; readonly reason: GroupRefusal };

/** Opens a rotation request from a trusted device; the app decides whether to rotate (`stale` false). */
export async function openRotationRequest(
  params: Omit<AcceptParams, 'limits'> & { readonly limits?: Partial<GroupLimits> },
): Promise<RequestResult> {
  const { appId, own, trust, state, file } = params;
  const lim = resolveGroupLimits(params.limits);
  if (!isDeviceText(own?.device) || !isSetText(state?.dataSet))
    return { ok: false, reason: 'bad-input' };
  const opened = await openPayload(appId, own, trust, file, lim, 'not-a-request');
  if (!opened.ok) return opened;
  const request = parseRequest(appId, opened.text);
  if (!request) return { ok: false, reason: 'bad-payload' };
  if (request.set !== state.dataSet) return { ok: false, reason: 'wrong-data-set' };
  return {
    ok: true,
    from: opened.from,
    epoch: request.epoch,
    stale: request.epoch < highestEpoch(state),
  };
}
