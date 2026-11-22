// Operator lock and unlock orders: one signed text for one target device. The signature is made with a
// device signing key of the trust layer and checked against a key the caller looks up; whether that
// device MAY give orders is a predicate the caller must pass (there is no default). Strict reader: one
// spelling (compact JSON, fixed member order), bounded, versioned. Nothing here throws on foreign input.
import { marker } from '../core/markers.ts';
import { signText, verifyText } from '../core/signature.ts';
import { field, hasMembers, isDeviceText, isPlain, parseJson } from '../core/secure.ts';
import type { LockState } from './state.ts';

/** Version of the order text (its marker and signed text). */
export const ORDER_VERSION = 1;
/** The longest order text: two 200-unit ids with JSON escapes at most, a counter, a signature. */
export const MAX_ORDER_CHARS = 1200;
const SIGNATURE_CHARS = 86;
const q = JSON.stringify;

export type LockOp = 'lock' | 'unlock';

export interface LockOrder {
  readonly to: string;
  readonly from: string;
  readonly op: LockOp;
  /** Grows with every order for this target (use the operator's clock in ms): an older one is a replay. */
  readonly n: number;
  readonly sig: string;
}

export type OrderRefusal =
  | 'bad-input'
  | 'not-an-order'
  | 'wrong-device'
  | 'not-allowed'
  | 'unknown-key'
  | 'bad-signature'
  | 'replayed';

const isCounter = (n: unknown): n is number =>
  typeof n === 'number' && Number.isSafeInteger(n) && n >= 1;

/** The signed text: marker and length-prefixed fields, so no field can shift into another. */
function signedText(appId: string, o: Omit<LockOrder, 'sig'>): string {
  return `${marker(appId, 'lockorder', ORDER_VERSION)}|${field(o.to)}${field(o.from)}${o.op}|${o.n}`;
}

function orderText(appId: string, o: LockOrder): string {
  return `{"k":${q(marker(appId, 'lockorder', ORDER_VERSION))},"to":${q(o.to)},"from":${q(o.from)},"op":${q(o.op)},"n":${o.n},"sig":${q(o.sig)}}`;
}

export interface SignOrderParams {
  readonly appId: string;
  /** The operator device (its signing key signs). */
  readonly from: string;
  /** The device that is to be locked or unlocked. */
  readonly to: string;
  readonly op: LockOp;
  readonly n: number;
  readonly privateKey: CryptoKey;
}

export type SignedOrder =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly reason: 'bad-input' };

export async function signLockOrder(p: SignOrderParams): Promise<SignedOrder> {
  try {
    if (
      !isDeviceText(p.from) ||
      !isDeviceText(p.to) ||
      (p.op !== 'lock' && p.op !== 'unlock') ||
      !isCounter(p.n)
    ) {
      return { ok: false, reason: 'bad-input' };
    }
    const body = { to: p.to, from: p.from, op: p.op, n: p.n };
    const sig = await signText(p.privateKey, signedText(p.appId, body));
    return { ok: true, text: orderText(p.appId, { ...body, sig }) };
  } catch {
    return { ok: false, reason: 'bad-input' };
  }
}

/** The strict reader: undefined for anything but exactly the text `signLockOrder` writes for this app. */
export function readLockOrder(text: unknown, appId: string): LockOrder | undefined {
  try {
    if (typeof text !== 'string' || text.length > MAX_ORDER_CHARS) return undefined;
    const v = parseJson(text);
    const names = ['k', 'to', 'from', 'op', 'n', 'sig'] as const;
    if (!isPlain(v) || !hasMembers(v, names)) return undefined;
    if (
      v.k !== marker(appId, 'lockorder', ORDER_VERSION) ||
      !isDeviceText(v.to) ||
      !isDeviceText(v.from) ||
      (v.op !== 'lock' && v.op !== 'unlock') ||
      !isCounter(v.n) ||
      typeof v.sig !== 'string' ||
      v.sig.length !== SIGNATURE_CHARS
    ) {
      return undefined;
    }
    const order: LockOrder = { to: v.to, from: v.from, op: v.op, n: v.n, sig: v.sig };
    return orderText(appId, order) === text ? order : undefined;
  } catch {
    return undefined;
  }
}

export interface ApplyOrderParams {
  readonly appId: string;
  /** This device's id: an order for another device is refused. */
  readonly self: string;
  /** Looks up the signing key of the operator (e.g. through the trust layer's key source). */
  readonly keys: (device: string) => CryptoKey | undefined | Promise<CryptoKey | undefined>;
  /** Whether this device may give orders at all (e.g. a role check on the trust layer's entry). Required. */
  readonly mayOperate: (device: string) => boolean;
}

export type ApplyOrderResult =
  | { readonly ok: true; readonly state: LockState; readonly order: LockOrder }
  | { readonly ok: false; readonly reason: OrderRefusal };

/**
 * Reads, checks and applies one order. Cheap checks first, the signature last: wrong text, wrong target,
 * not allowed, replay (a counter at or below the highest applied), unknown key, signature. A lock sets
 * the operator lock; an unlock clears only that (an expired time needs a contact). The package cannot
 * stop a carrier from dropping or delaying an order.
 */
export async function applyLockOrder(
  state: LockState,
  text: string,
  p: ApplyOrderParams,
): Promise<ApplyOrderResult> {
  try {
    if (
      !isDeviceText(p.self) ||
      typeof p.mayOperate !== 'function' ||
      typeof p.keys !== 'function'
    ) {
      return { ok: false, reason: 'bad-input' };
    }
    const o = readLockOrder(text, p.appId);
    if (o === undefined) return { ok: false, reason: 'not-an-order' };
    if (o.to !== p.self) return { ok: false, reason: 'wrong-device' };
    if (o.from === p.self || p.mayOperate(o.from) !== true) {
      return { ok: false, reason: 'not-allowed' };
    }
    if (o.n <= state.opN) return { ok: false, reason: 'replayed' };
    let key: CryptoKey | undefined;
    try {
      key = await p.keys(o.from);
    } catch {
      key = undefined;
    }
    if (key === undefined) return { ok: false, reason: 'unknown-key' };
    const { sig, ...body } = o;
    if (!(await verifyText(key, signedText(p.appId, body), sig))) {
      return { ok: false, reason: 'bad-signature' };
    }
    // The state may have moved while the key was awaited: check the counter again.
    if (o.n <= state.opN) return { ok: false, reason: 'replayed' };
    const next: LockState =
      o.op === 'lock'
        ? { ...state, held: true, by: o.from, opN: o.n }
        : { ...state, held: false, by: null, opN: o.n };
    return { ok: true, state: next, order: o };
  } catch {
    return { ok: false, reason: 'bad-input' };
  }
}
