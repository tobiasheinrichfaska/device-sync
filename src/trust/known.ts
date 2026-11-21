import { resolveValidators } from './ids.ts';
import type { Introduction, KnownDevice, Validators } from './types.ts';
import { isPlain, parseIntroduction } from './wire.ts';

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const CHECK_CODE = /^\d{4}( \d{4}){4}$/;

/** Order by name (case-insensitive), then exactly, then id: the same everywhere, no locale involved. */
export function byName(a: { name: string; device: string }, b: { name: string; device: string }) {
  const x = a.name.toLowerCase();
  const y = b.name.toLowerCase();
  if (x !== y) return x < y ? -1 : 1;
  if (a.name !== b.name) return a.name < b.name ? -1 : 1;
  return a.device < b.device ? -1 : a.device > b.device ? 1 : 0;
}

export type RememberResult =
  | { readonly ok: true; readonly list: readonly KnownDevice[]; readonly added: boolean }
  | { readonly ok: false; readonly reason: 'own-device' | 'bad-role' | 'other-keys' };

/**
 * Takes a device met in person into this device's list. Meeting a known one again changes nothing
 * but its role (when one is given); a known id with other keys is refused (another device or a
 * forged code: forget it first).
 */
export function rememberDevice(
  list: readonly KnownDevice[],
  ownDevice: string,
  met: Introduction,
  role: string | undefined,
  since: string,
  checkCode: string,
  valid?: Partial<Validators>,
): RememberResult {
  if (met.device === ownDevice) return { ok: false, reason: 'own-device' };
  if (role !== undefined && !resolveValidators(valid).role(role)) {
    return { ok: false, reason: 'bad-role' };
  }
  const known = list.find((b) => b.device === met.device);
  if (known) {
    if (known.sig !== met.sig || known.dh !== met.dh) return { ok: false, reason: 'other-keys' };
    if (role === undefined || known.role === role) return { ok: true, list, added: false };
    return {
      ok: true,
      added: true,
      list: list.map((b) => (b.device === met.device ? { ...b, role } : b)),
    };
  }
  const entry: KnownDevice = {
    device: met.device,
    name: met.name,
    sig: met.sig,
    dh: met.dh,
    ...(role !== undefined ? { role } : {}),
    since,
    checkCode,
  };
  return { ok: true, added: true, list: [...list, entry].sort(byName) };
}

export const forgetDevice = (list: readonly KnownDevice[], device: string): KnownDevice[] =>
  list.filter((b) => b.device !== device);

/** A known device under a new name (the list stays sorted). */
export const renameKnown = (
  list: readonly KnownDevice[],
  device: string,
  name: string,
): KnownDevice[] => list.map((b) => (b.device === device ? { ...b, name } : b)).sort(byName);

/** Notes the relay id of a known device; a broken id or an unknown device leaves the list as it is. */
export function noteRelayId(
  list: readonly KnownDevice[],
  device: string,
  relayId: string,
  valid?: Partial<Validators>,
): readonly KnownDevice[] {
  if (!resolveValidators(valid).relayId(relayId)) return list;
  return list.some((b) => b.device === device && b.relayId !== relayId)
    ? list.map((b) => (b.device === device ? { ...b, relayId } : b))
    : list;
}

/** The stored list, strictly read: a damaged entry is dropped, never trusted. */
export function parseKnownList(raw: unknown, validators?: Partial<Validators>): KnownDevice[] {
  if (!Array.isArray(raw)) return [];
  const valid = resolveValidators(validators);
  return raw.flatMap((entry: unknown): KnownDevice[] => {
    const intro = parseIntroduction(entry, valid);
    if (!intro || !isPlain(entry)) return [];
    const { role, since, checkCode, relayId } = entry;
    if (role !== undefined && !(typeof role === 'string' && valid.role(role))) return [];
    if (typeof since !== 'string' || !DATE.test(since)) return [];
    if (typeof checkCode !== 'string' || !CHECK_CODE.test(checkCode)) return [];
    // a broken relay id is left out alone (the entry stays)
    return [
      {
        ...intro,
        ...(typeof role === 'string' ? { role } : {}),
        since,
        checkCode,
        ...(typeof relayId === 'string' && valid.relayId(relayId) ? { relayId } : {}),
      },
    ];
  });
}
