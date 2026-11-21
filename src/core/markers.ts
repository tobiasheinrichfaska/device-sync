/** Version of the wire format; every marker of this format carries it. */
export const FORMAT_VERSION = 2;

const APP_ID = /^[a-z][a-z0-9]{1,15}$/;
/** A kind never contains the separators `-`, `:` or `|`, so two different markers can never read the same. */
const KIND = /^[a-z][a-z0-9]{0,31}$/;

/**
 * Domain-separation string `${appId}-${kind}:${version}`. Every marker enters hashes, key
 * derivation and AAD, so a different `appId` can never produce the same bytes.
 */
export function marker(appId: string, kind: string, version: number = FORMAT_VERSION): string {
  if (typeof appId !== 'string' || !APP_ID.test(appId)) {
    throw new Error(`invalid appId: must match ${APP_ID.source}`);
  }
  if (typeof kind !== 'string' || !KIND.test(kind)) {
    throw new Error(`invalid kind: must match ${KIND.source}`);
  }
  if (!Number.isInteger(version) || version < 0) throw new Error('invalid version');
  return `${appId}-${kind}:${version}`;
}
