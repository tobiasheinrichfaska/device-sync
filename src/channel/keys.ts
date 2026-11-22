// The two key views a channel needs from one derived trust: the signing point of a device (envelope
// level) and a `KeySource` for the changes' signatures. Both read `Trust.checkableById`: a removed
// device stays checkable (its signed writes verify), and who may WRITE is the app's `mayWrite`.
import { importPublicKey } from '../core/index.ts';
import type { KeySource } from '../log/index.ts';
import type { Trust } from '../trust/index.ts';

export interface ChannelKeys {
  readonly authorKey: (device: string) => string | undefined;
  readonly keys: KeySource;
}

/**
 * Key views of a derived trust. `own` adds this device's own signing key (changes under its own id).
 * The trust is read when asked, so pass a getter to follow a trust that is derived again.
 */
export function channelKeys(
  trust: Trust | (() => Trust),
  own?: { readonly device: string; readonly publicKey: CryptoKey },
): ChannelKeys {
  const current = (): Trust => (typeof trust === 'function' ? trust() : trust);
  const imported = new Map<string, Promise<CryptoKey | undefined>>();
  return {
    authorKey: (device) => current().checkableById.get(device)?.sig,
    keys: {
      async keyFor(device) {
        if (own && device === own.device) return own.publicKey;
        const sig = current().checkableById.get(device)?.sig;
        if (sig === undefined) return undefined;
        let key = imported.get(sig);
        if (!key) imported.set(sig, (key = importPublicKey(sig, 'sig')));
        return key;
      },
    },
  };
}
