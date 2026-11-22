import type { CredentialStore } from '../relay/client.ts';
import { RECORD_NAMES, type KeyStore, type StoreReason } from './keystore.ts';

/** What the credential store throws; `RelayClient` catches it and reports `storage`. */
export class KeyStoreError extends Error {
  readonly code: StoreReason;
  constructor(code: StoreReason) {
    super(code);
    this.name = 'KeyStoreError';
    this.code = code;
  }
}

/**
 * The relay client's credential store on top of a key store: one text record. A record that cannot be
 * read (`corrupt`, `wrong-kind`, ...) is thrown as a `KeyStoreError`, not turned into "nothing stored":
 * the client then treats the device as not enrolled and the app decides what to do (`remove`, enrol again).
 */
export function relayCredentialStore(
  store: KeyStore,
  recordName: string = RECORD_NAMES.relayCredential,
): CredentialStore {
  return {
    async get() {
      const r = await store.getText(recordName);
      if (!r.ok) throw new KeyStoreError(r.reason);
      return r.value;
    },
    async set(text) {
      const r = await store.putText(recordName, text);
      if (!r.ok) throw new KeyStoreError(r.reason);
    },
    async remove() {
      const r = await store.remove(recordName);
      if (!r.ok) throw new KeyStoreError(r.reason);
    },
  };
}
