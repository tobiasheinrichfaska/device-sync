// Round 5 review of the relay client: an answer that did not come from the relay's origin.
import { describe, expect, it } from 'vitest';
import { RelayClient, type CredentialStore, type FetchLike } from '../../src/relay/index.ts';
import { ALPHA, BASE, serverFor } from './helpers.ts';

const store: CredentialStore = { get: () => undefined, set: () => {}, remove: () => {} };

describe('round 5: redirected answers', () => {
  const make = (mark: (r: Response) => void): RelayClient => {
    const server = serverFor();
    const fetchFn: FetchLike = async (url, init) => {
      const r = await server.fetch(url, init);
      mark(r);
      return r;
    };
    return new RelayClient({
      baseUrl: BASE,
      appId: ALPHA.app,
      origin: ALPHA.origin,
      fetch: fetchFn,
      store,
      clock: server.now,
      random: () => 0.5,
      sleep: () => Promise.resolve(),
    });
  };

  it('control: the same answer is read when nothing marks it', async () => {
    expect((await make(() => {}).health()).ok).toBe(true);
  });

  it('an answer a fetch reports as redirected is not read', async () => {
    const r = await make((res) =>
      Object.defineProperty(res, 'redirected', { value: true }),
    ).health();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.kind).toBe('malformed');
  });

  it('an answer whose url is another origin is not read', async () => {
    const r = await make((res) =>
      Object.defineProperty(res, 'url', { value: 'https://elsewhere.example/gesund' }),
    ).health();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.kind).toBe('malformed');
  });

  it('an answer whose url is the relay origin is read', async () => {
    const r = await make((res) =>
      Object.defineProperty(res, 'url', { value: `${BASE}/gesund` }),
    ).health();
    expect(r.ok).toBe(true);
  });
});
