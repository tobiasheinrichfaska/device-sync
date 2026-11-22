// Browser layer in real Chromium: the real IDBFactory, real non-extractable CryptoKeys, real Web Locks.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  bundleLibrary,
  launch,
  openPage,
  startSite,
  type Browser,
  type Context,
  type Site,
} from './harness.ts';

let browser: Browser;
let context: Context;
let site: Site;

beforeAll(async () => {
  site = await startSite(await bundleLibrary());
  browser = await launch();
  context = await browser.newContext();
});
afterAll(async () => {
  await browser?.close();
  await site?.close();
});

describe('key store on the real IndexedDB', () => {
  it('keeps non-extractable keys usable for signing and ECDH, across a reload', async () => {
    const page = await openPage(context, site);
    const first = await page.evaluate(async () => {
      const { generateDeviceKeys, openKeyStore, signText, verifyText } = window.ds;
      const keys = await generateDeviceKeys();
      const s = await openKeyStore(indexedDB, { name: 'ks-roundtrip' });
      if (!s.ok) return { step: 'open', reason: s.reason };
      const put = await s.value.putKeys('device-keys', keys);
      const got = await s.value.getKeys('device-keys');
      if (!put.ok || !got.ok || !got.value) return { step: 'get', put, got: got.ok };
      const sig = await signText(got.value.signing.privateKey, 'hello');
      const verified = await verifyText(got.value.signing.publicKey, 'hello', sig);
      // a peer's ECDH key and the stored private key agree on the same secret
      const peer = await generateDeviceKeys();
      const a = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: peer.agreement.publicKey },
        got.value.agreement.privateKey,
        256,
      );
      const b = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: got.value.agreement.publicKey },
        peer.agreement.privateKey,
        256,
      );
      let exported = 'refused';
      try {
        await crypto.subtle.exportKey('jwk', got.value.signing.privateKey);
        exported = 'allowed';
      } catch {
        // expected
      }
      return {
        step: 'done',
        verified,
        sameSecret: new Uint8Array(a).join() === new Uint8Array(b).join(),
        extractable: got.value.signing.privateKey.extractable,
        exported,
        sig: sig.length,
      };
    });
    expect(first).toMatchObject({
      step: 'done',
      verified: true,
      sameSecret: true,
      extractable: false,
      exported: 'refused',
    });

    // The same origin after a reload: the stored keys sign, and the old public key verifies.
    await page.reload();
    await page.waitForFunction(() => typeof window.ds === 'object');
    const second = await page.evaluate(async () => {
      const { openKeyStore, signText, verifyText } = window.ds;
      const s = await openKeyStore(indexedDB, { name: 'ks-roundtrip' });
      if (!s.ok) return { reason: s.reason };
      const got = await s.value.getKeys('device-keys');
      if (!got.ok || !got.value) return { reason: 'none' };
      const sig = await signText(got.value.signing.privateKey, 'after reload');
      return { verified: await verifyText(got.value.signing.publicKey, 'after reload', sig) };
    });
    expect(second).toEqual({ verified: true });
    await page.close();
  });

  it('refuses an extractable private key and a record of the wrong kind', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const { generateDeviceKeys, openKeyStore } = window.ds;
      const s = await openKeyStore(indexedDB, { name: 'ks-refuse' });
      if (!s.ok) return { reason: s.reason };
      const good = await generateDeviceKeys();
      const loose = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
      ]);
      const extractable = await s.value.putKeys('k', { signing: loose, agreement: good.agreement });
      await s.value.putText('t', 'some text');
      const wrong = await s.value.getKeys('t');
      const badName = await s.value.putText('-bad', 'x');
      return { extractable, wrong, badName };
    });
    expect(r).toEqual({
      extractable: { ok: false, reason: 'extractable-private-key' },
      wrong: { ok: false, reason: 'wrong-kind' },
      badName: { ok: false, reason: 'bad-name' },
    });
    await page.close();
  });

  it('reads a foreign write as corrupt (a real structured clone of a plain object)', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const { openKeyStore, STORE_NAME } = window.ds;
      const s = await openKeyStore(indexedDB, { name: 'ks-corrupt' });
      if (!s.ok) return { reason: s.reason };
      s.value.close();
      // a second tab or a script of the origin writes something else under the same name
      const db = await new Promise<IDBDatabase>((res, rej) => {
        const q = indexedDB.open('ks-corrupt', 1);
        q.onsuccess = () => res(q.result);
        q.onerror = () => rej(q.error);
      });
      await new Promise<void>((res, rej) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        tx.objectStore(STORE_NAME).put({ v: 1, kind: 'text', text: 5 }, 'x');
        tx.objectStore(STORE_NAME).put({ v: 2, kind: 'text', text: 'new' }, 'y');
        tx.oncomplete = () => res();
        tx.onerror = () => rej(tx.error);
      });
      db.close();
      const s2 = await openKeyStore(indexedDB, { name: 'ks-corrupt' });
      if (!s2.ok) return { reason: s2.reason };
      return { x: await s2.value.getText('x'), y: await s2.value.getText('y') };
    });
    expect(r).toEqual({
      x: { ok: false, reason: 'corrupt' },
      y: { ok: false, reason: 'unsupported-version' },
    });
    await page.close();
  });

  it('wipe deletes the database for real; a second tab holding it open is closed by versionchange', async () => {
    const a = await openPage(context, site);
    const b = await openPage(context, site);
    await a.evaluate(async () => {
      const s = await window.ds.openKeyStore(indexedDB, { name: 'ks-wipe' });
      if (!s.ok) throw new Error(s.reason);
      await s.value.putText('t', 'secret');
      (window as unknown as { store: unknown }).store = s.value;
    });
    await b.evaluate(async () => {
      const s = await window.ds.openKeyStore(indexedDB, { name: 'ks-wipe' });
      if (!s.ok) throw new Error(s.reason);
      (window as unknown as { store: unknown }).store = s.value;
    });
    // tab B reads what tab A wrote
    expect(
      await b.evaluate(async () => {
        const s = (window as unknown as { store: { getText(n: string): Promise<unknown> } }).store;
        return s.getText('t');
      }),
    ).toEqual({ ok: true, value: 'secret' });
    const wiped = await a.evaluate(async () => {
      const s = (window as unknown as { store: { wipe(): Promise<unknown> } }).store;
      return s.wipe();
    });
    expect(wiped).toEqual({ ok: true, value: null });
    const after = await b.evaluate(async () => {
      const s = (
        window as unknown as {
          store: { isOpen(): boolean; getText(n: string): Promise<unknown> };
        }
      ).store;
      return { open: s.isOpen(), read: await s.getText('t') };
    });
    expect(after).toEqual({ open: false, read: { ok: false, reason: 'closed' } });
    const names = await a.evaluate(async () => (await indexedDB.databases()).map((d) => d.name));
    expect(names).not.toContain('ks-wipe');
    // and a fresh open finds an empty store
    const fresh = await a.evaluate(async () => {
      const s = await window.ds.openKeyStore(indexedDB, { name: 'ks-wipe' });
      return s.ok ? s.value.getText('t') : s;
    });
    expect(fresh).toEqual({ ok: true, value: undefined });
    await a.close();
    await b.close();
  });

  it('wipe with a foreign connection that ignores versionchange: records are gone, deletion completes once it closes', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const s = await window.ds.openKeyStore(indexedDB, { name: 'ks-blocked' });
      if (!s.ok) return { reason: s.reason };
      await s.value.putText('t', 'secret');
      // another script of the origin keeps a plain connection open and never closes on versionchange
      const hold = await new Promise<IDBDatabase>((res, rej) => {
        const q = indexedDB.open('ks-blocked');
        q.onsuccess = () => res(q.result);
        q.onerror = () => rej(q.error);
      });
      const wiped = await s.value.wipe();
      const left = await new Promise<unknown>((res) => {
        const tx = hold.transaction('records', 'readonly');
        const q = tx.objectStore('records').count();
        q.onsuccess = () => res(q.result);
      });
      const listedWhileHeld = (await indexedDB.databases()).some((d) => d.name === 'ks-blocked');
      hold.close();
      await new Promise((res) => setTimeout(res, 300));
      const listedAfter = (await indexedDB.databases()).some((d) => d.name === 'ks-blocked');
      return { wiped, left, listedWhileHeld, listedAfter, open: s.value.isOpen() };
    });
    expect(r).toEqual({
      wiped: { ok: true, value: null },
      left: 0,
      listedWhileHeld: true,
      listedAfter: false,
      open: false,
    });
    await page.close();
  });

  it('answers unsupported-version for a database of a newer schema, foreign-database for a foreign one', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const raw = (name: string, version: number, upgrade?: (db: IDBDatabase) => void) =>
        new Promise<void>((res, rej) => {
          const q = indexedDB.open(name, version);
          q.onupgradeneeded = () => upgrade?.(q.result);
          q.onsuccess = () => {
            q.result.close();
            res();
          };
          q.onerror = () => rej(q.error);
        });
      await raw('ks-newer', 2, (db) => db.createObjectStore('records'));
      await raw('ks-foreign', 1, (db) => db.createObjectStore('other'));
      const newer = await window.ds.openKeyStore(indexedDB, { name: 'ks-newer' });
      const foreign = await window.ds.openKeyStore(indexedDB, { name: 'ks-foreign' });
      return {
        newer: newer.ok ? 'ok' : newer.reason,
        foreign: foreign.ok ? 'ok' : foreign.reason,
      };
    });
    expect(r).toEqual({ newer: 'unsupported-version', foreign: 'foreign-database' });
    await page.close();
  });

  it('answers unavailable without a factory and works as the relay credential store', async () => {
    const page = await openPage(context, site);
    const r = await page.evaluate(async () => {
      const { openKeyStore, relayCredentialStore } = window.ds;
      const none = await openKeyStore(undefined, { name: 'ks-cred' });
      const s = await openKeyStore(indexedDB, { name: 'ks-cred' });
      if (!s.ok) return { reason: s.reason };
      const cred = relayCredentialStore(s.value);
      const empty = await cred.get();
      await cred.set('token-text');
      const got = await cred.get();
      await cred.remove();
      return { none: none.ok ? 'ok' : none.reason, empty, got, gone: await cred.get() };
    });
    expect(r).toEqual({
      none: 'unavailable',
      empty: undefined,
      got: 'token-text',
      gone: undefined,
    });
    await page.close();
  });
});

describe('one listener per tab on the real Web Locks', () => {
  type Probe = { events: string[]; l: { release(): void; isLeader(): boolean } };
  const install = async (
    page: Awaited<ReturnType<typeof openPage>>,
    name: string,
    tag: string,
  ): Promise<void> => {
    await page.evaluate(
      ({ name, tag }: { name: string; tag: string }) => {
        const events: string[] = [];
        const r = window.ds.createSingleListener({
          name,
          locks: navigator.locks,
          onGain: () => events.push(`${tag}:gain`),
          onLose: () => events.push(`${tag}:lose`),
          onError: (c) => events.push(`${tag}:error:${c}`),
        });
        if (!r.ok) throw new Error(r.reason);
        (window as unknown as { probe: Probe }).probe = { events, l: r.value };
      },
      { name, tag },
    );
  };
  const state = (page: Awaited<ReturnType<typeof openPage>>) =>
    page.evaluate(() => {
      const p = (window as unknown as { probe: Probe }).probe;
      return { events: p.events.slice(), leader: p.l.isLeader() };
    });

  it('elects exactly one of two pages, hands over on release and on a closed tab', async () => {
    const a = await openPage(context, site);
    const b = await openPage(context, site);
    const c = await openPage(context, site);
    await install(a, 'real-lock', 'a');
    await a.waitForFunction(() => (window as unknown as { probe: Probe }).probe.l.isLeader());
    await install(b, 'real-lock', 'b');
    await install(c, 'real-lock', 'c');
    // give b and c time to queue; neither may lead while a does
    await b.waitForTimeout(300);
    expect(await state(a)).toEqual({ events: ['a:gain'], leader: true });
    expect(await state(b)).toEqual({ events: [], leader: false });
    expect(await state(c)).toEqual({ events: [], leader: false });

    // a releases: exactly one of the waiting pages takes over
    await a.evaluate(() => (window as unknown as { probe: Probe }).probe.l.release());
    await a.waitForFunction(() => !(window as unknown as { probe: Probe }).probe.l.isLeader());
    await b.waitForTimeout(300);
    const sb = await state(b);
    const sc = await state(c);
    expect([sb.leader, sc.leader].filter(Boolean)).toHaveLength(1);
    expect((await state(a)).events).toEqual(['a:gain', 'a:lose']);

    // the leader's tab is closed (no release): the browser frees the lock, the other takes over
    const [leaderPage, otherPage, otherState] = sb.leader ? [b, c, sc] : [c, b, sb];
    expect(otherState.leader).toBe(false);
    await leaderPage.close();
    await otherPage.waitForFunction(() =>
      (window as unknown as { probe: Probe }).probe.l.isLeader(),
    );
    await otherPage.close();
    await a.close();
  });

  it('a different name is an independent election', async () => {
    const a = await openPage(context, site);
    const b = await openPage(context, site);
    await install(a, 'lock-one', 'a');
    await install(b, 'lock-two', 'b');
    await a.waitForFunction(() => (window as unknown as { probe: Probe }).probe.l.isLeader());
    await b.waitForFunction(() => (window as unknown as { probe: Probe }).probe.l.isLeader());
    await a.close();
    await b.close();
  });

  it('release before the lock is granted aborts the real request without an error', async () => {
    const a = await openPage(context, site);
    const b = await openPage(context, site);
    await install(a, 'lock-abort', 'a');
    await a.waitForFunction(() => (window as unknown as { probe: Probe }).probe.l.isLeader());
    await install(b, 'lock-abort', 'b');
    await b.waitForTimeout(100);
    await b.evaluate(() => (window as unknown as { probe: Probe }).probe.l.release());
    await b.waitForTimeout(200);
    expect(await state(b)).toEqual({ events: [], leader: false });
    // the queue is clean: after a leaves nobody is granted the lock
    await a.evaluate(() => (window as unknown as { probe: Probe }).probe.l.release());
    await b.waitForTimeout(200);
    const held = await b.evaluate(async () => {
      const q = await navigator.locks.query();
      return (q.held ?? []).concat(q.pending ?? []).filter((x) => x.name?.includes('lock-abort'));
    });
    expect(held).toEqual([]);
    await a.close();
    await b.close();
  });

  it('the BroadcastChannel fallback works between two real pages on the real clock', async () => {
    const a = await openPage(context, site);
    const b = await openPage(context, site);
    const start = ({ tag }: { tag: string }) => {
      const events: string[] = [];
      const channel = new BroadcastChannel('device-sync:real-channel');
      const r = window.ds.createSingleListener({
        name: 'real-channel',
        channel,
        id: `${tag}-${Math.random().toString(16).slice(2)}`,
        clock: () => Date.now(),
        timers: {
          set: (fn, ms) => setTimeout(fn, ms),
          clear: (h) => clearTimeout(h as number),
        },
        heartbeatMs: 100,
        timeoutMs: 600,
        delayMs: 50,
        lateMs: 100,
        onGain: () => events.push('gain'),
        onLose: () => events.push('lose'),
      });
      if (!r.ok) throw new Error(r.reason);
      (window as unknown as { probe: Probe }).probe = { events, l: r.value };
    };
    await a.evaluate(start, { tag: 'a' });
    await b.evaluate(start, { tag: 'b' });
    await a.waitForTimeout(1500);
    const sa = await state(a);
    const sb = await state(b);
    expect([sa.leader, sb.leader].filter(Boolean)).toHaveLength(1);
    // the leader closes its tab without releasing; the other takes over after the timeout
    const [dead, alive] = sa.leader ? [a, b] : [b, a];
    await dead.close();
    await alive.waitForFunction(
      () => (window as unknown as { probe: Probe }).probe.l.isLeader(),
      null,
      {
        timeout: 5000,
      },
    );
    await alive.close();
  });
});
