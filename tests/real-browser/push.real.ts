// Push layer in real Chromium: the generated service worker registered on http://localhost, a real push
// event delivered through the DevTools protocol, and the notification that the browser actually shows
// (`registration.getNotifications()`). Notification clicks cannot be made by a script: the click handler
// is run in the real worker with the browser's own `NotificationEvent` and stubs for focus and open.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildServiceWorkerSource } from '../../src/push/worker.ts';
import {
  bundleLibrary,
  launch,
  openPage,
  startSite,
  type Browser,
  type Context,
  type Page,
  type Site,
} from './harness.ts';

const OPTIONS = {
  texts: {
    en: { title: 'New data', body: 'Open the app to sync.' },
    de: { title: 'Neue Daten', body: 'App öffnen zum Abgleichen.' },
  },
  fallback: 'en',
  appUrl: '/app/',
  tag: 'sync-ring',
} as const;

// Worker-scope names that the DOM typings lack (the code below runs inside the real worker).
interface WorkerScope {
  clients: { openWindow(url: string | URL): Promise<unknown> };
  registration: { getNotifications(): Promise<unknown[]> };
  dispatchEvent(ev: unknown): boolean;
}
declare class NotificationEvent {
  constructor(type: string, init: { notification: unknown });
}
declare const WindowClient: { prototype: { url: string; focus(): Promise<unknown> } };

let site: Site;

beforeAll(async () => {
  site = await startSite(await bundleLibrary());
  const built = buildServiceWorkerSource(OPTIONS);
  if (!built.ok) throw new Error(built.reason);
  site.serve('/sw.js', 'text/javascript', built.value);
  site.serve('/app/', 'text/html', '<!doctype html><meta charset="utf-8"><title>app</title>');
});
afterAll(async () => {
  await site?.close();
});

interface Registered {
  /** Closes the context and its browser: one browser per test, so registrations never mix. */
  close(): Promise<void>;
  readonly context: Context;
  readonly page: Page;
  readonly cdp: { send(method: string, params?: object): Promise<unknown> };
  readonly registrationId: string;
}

async function register(locale: string): Promise<Registered> {
  const browser: Browser = await launch();
  const context = await browser.newContext({ locale });
  await context.grantPermissions(['notifications'], { origin: site.origin });
  const page = await openPage(context, site);
  const cdp = await context.newCDPSession(page);
  let registrationId = '';
  const seen = new Promise<void>((resolve) => {
    (cdp as unknown as { on(e: string, f: (p: unknown) => void): void }).on(
      'ServiceWorker.workerRegistrationUpdated',
      (p) => {
        const regs = (p as { registrations: { registrationId: string; scopeURL: string }[] })
          .registrations;
        const mine = regs.find((r) => r.scopeURL.startsWith(site.origin));
        if (mine) {
          registrationId = mine.registrationId;
          resolve();
        }
      },
    );
  });
  await cdp.send('ServiceWorker.enable');
  const state = await page.evaluate(async () => {
    const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    await navigator.serviceWorker.ready;
    return { scope: reg.scope, active: reg.active?.state ?? 'none' };
  });
  expect(state.scope).toBe(site.origin + '/');
  await seen;
  return { close: () => browser.close(), context, page, cdp, registrationId };
}

const push = (r: Registered, data = ''): Promise<unknown> =>
  r.cdp.send('ServiceWorker.deliverPushMessage', {
    origin: site.origin,
    registrationId: r.registrationId,
    data,
  });

const shown = (page: Page): Promise<{ title: string; body: string; tag: string }[]> =>
  page.evaluate(async () => {
    const reg = await navigator.serviceWorker.ready;
    const list = await reg.getNotifications();
    return list.map((n) => ({ title: n.title, body: n.body, tag: n.tag }));
  });

/** A push can be lost right after registration or right after a close (a race inside Chromium): retry. */
async function pushUntilShown(r: Registered, data = ''): Promise<void> {
  for (let attempt = 0; attempt < 6; attempt++) {
    await push(r, data);
    for (let wait = 0; wait < 15; wait++) {
      if ((await shown(r.page)).length > 0) return;
      await r.page.waitForTimeout(100);
    }
  }
  throw new Error('no notification was shown');
}

describe('generated service worker in a real browser', () => {
  it('registers, activates and shows the table text for a content-free push (English)', async () => {
    const r = await register('en-US');
    await pushUntilShown(r);
    expect(await shown(r.page)).toEqual([
      { title: 'New data', body: 'Open the app to sync.', tag: 'sync-ring' },
    ]);
    await r.close();
  });

  it('takes the primary subtag of the browser language and falls back for an unknown one', async () => {
    const de = await register('de-DE');
    await pushUntilShown(de);
    expect((await shown(de.page))[0]).toMatchObject({ title: 'Neue Daten' });
    await de.close();
    const fr = await register('fr-FR');
    await pushUntilShown(fr);
    expect((await shown(fr.page))[0]).toMatchObject({ title: 'New data' });
    await fr.close();
  });

  it('never reads the payload: a push with hostile text content shows the same table text, one per tag', async () => {
    const r = await register('en-US');
    await pushUntilShown(r, Buffer.from('<script>alert(1)</script> secret').toString('base64'));
    await push(r, Buffer.from('second').toString('base64'));
    await r.page.waitForTimeout(500);
    // the same tag replaces the earlier notification
    expect(await shown(r.page)).toEqual([
      { title: 'New data', body: 'Open the app to sync.', tag: 'sync-ring' },
    ]);
    await r.close();
  });

  it('the click handler closes the notification and focuses an open window of the app, else opens one', async () => {
    const r = await register('en-US');
    await pushUntilShown(r);
    const worker = r.context.serviceWorkers()[0];
    const run = (): Promise<{ closed: boolean; focused: string[]; opened: string[] }> =>
      worker.evaluate(async () => {
        const g = self as unknown as WorkerScope;
        const focused: string[] = [];
        const opened: string[] = [];
        const origFocus = WindowClient.prototype.focus;
        const origOpen = g.clients.openWindow.bind(g.clients);
        WindowClient.prototype.focus = function (this: { url: string }) {
          focused.push(this.url);
          return Promise.resolve(this);
        };
        g.clients.openWindow = (url: string | URL) => {
          opened.push(String(url));
          return Promise.resolve(null);
        };
        try {
          const [notification] = await g.registration.getNotifications();
          const ev = new NotificationEvent('notificationclick', { notification: notification! });
          let waited: Promise<unknown> = Promise.resolve();
          // a script-made event is not "active"; take the promise the handler passes
          (ev as unknown as { waitUntil(p: Promise<unknown>): void }).waitUntil = (p) => {
            waited = p;
          };
          g.dispatchEvent(ev);
          await waited;
          return {
            closed: (await g.registration.getNotifications()).length === 0,
            focused,
            opened,
          };
        } finally {
          WindowClient.prototype.focus = origFocus;
          g.clients.openWindow = origOpen;
        }
      });

    // no window of the app (the test page is at "/", outside "/app/"): a window is opened
    const first = await run();
    expect(first.closed).toBe(true);
    expect(first.focused).toEqual([]);
    expect(first.opened).toEqual([site.origin + '/app/']);

    // a window inside the app path exists: it is focused and nothing is opened. (Chromium closes a
    // notification asynchronously; a push right after the close can be swallowed by the same tag.)
    await pushUntilShown(r);
    const inApp = await r.context.newPage();
    await inApp.goto(site.origin + '/app/');
    const second = await run();
    expect(second.closed).toBe(true);
    expect(second.focused).toEqual([site.origin + '/app/']);
    expect(second.opened).toEqual([]);
    await r.close();
  });
});
