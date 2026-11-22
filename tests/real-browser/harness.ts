// Real-browser harness: bundles the library, serves it from http://localhost (a secure context, so
// WebCrypto, Web Locks, IndexedDB and service workers are real), and drives Chromium with Playwright.
// Playwright is NOT a dependency of this package: it is looked up where the machine has it (see
// `loadPlaywright`). Nothing here runs in `npm test`; the script is `npm run test:browser`.
import { createRequire } from 'node:module';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';

// The library as the page sees it (`window.ds`).
export type Ds = typeof import('../../src/index.ts');

// Playwright's types are not installed here; the harness uses the few members below.
export type Page = any; // eslint-disable-line @typescript-eslint/no-explicit-any
export type Context = any; // eslint-disable-line @typescript-eslint/no-explicit-any
export type Browser = any; // eslint-disable-line @typescript-eslint/no-explicit-any

declare global {
  interface Window {
    ds: Ds;
  }
}

const here = (p: string): string => fileURLToPath(new URL(p, import.meta.url));

export function loadPlaywright(): { chromium: { launch(o?: object): Promise<Browser> } } {
  const require = createRequire(import.meta.url);
  const where = [undefined, process.env['PLAYWRIGHT_DIR'], '/opt/node-tools/node_modules'];
  for (const dir of where) {
    try {
      return require(dir ? require.resolve('playwright', { paths: [dir] }) : 'playwright');
    } catch {
      // try the next place
    }
  }
  throw new Error('playwright not found: set PLAYWRIGHT_DIR to the node_modules that holds it');
}

/**
 * Chromium (the full build in its new headless mode, not the headless shell: the shell has no
 * notification permission) with the flags a test needs. `DS_BROWSER_CHANNEL=` (empty) uses Playwright's
 * default build instead.
 */
export const launch = (args: string[] = []): Promise<Browser> => {
  const channel = process.env['DS_BROWSER_CHANNEL'] ?? 'chromium';
  return loadPlaywright().chromium.launch({ args, ...(channel ? { channel } : {}) });
};

/** The library as one script that defines `ds`. */
export async function bundleLibrary(): Promise<string> {
  const { rolldown } = (await import('rolldown')) as unknown as {
    rolldown(o: object): Promise<{ generate(o: object): Promise<{ output: { code: string }[] }> }>;
  };
  const build = await rolldown({
    input: here('../../src/index.ts'),
    platform: 'browser',
    logLevel: 'silent',
  });
  const { output } = await build.generate({ format: 'iife', name: 'ds' });
  return (output[0] as { code: string }).code;
}

export interface Site {
  readonly origin: string;
  /** Adds or replaces a file served by the site (path starting with `/`). */
  serve(path: string, type: string, body: string): void;
  close(): Promise<void>;
}

const PAGE = `<!doctype html><meta charset="utf-8"><title>real browser</title><script src="/lib.js"></script>`;

export async function startSite(lib: string): Promise<Site> {
  const files = new Map<string, { type: string; body: string }>([
    ['/', { type: 'text/html', body: PAGE }],
    ['/lib.js', { type: 'text/javascript', body: `${lib}\nwindow.ds = ds;` }],
  ]);
  const server: Server = createServer((req, res) => {
    const f = files.get((req.url ?? '/').split('?')[0] as string);
    if (!f) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': f.type, 'cache-control': 'no-store' }).end(f.body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    origin: `http://localhost:${port}`,
    serve: (path, type, body) => void files.set(path, { type, body }),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

export async function openPage(context: Context, site: Site): Promise<Page> {
  const page = await context.newPage();
  await page.goto(site.origin + '/');
  await page.waitForFunction(() => typeof window.ds === 'object');
  return page;
}
