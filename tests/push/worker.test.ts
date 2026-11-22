// The service worker template: the generated source is run in a node `vm` sandbox with a fake `self`,
// `registration` and `clients`. The push handler must show only table text, read nothing from the payload
// and use no network; the click handler must focus the app or open it.
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { PUSH_LIMITS, buildServiceWorkerSource, type WorkerOptions } from '../../src/push/index.ts';

const OPTIONS: WorkerOptions = {
  texts: {
    de: { title: 'Neuigkeiten', body: 'Es gibt etwas Neues.' },
    en: { title: 'News', body: 'Something is new.' },
  },
  fallback: 'en',
  appUrl: 'https://app.example/start/',
  tag: 'news',
  icon: '/icon.png',
};

const source = (over: Partial<WorkerOptions> = {}): string => {
  const r = buildServiceWorkerSource({ ...OPTIONS, ...over });
  if (!r.ok) throw new Error(r.reason);
  return r.value;
};

interface FakeClient {
  url: string;
  focused: number;
  focus(): Promise<unknown>;
}
const client = (url: string): FakeClient => ({
  url,
  focused: 0,
  focus() {
    this.focused += 1;
    return Promise.resolve(this);
  },
});

/** Runs the source with a fake worker scope and returns handles to drive it. */
function boot(js: string, opts: { language?: string; clients?: FakeClient[] } = {}) {
  const handlers: Record<string, (event: unknown) => void> = {};
  const shown: { title: string; options: Record<string, unknown> }[] = [];
  const opened: string[] = [];
  const queried: unknown[] = [];
  let networkTouched = 0;
  const self = {
    navigator: { language: opts.language ?? 'en-US' },
    location: { href: 'https://app.example/sw.js' },
    addEventListener: (type: string, fn: (event: unknown) => void) => {
      handlers[type] = fn;
    },
    registration: {
      showNotification: (title: string, options: Record<string, unknown>) => {
        shown.push({ title, options });
        return Promise.resolve();
      },
    },
    clients: {
      matchAll: (q: unknown) => {
        queried.push(q);
        return Promise.resolve(opts.clients ?? []);
      },
      openWindow: (url: string) => {
        opened.push(url);
        return Promise.resolve(null);
      },
    },
  };
  const trap = () => {
    networkTouched += 1;
    throw new Error('network');
  };
  runInNewContext(js, {
    self,
    URL,
    Object,
    String,
    Promise,
    fetch: trap,
    XMLHttpRequest: trap,
    WebSocket: trap,
    importScripts: trap,
    EventSource: trap,
  });
  const waits: Promise<unknown>[] = [];
  const fire = async (type: string, event: Record<string, unknown>) => {
    const full = Object.assign(Object.create(event), {
      waitUntil: (p: Promise<unknown>) => void waits.push(p),
    });
    handlers[type]?.(full);
    await Promise.all(waits.splice(0));
  };
  return { handlers, shown, opened, queried, fire, network: () => networkTouched };
}

describe('the push handler', () => {
  it('registers exactly the two handlers', () => {
    const w = boot(source());
    expect(Object.keys(w.handlers).sort()).toEqual(['notificationclick', 'push']);
  });

  it('shows the table text for the browser language and keeps the push waiting until it is shown', async () => {
    const w = boot(source(), { language: 'de-DE' });
    await w.fire('push', {});
    expect(w.shown).toHaveLength(1);
    expect(w.shown[0]).toEqual({
      title: 'Neuigkeiten',
      options: { body: 'Es gibt etwas Neues.', tag: 'news', renotify: true, icon: '/icon.png' },
    });
  });

  it('falls back for an unknown language, an empty one, an odd one and a prototype name', async () => {
    for (const language of ['fr', '', 'xx-YY', '__proto__', 'constructor', 'toString']) {
      const w = boot(source(), { language });
      await w.fire('push', {});
      expect(w.shown[0]?.title, language).toBe('News');
    }
  });

  it('shows the text even when the push carries a payload; the payload is never read or shown', async () => {
    const w = boot(source());
    let reads = 0;
    const hostile = {
      get data() {
        reads += 1;
        return { text: () => 'EVIL', json: () => ({ title: 'EVIL' }) };
      },
    };
    await w.fire('push', hostile);
    expect(reads).toBe(0);
    expect(JSON.stringify(w.shown)).not.toContain('EVIL');
    expect(w.shown[0]?.title).toBe('News');
  });

  it('touches no network API', async () => {
    const w = boot(source());
    await w.fire('push', {});
    await w.fire('notificationclick', { notification: { close() {} } });
    expect(w.network()).toBe(0);
  });

  it('shows a notification on every push (browsers require it), also twice in a row', async () => {
    const w = boot(source());
    await w.fire('push', {});
    await w.fire('push', {});
    expect(w.shown).toHaveLength(2);
  });

  it('omits icon and badge when none were given and passes the badge when given', async () => {
    const plain = boot(source({ icon: undefined as never }));
    await plain.fire('push', {});
    expect(plain.shown[0]?.options).toEqual({
      body: 'Something is new.',
      tag: 'news',
      renotify: true,
    });
    const badged = boot(source({ badge: 'https://app.example/b.png' }));
    await badged.fire('push', {});
    expect(badged.shown[0]?.options['badge']).toBe('https://app.example/b.png');
  });
});

describe('the click handler', () => {
  const click = (w: ReturnType<typeof boot>) => {
    let closed = 0;
    const done = w.fire('notificationclick', {
      notification: {
        close: () => (closed += 1),
        data: { url: 'https://evil.example/' }, // never used
      },
    });
    return done.then(() => closed);
  };

  it('closes the notification and focuses a window of the app', async () => {
    const other = client('https://app.example/elsewhere');
    const mine = client('https://app.example/start/page?x=1#y');
    const w = boot(source(), { clients: [other, mine] });
    expect(await click(w)).toBe(1);
    expect(mine.focused).toBe(1);
    expect(other.focused).toBe(0);
    expect(w.opened).toEqual([]);
    expect(w.queried).toEqual([{ type: 'window', includeUncontrolled: true }]);
  });

  it('opens the app when no window of it exists, never the data of the notification', async () => {
    const w = boot(source(), { clients: [client('https://evil.example/start/')] });
    await click(w);
    expect(w.opened).toEqual(['https://app.example/start/']);
  });

  it('matches origin and path exactly: a sibling path, another origin and a look-alike do not count', async () => {
    const siblings = [
      client('https://app.example/start2/'),
      client('https://app.example.evil.net/start/'),
      client('http://app.example/start/'),
      client('https://app.example:8443/start/'),
      client('not a url'),
      client(''),
    ];
    const w = boot(source(), { clients: siblings });
    await click(w);
    expect(siblings.map((c) => c.focused)).toEqual([0, 0, 0, 0, 0, 0]);
    expect(w.opened).toEqual(['https://app.example/start/']);
    const exact = client('https://app.example/start/');
    const w2 = boot(source(), { clients: [exact] });
    await click(w2);
    expect(exact.focused).toBe(1);
  });

  it('an app URL without a trailing slash matches itself and its subpaths only', async () => {
    const js = source({ appUrl: 'https://app.example/app' });
    for (const [url, hit] of [
      ['https://app.example/app', true],
      ['https://app.example/app/x', true],
      ['https://app.example/app2', false],
      ['https://app.example/ap', false],
    ] as const) {
      const c = client(url);
      const w = boot(js, { clients: [c] });
      await click(w);
      expect(c.focused > 0, url).toBe(hit);
    }
  });

  it('a path as app URL is resolved against the worker URL', async () => {
    const w = boot(source({ appUrl: '/start/' }), { clients: [] });
    await click(w);
    expect(w.opened).toEqual(['https://app.example/start/']);
  });
});

describe('the generated source', () => {
  it('is deterministic and parses as a strict-mode script', () => {
    expect(source()).toBe(source());
    expect(source().startsWith("'use strict';")).toBe(true);
    expect(() => runInNewContext(`(function(){${source()}\n})`, {})).not.toThrow();
  });

  it('contains no network, eval or payload access (static check of the whole text)', () => {
    const js = source();
    for (const word of [
      'fetch',
      'XMLHttpRequest',
      'WebSocket',
      'importScripts',
      'EventSource',
      'sendBeacon',
      'eval(',
      'Function(',
      'event.data',
      'notification.data',
      '.json(',
      '.text(',
    ])
      expect(js.includes(word), word).toBe(false);
  });

  it('carries texts that are hostile to a script exactly and harmlessly', async () => {
    const nasty = {
      title: `</script><script>alert(1)</script> "quote" 'single' \\ back \`tick\` \${x}`,
      body: 'Zeile äöü 😀 </script>',
    };
    const js = source({ texts: { en: nasty }, fallback: 'en' });
    expect(js.includes('</')).toBe(false);
    const w = boot(js);
    await w.fire('push', {});
    expect(w.shown[0]?.title).toBe(nasty.title);
    expect(w.shown[0]?.options['body']).toBe(nasty.body);
  });

  it('every language key and text lands in the table (40 languages at the limit)', async () => {
    const texts: Record<string, { title: string; body: string }> = {};
    for (let i = 0; i < PUSH_LIMITS.workerLanguagesMax; i += 1) {
      const key = `a${String.fromCharCode(97 + (i % 26))}${String.fromCharCode(97 + Math.floor(i / 26))}`;
      texts[key] = { title: `t${key}`, body: `b${key}` };
    }
    const keys = Object.keys(texts);
    const js = source({ texts, fallback: keys[0] as string });
    for (const k of keys) {
      const w = boot(js, { language: k });
      await w.fire('push', {});
      expect(w.shown[0]?.title).toBe(`t${k}`);
    }
  });
});

describe('option validation', () => {
  const bad = (over: Record<string, unknown>, reason: string) =>
    expect(
      buildServiceWorkerSource({ ...OPTIONS, ...over } as never),
      JSON.stringify(over),
    ).toEqual({
      ok: false,
      reason,
    });
  const text = (title: string, body = 'b') => ({ en: { title, body } });

  it('refuses a bad table, language, text, fallback, URL and tag with a code', () => {
    bad({ texts: {} }, 'texts');
    bad({ texts: null }, 'texts');
    bad({ texts: [] }, 'texts');
    bad({ texts: { EN: { title: 't', body: 'b' } } }, 'language');
    bad({ texts: { e: { title: 't', body: 'b' } } }, 'language');
    bad({ texts: { 'en-US': { title: 't', body: 'b' } } }, 'language');
    bad({ texts: { en: 'x' } }, 'text');
    bad({ texts: { en: { title: 't' } } }, 'text');
    bad({ texts: { en: { title: 't', body: 'b', extra: 1 } } }, 'text');
    bad({ texts: text('') }, 'text');
    bad({ texts: text('t', '') }, 'text');
    bad({ texts: text('t'.repeat(101)) }, 'text');
    bad({ texts: text('t', 'b'.repeat(301)) }, 'text');
    bad({ texts: text('a\nb') }, 'text');
    bad({ texts: text('a‮b') }, 'text'); // bidi override (format character)
    bad({ texts: text('a b') }, 'text');
    bad({ texts: text('a\ud800b') }, 'text'); // lone surrogate
    bad({ texts: text('a\u0000b') }, 'text');
    bad({ texts: text(5 as never) }, 'text');
    bad({ fallback: 'fr' }, 'fallback');
    bad({ fallback: '__proto__' }, 'fallback');
    bad({ fallback: 5 }, 'fallback');
    for (const appUrl of [
      'http://app.example/',
      '//evil.example/',
      'javascript:alert(1)',
      'https://app.example/#frag',
      'https://app.example/a b',
      'https://user@app.example/',
      'app/relative',
      '',
      5,
      `https://app.example/${'a'.repeat(500)}`,
    ])
      bad({ appUrl }, 'url');
    bad({ icon: 'javascript:1' }, 'url');
    bad({ badge: 'http://x/' }, 'url');
    for (const tag of ['', 'a b', 'a'.repeat(65), 'ä', 5, undefined]) bad({ tag }, 'tag');
    expect(buildServiceWorkerSource(null as never)).toEqual({ ok: false, reason: 'options' });
    expect(buildServiceWorkerSource('x' as never)).toEqual({ ok: false, reason: 'options' });
  });

  it('the limits are inclusive: 100-character title, 300-character body, 500-character URL, 64-character tag', () => {
    const ok = buildServiceWorkerSource({
      ...OPTIONS,
      texts: { en: { title: 't'.repeat(100), body: 'b'.repeat(300) } },
      appUrl: `https://app.example/${'a'.repeat(500 - 'https://app.example/'.length)}`,
      tag: 'x'.repeat(64),
    });
    expect(ok.ok).toBe(true);
  });

  it('more than 40 languages are refused', () => {
    const texts: Record<string, { title: string; body: string }> = {};
    for (let i = 0; i < 41; i += 1) {
      texts[
        `b${String.fromCharCode(97 + (i % 26))}${String.fromCharCode(97 + Math.floor(i / 26))}`
      ] = {
        title: 't',
        body: 'b',
      };
    }
    bad({ texts, fallback: Object.keys(texts)[0] }, 'texts');
  });

  it('options with a throwing getter are a code, not an exception', () => {
    const o = {
      get texts(): never {
        throw new Error('boom');
      },
    };
    expect(buildServiceWorkerSource(o as never)).toEqual({ ok: false, reason: 'options' });
  });
});
