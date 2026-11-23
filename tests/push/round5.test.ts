// Round 5 review of the push layer: a "relative" URL that a browser reads as another origin.
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { buildServiceWorkerSource, type WorkerOptions } from '../../src/push/index.ts';

const OPTIONS: WorkerOptions = {
  texts: { en: { title: 'News', body: 'Something is new.' } },
  fallback: 'en',
  appUrl: 'https://app.example/start/',
  tag: 'news',
};

describe('round 5: URLs the worker is given', () => {
  it('a backslash after the first slash turns a path into another origin, so it is refused', () => {
    // new URL('/\\evil.example/x', 'https://app.example/sw.js').origin is https://evil.example
    expect(new URL('/\\evil.example/x', 'https://app.example/sw.js').origin).toBe(
      'https://evil.example',
    );
    for (const bad of [
      '/\\evil.example/x',
      '/a\\b',
      '/\\\\evil.example',
      'https://a.example/\\b',
    ]) {
      for (const field of ['appUrl', 'icon', 'badge'] as const) {
        const r = buildServiceWorkerSource({ ...OPTIONS, [field]: bad });
        expect(r, `${field} ${bad}`).toEqual({ ok: false, reason: 'url' });
      }
    }
  });

  it('every accepted path stays on the app origin (seeded random tails)', () => {
    let seed = 12345;
    const rnd = (): number => {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      return seed / 2 ** 32;
    };
    const alphabet = '/\\.:@?%-_aZ0~!$&\'()*+,;=[]{}|^`"<>';
    let accepted = 0;
    for (let i = 0; i < 3000; i++) {
      let tail = '';
      for (let k = 1 + Math.floor(rnd() * 6); k > 0; k--)
        tail += alphabet[Math.floor(rnd() * alphabet.length)];
      const candidate = `/${tail}`;
      const r = buildServiceWorkerSource({ ...OPTIONS, appUrl: candidate });
      if (!r.ok) continue;
      accepted += 1;
      expect(new URL(candidate, 'https://app.example/sw.js').origin, candidate).toBe(
        'https://app.example',
      );
      expect(() => runInNewContext(`(function(){${r.value}\n})`), candidate).not.toThrow();
    }
    expect(accepted).toBeGreaterThan(100);
  });
});
