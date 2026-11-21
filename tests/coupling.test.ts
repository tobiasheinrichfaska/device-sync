// Guard: this is a public, app-independent package. It must not name the apps it was extracted from
// (files and git history), and must not import anything from outside itself.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import { STATUS } from '../src/index.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const SKIP = new Set(['node_modules', 'dist', '.git', '.tmp', 'package-lock.json', 'LICENSE']);
const SELF = join(ROOT, 'tests', 'coupling.test.ts');

// Words that identify private projects or their domain. Built from parts so this file is not a hit.
const FORBIDDEN = [
  ['tk', 'd'],
  ['trainer', 'buch'],
  ['az', 'p'],
  ['arbeits', 'zeit'],
  ['bürger', 'verein'],
  ['buerger', 'verein'],
  ['family', '-patch'],
  ['treff', 'punkt'],
  ['fa', 'ska'],
  ['sport', 'abzeichen'],
  ['kan', 'zlei'],
  ['tae', 'kwondo'],
].map((parts) => parts.join(''));

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    if (SKIP.has(name)) return [];
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

describe('coupling guard', () => {
  it('the scaffold exports only its status', () => {
    expect(STATUS).toBe('scaffold');
  });

  it('no file names a private project or its domain', () => {
    const hits: string[] = [];
    for (const path of files(ROOT)) {
      if (path === SELF || /\.(png|jpg|ico)$/.test(path)) continue;
      const text = readFileSync(path, 'utf8');
      // Whole words only: the repository owner's name contains one of them.
      for (const word of FORBIDDEN) {
        if (new RegExp(String.raw`\b${word}\b`, 'i').test(text))
          hits.push(`${relative(ROOT, path)}: ${word}`);
      }
    }
    expect(hits).toEqual([]);
  });

  it('source files import only relative paths and node:/own packages', () => {
    const bad: string[] = [];
    for (const path of files(join(ROOT, 'src'))) {
      const text = readFileSync(path, 'utf8');
      for (const m of text.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
        const spec = m[1]!;
        if (!spec.startsWith('.') && !spec.startsWith('node:') && !spec.startsWith('@noble/')) {
          bad.push(`${relative(ROOT, path)}: ${spec}`);
        }
      }
    }
    expect(bad).toEqual([]);
  });
});
