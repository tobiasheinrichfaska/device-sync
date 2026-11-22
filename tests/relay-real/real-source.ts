// Finds, in the source of the real relay server, the few things the opt-in tests need by what the
// source says, not by the server's own name (this public package does not name it): the module that
// builds the relay object and the names of the two environment variables of its start.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

/** The module whose exported `…Anlegen(u: Umgebung)` builds the relay object (the one with `vorpruefen`). */
export async function loadCore(root: string): Promise<{ create: (u: unknown) => any }> {
  const dir = join(root, 'src');
  for (const name of readdirSync(dir).filter((n) => n.endsWith('.ts'))) {
    const text = readFileSync(join(dir, name), 'utf8');
    const m = /export function (\w+)\(u: Umgebung\)/.exec(text);
    if (m && text.includes('vorpruefen(')) {
      const mod = await import(pathToFileURL(join(dir, name)).href);
      return { create: mod[m[1] as string] };
    }
  }
  throw new Error('the real relay server source has no module that builds the relay object');
}

export function loadModule(root: string, name: string): Promise<any> {
  return import(pathToFileURL(join(root, 'src', `${name}.ts`)).href);
}

/** The names of the environment variables for the apps file and the secret, read from the start module. */
export function envNames(root: string): { apps: string; secret: string } {
  const text = readFileSync(join(root, 'src', 'start.ts'), 'utf8');
  const apps = /env\['([A-Z]+_APPS)'\]/.exec(text)?.[1];
  const secret = /env\['([A-Z]+_SCHLUESSEL)'\]/.exec(text)?.[1];
  if (!apps || !secret)
    throw new Error('cannot find the environment variable names in the start module');
  return { apps, secret };
}

/**
 * The two request headers of revision 2 as the real server spells them, read from the preflight
 * answer in its source (the names carry its own product name, which this public package does not write).
 */
export function realHeaderNames(root: string): { possession: string; version: string } {
  const text = readFileSync(join(root, 'src', 'treffpunkt.ts'), 'utf8');
  const m = /'authorization, content-type, (x-[a-z]+-[a-z]+), (x-[a-z]+-[a-z]+)'/.exec(text);
  if (!m?.[1] || !m[2]) throw new Error('cannot find the header names in the real server source');
  return { possession: m[1], version: m[2] };
}
