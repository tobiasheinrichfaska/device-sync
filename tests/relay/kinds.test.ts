import { describe, expect, it } from 'vitest';
import {
  DROP_REFUSAL_TOKENS,
  LOCAL_KINDS,
  RELAY_KINDS,
  kindOfToken,
} from '../../src/relay/index.ts';

describe('the error-kind table', () => {
  it('has unique tokens and unique names, and well-formed rows', () => {
    expect(new Set(RELAY_KINDS.map((k) => k.token)).size).toBe(RELAY_KINDS.length);
    expect(new Set(RELAY_KINDS.map((k) => k.name)).size).toBe(RELAY_KINDS.length);
    for (const k of RELAY_KINDS) {
      expect(k.token, k.token).toMatch(/^[a-z][a-z-]{1,39}$/);
      expect(k.name, k.name).toMatch(/^[a-z][a-z-]+$/);
      expect(k.status === null || (k.status >= 400 && k.status <= 599), k.token).toBe(true);
    }
  });

  it('every retry kind has a delay hint, no fatal kind has one that invites a retry loop', () => {
    for (const k of RELAY_KINDS) {
      if (k.class === 'retry') expect(k.retryAfterMs, k.token).toBeGreaterThanOrEqual(250);
      if (k.class === 'fatal' || k.class === 'reenrol') expect(k.retryAfterMs, k.token).toBeNull();
    }
  });

  it('the classes of the kinds a client must act on', () => {
    const cls = (t: string): string | undefined => kindOfToken(t)?.class;
    expect(cls('zugang-abgelaufen')).toBe('reenrol');
    expect(cls('zugang-ungueltig')).toBe('reenrol');
    expect(cls('zu-viele-anfragen')).toBe('retry');
    expect(cls('gesperrt')).toBe('fatal');
    expect(cls('verbraucht')).toBe('fatal');
    expect(cls('empfaenger-voll')).toBe('refused');
  });

  it('looks a kind up by token and refuses what is not a known token', () => {
    expect(kindOfToken('unlesbar')?.status).toBe(400);
    for (const bad of [
      '',
      'UNLESBAR',
      '__proto__',
      'constructor',
      'toString',
      5,
      null,
      undefined,
      {},
    ]) {
      expect(kindOfToken(bad)).toBeUndefined();
    }
  });

  it('the refusals of one recipient are exactly the four without a status', () => {
    expect([...DROP_REFUSAL_TOKENS].sort()).toEqual([
      'absender-voll',
      'app-voll',
      'empfaenger-voll',
      'voll',
    ]);
  });

  it('local kinds have a class and never a token of the relay', () => {
    for (const [name, v] of Object.entries(LOCAL_KINDS)) {
      expect(['fatal', 'retry', 'reenrol']).toContain(v.class);
      expect(kindOfToken(name) === undefined || name === 'storage').toBe(true);
    }
  });
});
