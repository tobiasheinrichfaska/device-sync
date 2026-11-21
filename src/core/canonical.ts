import { base64url, sha256Text } from './encoding.ts';

/** JSON with sorted keys and no undefined members: the same value always gives the same text. */
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const parts = Object.keys(record)
      .filter((k) => record[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(record[k])}`);
    return `{${parts.join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

/** Check value of any value: base64url(SHA-256(canonical(value))). */
export function checkValue(value: unknown): string {
  return base64url(sha256Text(canonical(value)));
}
