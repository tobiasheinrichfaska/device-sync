// Calendar days as the envelope and the mailbox use them: `YYYY-MM-DD`, one spelling, a real date.
// Pure: nothing here reads a clock (the caller passes "today").

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;
const MS_PER_DAY = 86_400_000;

/** A real calendar day in the form `YYYY-MM-DD`, year 1970 to 9999 (so `2026-02-30` is not one). */
export function isDay(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== 10) return false;
  const m = DAY.exec(value);
  if (!m) return false;
  const [year, month, day] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (year < 1970) return false;
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day
  );
}

/** Days since 1970-01-01 (UTC) of a day text that `isDay` accepts; NaN for anything else. */
export function dayNumber(day: string): number {
  return isDay(day) ? Date.parse(`${day}T00:00:00Z`) / MS_PER_DAY : Number.NaN;
}
