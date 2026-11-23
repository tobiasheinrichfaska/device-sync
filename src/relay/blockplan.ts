// Reporting blocks again and again (docs/relay-protocol.md, "Blocking, `sperren`"): the relay keeps its
// list of blocked devices in RAM, so a restart forgets it. A certificate lives 60 days and a blocked
// device cannot renew it, so whoever blocks reports the block ONCE when it blocks and then DAILY (at
// every start of the app and once a day) for 60 days, 90 for a device that still held an old access.
// This device keeps, for each device it blocked, the day of the block and the day it last reported it.
// Pure: the plan is a list the app stores, read strictly; days are `YYYY-MM-DD` strings, the clock is a
// parameter. `repeatBlocks` runs one round against a client.
import { RELAY_DEVICE_ID } from './strict.ts';
import type { RelayClient, RelayFailure } from './client.ts';

export const BLOCK_PLAN = {
  /** Days a block is reported: a certificate lives 60 days. */
  days: 60,
  /** … and for a device with an old access (90 days). */
  daysOldAccess: 90,
  /** The relay takes 30 blocks per device and hour; a round reports at most this many. */
  perRound: 25,
  /** Entries kept (the relay's list holds 500 per group). */
  maxEntries: 500,
} as const;

const DAY = /^\d{4}-\d{2}-\d{2}$/;

export interface BlockPlanEntry {
  readonly device: string;
  /** The day of the block. */
  readonly since: string;
  /** The last day it is still reported. */
  readonly until: string;
  /** The day it was last reported. */
  readonly last?: string;
}

const isDay = (v: unknown): v is string =>
  typeof v === 'string' &&
  DAY.test(v) &&
  !Number.isNaN(Date.parse(`${v}T00:00:00Z`)) &&
  new Date(`${v}T00:00:00Z`).toISOString().slice(0, 10) === v;

const dayPlus = (day: string, days: number): string =>
  new Date(Date.parse(`${day}T00:00:00Z`) + days * 86_400_000).toISOString().slice(0, 10);

/** The day (UTC) of a time in ms. */
export const planDay = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

/** The stored plan, strictly read: a damaged entry is dropped, never trusted; no device twice; bounded. Never throws. */
export function readBlockPlan(raw: unknown): BlockPlanEntry[] {
  if (!Array.isArray(raw)) return [];
  const out: BlockPlanEntry[] = [];
  const seen = new Set<string>();
  for (const e of raw.slice(0, BLOCK_PLAN.maxEntries)) {
    if (typeof e !== 'object' || e === null || Array.isArray(e)) continue;
    const o = e as Record<string, unknown>;
    const keys = Object.keys(o);
    if (!keys.every((k) => ['device', 'since', 'until', 'last'].includes(k))) continue;
    const { device, since, until, last } = o;
    if (typeof device !== 'string' || !RELAY_DEVICE_ID.test(device) || seen.has(device)) continue;
    if (!isDay(since) || !isDay(until)) continue;
    if (last !== undefined && !isDay(last)) continue;
    seen.add(device);
    out.push({ device, since, until, ...(last === undefined ? {} : { last }) });
  }
  return out;
}

/** A block made today (`oldAccess`: the device held an old access, 90 days). The same device again keeps the longer end. */
export function noteBlock(
  plan: readonly BlockPlanEntry[],
  b: { readonly device: string; readonly today: string; readonly oldAccess?: boolean },
): BlockPlanEntry[] {
  if (!RELAY_DEVICE_ID.test(b.device) || !isDay(b.today)) return [...plan];
  const until = dayPlus(b.today, b.oldAccess === true ? BLOCK_PLAN.daysOldAccess : BLOCK_PLAN.days);
  if (plan.some((e) => e.device === b.device)) {
    return plan.map((e) => (e.device === b.device && e.until < until ? { ...e, until } : e));
  }
  return [...plan, { device: b.device, since: b.today, until }].slice(-BLOCK_PLAN.maxEntries);
}

/** Drops what ran out (the day after `until`): the blocked device's certificate cannot be valid any more. */
export const cleanBlockPlan = (plan: readonly BlockPlanEntry[], today: string): BlockPlanEntry[] =>
  plan.filter((e) => e.until >= today);

/**
 * Which blocks to report now: at a start of the app (`start`) every one that has not run out, else those
 * not yet reported today; never reported or longest ago first, at most `max` (default `perRound`).
 */
export function dueBlocks(
  plan: readonly BlockPlanEntry[],
  o: { readonly today: string; readonly start?: boolean; readonly max?: number },
): string[] {
  return cleanBlockPlan(plan, o.today)
    .filter((e) => o.start === true || e.last !== o.today)
    .sort((a, b) => (a.last ?? '').localeCompare(b.last ?? ''))
    .slice(0, o.max ?? BLOCK_PLAN.perRound)
    .map((e) => e.device);
}

/** Notes that `devices` were reported today. */
export const markReported = (
  plan: readonly BlockPlanEntry[],
  devices: readonly string[],
  today: string,
): BlockPlanEntry[] => plan.map((e) => (devices.includes(e.device) ? { ...e, last: today } : e));

/**
 * One round: reports what is due. A refusal for lack of rights (`role-not-allowed`, `device-unknown`) or a
 * full list counts as reported (it would be the same again); any other failure (the net, the relay busy)
 * ends the round and the rest follows at the next one. → the new plan, how many were reported, how many
 * are still open today.
 */
export async function repeatBlocks(
  client: Pick<RelayClient, 'block'>,
  plan: readonly BlockPlanEntry[],
  o: { readonly today: string; readonly start?: boolean; readonly max?: number },
): Promise<{ readonly plan: BlockPlanEntry[]; readonly reported: number; readonly open: number }> {
  let current = cleanBlockPlan(plan, o.today);
  let reported = 0;
  for (const device of dueBlocks(current, o)) {
    const r = await client.block(device);
    if (r.ok) reported += 1;
    else if (!accepted(r)) break;
    current = markReported(current, [device], o.today);
  }
  return { plan: current, reported, open: dueBlocks(current, { today: o.today }).length };
}

/**
 * Blocks a device and notes the block for the daily repetition. The note is made FIRST, so a block the net
 * did not take is repeated by the next round; a device that blocks itself is not noted (a blocked device
 * cannot report, and what it holds goes at once: the client's blocked hook). → the new plan and the result
 * of the call.
 */
export async function blockAndNote(
  client: Pick<RelayClient, 'block' | 'deviceId'>,
  plan: readonly BlockPlanEntry[],
  device: string,
  o: { readonly today: string; readonly oldAccess?: boolean },
): Promise<{
  readonly plan: BlockPlanEntry[];
  readonly result: Awaited<ReturnType<RelayClient['block']>>;
}> {
  const own = await client.deviceId();
  const note = device !== own;
  let current = note
    ? noteBlock(plan, { device, today: o.today, oldAccess: o.oldAccess === true })
    : [...plan];
  const result = await client.block(device);
  if (result.ok && note) current = markReported(current, [device], o.today);
  return { plan: current, result };
}

/** A refusal that is final for this block: asking again gives the same answer. */
const accepted = (f: RelayFailure): boolean =>
  f.kind === 'role-not-allowed' || f.kind === 'device-unknown' || f.kind === 'blocklist-full';

/**
 * Takes blocks that other devices reported (for example a member's device that cannot repeat a block
 * itself after the relay forgot the device) into the plan, so this device repeats them like its own: from
 * the day of the block, 60 days (90 for `oldAccess`). A report that ran out is not taken; one the plan holds
 * keeps its day of last reporting, the longer end and the earlier day of the block. A day in the future
 * counts as today (a wrong clock must not stretch the 60 days).
 */
export function planFromReports(
  plan: readonly BlockPlanEntry[],
  reports: readonly {
    readonly device: string;
    readonly since: string;
    readonly oldAccess?: boolean;
  }[],
  today: string,
): BlockPlanEntry[] {
  let out = [...plan];
  for (const r of reports) {
    if (!RELAY_DEVICE_ID.test(r.device) || !isDay(r.since)) continue;
    const since = r.since > today ? today : r.since;
    if (dayPlus(since, r.oldAccess === true ? BLOCK_PLAN.daysOldAccess : BLOCK_PLAN.days) < today) {
      continue;
    }
    const had = out.find((e) => e.device === r.device);
    out = noteBlock(out, { device: r.device, today: since, oldAccess: r.oldAccess === true });
    if (had && had.since > since) {
      out = out.map((e) => (e.device === r.device ? { ...e, since } : e));
    }
  }
  return out;
}
