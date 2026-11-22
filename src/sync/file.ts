// The exchange file: what one device hands another by ANY way (a QR run, a mail, a memory stick, a
// direct connection) without a relay and without the other being online: the changes the other lacks
// (from the last stand of it that this device knows), this device's own stand (so the other can answer
// with a file of its own), the envelopes of the mailbox, and an optional notice slot. One file is
// sealed for ONE device (`sealFile`), carries no signature of its own (every change inside is signed by
// its author; the envelopes by theirs), and is judged exactly like what the relay brings.
//
// Why this exists next to the pull rounds (docs/sync.md, "Exchange by file"): a pull round needs a
// round trip and both devices online within 30 seconds of each other. A file is one way, asynchronous
// and carrier-free, and a device that remembers the other's last stand (`StandMemory`) sends only what
// is missing.
import { hasDuplicateKeys } from '../core/json.ts';
import {
  envelopeFromValue,
  openFile,
  readFileHeader,
  sealFile,
  type Envelope,
} from '../core/index.ts';
import { marker } from '../core/markers.ts';
import { decodeUtf8, hasMembers, isDeviceText, isPlain, parseJson } from '../core/secure.ts';
import { channelKeys } from '../channel/keys.ts';
import {
  emptyReplica,
  insertSignatures,
  onSyncMessage,
  parseSyncMessage,
  parseVector,
  receiveJudged,
  signOwnChanges,
  startSession,
  type JudgeOptions,
  type Limits as LogLimits,
  type Replica,
  type SessionOptions,
  type SyncMessage,
  type VersionVector,
} from '../log/index.ts';
import {
  EMPTY_MAILBOX,
  addEnvelopes,
  pruneMailbox,
  resolvePostLimits,
  type Mailbox,
} from '../post/index.ts';
import {
  judgeRemovalNotice,
  looksLikeRemovalNotice,
  readRemovalNotice,
  removalNotice,
  writeRemovalNotice,
  type NoticeVerdict,
  computeTrust,
  deviceKeySource,
  deviceNeverErase,
  resolveValidators,
  type Trust,
} from '../trust/index.ts';
import { FORBIDDEN_NAMES } from '../log/validate.ts';
import { resolveSyncLimits, type SyncCode } from './limits.ts';
import type { SyncHeld } from './sets.ts';
import type { SyncConfig } from './step.ts';
import { isSetName } from './wire.ts';

const utf8 = new TextEncoder();

export const fileMark = (appId: string): string => marker(appId, 'xfile', 1);

/** What this device knows of the stands of other devices: device, then data set, then the vector. */
export type StandMemory = Readonly<Record<string, Readonly<Record<string, VersionVector>>>>;

export const EMPTY_STANDS: StandMemory = Object.freeze({});

const dict = <T>(): Record<string, T> => Object.create(null) as Record<string, T>;

/**
 * The memory with `vector` as the last known stand of `device` in `set` (a stand that is not ahead of
 * the one remembered is not taken: remembered stands only grow). At most `maxRememberedPeers` devices
 * stay; the one touched earliest is forgotten first (so a forgotten peer costs one full file, nothing
 * more). A stand only ever says what the peer HAD, so a wrong memory costs a gap that the next file
 * fills, never a wrong replica.
 */
export function rememberStand(
  memory: StandMemory,
  device: string,
  set: string,
  vector: VersionVector,
  maxPeers: number = resolveSyncLimits().maxRememberedPeers,
): StandMemory {
  if (!isDeviceText(device) || FORBIDDEN_NAMES.has(device) || !isSetName(set)) return memory;
  const old = memory[device]?.[set] ?? {};
  const merged = dict<number>();
  for (const [d, n] of Object.entries(old)) merged[d] = n;
  for (const [d, n] of Object.entries(vector)) merged[d] = Math.max(merged[d] ?? 0, n);
  const out = dict<Record<string, VersionVector>>();
  // the touched peer goes last (most recent); the oldest are dropped past the bound
  const order = Object.keys(memory).filter((k) => k !== device);
  for (const k of order.slice(Math.max(0, order.length + 1 - maxPeers))) {
    out[k] = memory[k] as Record<string, VersionVector>;
  }
  const sets = dict<VersionVector>();
  for (const [s, v] of Object.entries(memory[device] ?? {})) sets[s] = v;
  sets[set] = merged;
  out[device] = sets;
  return out;
}

/** A stored memory, strictly (version vectors by the log's reader, names of one spelling); else undefined. */
export function readStandMemory(
  raw: unknown,
  options: { readonly maxPeers?: number; readonly maxSets?: number } = {},
): StandMemory | undefined {
  const lim = resolveSyncLimits();
  const maxPeers = options.maxPeers ?? lim.maxRememberedPeers;
  const maxSets = options.maxSets ?? lim.maxSets + 1;
  if (!isPlain(raw)) return undefined;
  const peers = Object.keys(raw);
  if (peers.length > maxPeers) return undefined;
  const out = dict<Record<string, VersionVector>>();
  for (const device of peers) {
    const sets = raw[device];
    if (
      !isDeviceText(device) ||
      FORBIDDEN_NAMES.has(device) ||
      !isPlain(sets) ||
      Object.keys(sets).length > maxSets
    ) {
      return undefined;
    }
    const copy = dict<VersionVector>();
    for (const [set, vector] of Object.entries(sets)) {
      const read = isSetName(set) ? parseVector(vector) : undefined;
      if (!read) return undefined;
      copy[set] = read;
    }
    out[device] = copy;
  }
  return out;
}

// ── the payload ───────────────────────────────────────────────────────────────────────────────

interface SetPart {
  readonly stand: Extract<SyncMessage, { t: 'stand' }>;
  readonly pieces: readonly Extract<SyncMessage, { t: 'changes' }>[];
}

interface FilePayload {
  readonly sets: ReadonlyMap<string, SetPart>;
  readonly envelopes: readonly Envelope[];
  readonly notice: string | null;
}

const MAX_PIECES = 64;

function writePayload(
  appId: string,
  parts: ReadonlyMap<string, SetPart>,
  envelopes: readonly Envelope[],
  notice: string | null,
): Uint8Array {
  const sets = [...parts].map(
    ([name, p]) =>
      `${JSON.stringify(name)}:{"stand":${JSON.stringify(p.stand)},"pieces":${JSON.stringify(p.pieces)}}`,
  );
  return utf8.encode(
    `{"m":"${fileMark(appId)}","sets":{${sets.join(',')}},"post":[${envelopes
      .map((e) => e.text)
      .join(',')}],"notice":${JSON.stringify(notice)}}`,
  );
}

/** The payload of an exchange file, strictly (one member list, duplicate keys refused, every message read by the log's and the post layer's parsers, bounded); undefined for anything else. Never throws. */
export function readExchangePayload(
  appId: string,
  bytes: Uint8Array,
  cfg: Pick<SyncConfig, 'log' | 'limits' | 'post'>,
  deviceId: (id: string) => boolean,
): FilePayload | undefined {
  const lim = resolveSyncLimits(cfg.limits);
  if (bytes.length === 0 || bytes.length > lim.maxExchangeFileBytes) return undefined;
  const text = decodeUtf8(bytes);
  if (text === undefined || !text.startsWith(`{"m":"${fileMark(appId)}","sets":{`)) {
    return undefined;
  }
  try {
    if (hasDuplicateKeys(text)) return undefined;
    const raw = parseJson(text);
    if (!isPlain(raw) || !hasMembers(raw, ['m', 'sets', 'post', 'notice'])) return undefined;
    if (raw.m !== fileMark(appId) || !isPlain(raw.sets) || !Array.isArray(raw.post)) {
      return undefined;
    }
    const notice = raw.notice;
    if (notice !== null && (typeof notice !== 'string' || notice.length > lim.maxNoticeChars)) {
      return undefined;
    }
    const parse = {
      limits: {
        ...cfg.log,
        maxSessionChanges: lim.answerChanges,
        maxSessionChars: lim.answerChars,
      },
      deviceId,
    };
    const names = Object.keys(raw.sets);
    if (names.length > lim.maxSets + 1) return undefined;
    const sets = new Map<string, SetPart>();
    for (const name of names) {
      const part = raw.sets[name];
      if (!isSetName(name) || !isPlain(part) || !hasMembers(part, ['stand', 'pieces'])) {
        return undefined;
      }
      const stand = parseSyncMessage(part.stand, parse);
      if (stand?.t !== 'stand' || !Array.isArray(part.pieces) || part.pieces.length > MAX_PIECES) {
        return undefined;
      }
      const pieces: Extract<SyncMessage, { t: 'changes' }>[] = [];
      for (const piece of part.pieces as unknown[]) {
        const message = parseSyncMessage(piece, parse);
        if (message?.t !== 'changes') return undefined;
        pieces.push(message);
      }
      sets.set(name, { stand, pieces });
    }
    const post = resolvePostLimits(cfg.post?.limits);
    if (raw.post.length > post.maxEnvelopes) return undefined;
    const envelopes: Envelope[] = [];
    for (const value of raw.post as unknown[]) {
      const envelope = envelopeFromValue(appId, value, post);
      if (!envelope) return undefined;
      envelopes.push(envelope);
    }
    return { sets, envelopes, notice };
  } catch {
    return undefined;
  }
}

// ── making a file ─────────────────────────────────────────────────────────────────────────────

export type ExchangeFileConfig = Pick<
  SyncConfig,
  'trust' | 'own' | 'direct' | 'random' | 'judge' | 'approval' | 'limits' | 'log' | 'sets' | 'post'
>;

export type ExchangeFileRefusal =
  'bad-input' | 'self-removed' | 'recipient-not-trusted' | 'too-large' | 'seal-failed';

export type MakeFileResult =
  | {
      readonly ok: true;
      /** The sealed file: hand it to the recipient by any way. */
      readonly file: Uint8Array;
      /** The replicas with this device's own changes signed (keep them). */
      readonly replica: Replica;
      readonly sets: Readonly<Record<string, Replica>>;
      /** Changes and envelopes in the file. */
      readonly changes: number;
      readonly envelopes: number;
      /** A set's answer was cut: the next file continues (the recipient's stand says where). */
      readonly more: boolean;
      /** The file is a removal notice for a removed recipient (no data, no envelopes, no notice slot). */
      readonly removalNotice?: true;
    }
  | { readonly ok: false; readonly reason: ExchangeFileRefusal; readonly detail?: string };

const directOf = (
  cfg: ExchangeFileConfig,
): ReturnType<typeof computeTrust> extends never ? never : Parameters<typeof computeTrust>[1] =>
  typeof cfg.direct === 'function' ? cfg.direct() : cfg.direct;

/**
 * The file for the trusted device `to`: per data set (the main one and every registered one that
 * `mayExchange` allows for `to`) this device's own stand and the changes `to` lacks according to
 * `memory` (nothing known: everything, cut to the answer budget; a cut set says `more`), the envelopes
 * of the mailbox (the newest `maxExchangeEnvelopes`; the recipient's quota and receipts decide the
 * rest) and `notice` (opaque text of at most `maxNoticeChars`, the app's: nothing here reads it).
 * Sealed for `to` alone. Nothing is remembered about what was sent: a file may be lost. The recipient
 * must be trusted now (`recipient-not-trusted`); this device must not be removed.
 */
export async function makeExchangeFile(
  cfg: ExchangeFileConfig,
  params: {
    readonly to: string;
    readonly replica: Replica;
    readonly held?: SyncHeld;
    readonly memory?: StandMemory;
    readonly notice?: string;
    readonly nowMs: number;
  },
): Promise<MakeFileResult> {
  const { appId, dataSet } = cfg.trust;
  const lim = resolveSyncLimits(cfg.limits);
  const refuse = (reason: ExchangeFileRefusal, detail?: string): MakeFileResult => ({
    ok: false,
    reason,
    ...(detail ? { detail } : {}),
  });
  const { own } = cfg;
  if (
    params.replica.device !== own.device ||
    !Number.isFinite(params.nowMs) ||
    !Number.isFinite(new Date(params.nowMs).getTime()) ||
    (params.notice !== undefined && params.notice.length > lim.maxNoticeChars)
  ) {
    return refuse('bad-input');
  }
  const names = Object.keys(cfg.sets ?? {});
  if (names.length > lim.maxSets || names.some((n) => !isSetName(n) || n === dataSet)) {
    return refuse('bad-input');
  }
  const signed = async (replica: Replica, set: string): Promise<Replica> =>
    insertSignatures(
      replica,
      await signOwnChanges(appId, own.keys.signing.privateKey, replica, set),
    );
  const main = await signed(params.replica, dataSet);
  const trust = await computeTrust(main, directOf(cfg), cfg.trust);
  if (trust.selfRemoved) return refuse('self-removed');
  const peer = trust.trusted.find((d) => d.device === params.to && d.device !== own.device);
  if (!peer) {
    // A device whose removal counts gets nothing but the removal notice (the proof that it was removed).
    const gone = trust.checkableById.get(params.to);
    if (!gone || !trust.removed.includes(params.to)) return refuse('recipient-not-trusted');
    const made = removalNotice(main, params.to, { ...cfg.trust, direct: directOf(cfg) });
    if (!made.ok) return refuse('recipient-not-trusted', made.reason);
    const sealed = await sealFile({
      appId,
      own: { device: own.device, agreement: own.keys.agreement },
      to: { device: gone.device, dh: gone.dh },
      payload: writeRemovalNotice(appId, made.changes),
      random: cfg.random(12),
    });
    if (!sealed.ok) return refuse('seal-failed', sealed.reason);
    return {
      ok: true,
      file: sealed.file,
      replica: main,
      sets: {},
      changes: 0,
      envelopes: 0,
      more: false,
      removalNotice: true,
    };
  }
  const valid = resolveValidators(cfg.trust.valid);
  const replicas = new Map<string, Replica>([[dataSet, main]]);
  for (const name of names) {
    replicas.set(name, await signed(params.held?.sets?.[name] ?? emptyReplica(own.device), name));
  }
  const rosterPeer = { device: peer.device, dh: peer.dh, relayId: peer.relayId ?? '' };
  const allowed = [...replicas.keys()].filter((name) => {
    try {
      const rule = cfg.sets?.[name]?.mayExchange;
      return rule ? rule(rosterPeer, trust) === true : true;
    } catch {
      return false;
    }
  });
  const today = new Date(params.nowMs).toISOString().slice(0, 10);
  const postLim = resolvePostLimits(cfg.post?.limits);
  let envelopes: readonly Envelope[] = [];
  if (cfg.post) {
    const box = pruneMailbox(appId, params.held?.mailbox ?? EMPTY_MAILBOX, today, postLim);
    envelopes = (box ?? EMPTY_MAILBOX).items.slice(-lim.maxExchangeEnvelopes);
  }
  const roundLimits = (changes: number, chars: number): Partial<LogLimits> => ({
    ...cfg.log,
    maxSessionChanges: changes,
    maxSessionChars: chars,
  });
  let changes = lim.answerChanges;
  let chars = lim.answerChars;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const parts = new Map<string, SetPart>();
    let count = 0;
    let more = false;
    for (const name of allowed) {
      const replica = replicas.get(name) as Replica;
      const started = startSession(replica).send[0];
      const options: SessionOptions = {
        limits: roundLimits(changes, chars),
        signedOnly: true,
        deviceId: valid.deviceId,
        ...(name === dataSet ? (cfg.approval ? { approval: cfg.approval } : {}) : {}),
      };
      const known = params.memory?.[params.to]?.[name] ?? {};
      const answer = onSyncMessage(
        startSession(replica).session,
        replica,
        {
          t: 'stand',
          vector: known,
          tips: {},
        },
        options,
      );
      if (started?.t !== 'stand' || answer.session.refusal) {
        return refuse('bad-input', answer.session.refusalReason);
      }
      const pieces = answer.send.filter(
        (m): m is Extract<SyncMessage, { t: 'changes' }> => m.t === 'changes',
      );
      for (const piece of pieces) {
        count += piece.changes.length;
        more ||= piece.more === true;
      }
      parts.set(name, { stand: started, pieces });
    }
    const payload = writePayload(appId, parts, envelopes, params.notice ?? null);
    if (payload.length <= lim.maxExchangeFileBytes) {
      const sealed = await sealFile({
        appId,
        own: { device: own.device, agreement: own.keys.agreement },
        to: { device: peer.device, dh: peer.dh },
        payload,
        random: cfg.random(12),
      });
      if (!sealed.ok) return refuse('seal-failed', sealed.reason);
      const sets: Record<string, Replica> = {};
      for (const [name, r] of replicas) if (name !== dataSet) sets[name] = r;
      return {
        ok: true,
        file: sealed.file,
        replica: main,
        sets,
        changes: count,
        envelopes: envelopes.length,
        more,
      };
    }
    if (changes <= 1 && chars <= 1) break;
    changes = Math.max(1, changes >> 1);
    chars = Math.max(1, chars >> 1);
  }
  return refuse('too-large');
}

// ── taking a file ─────────────────────────────────────────────────────────────────────────────

export type TakeFileRefusal =
  | 'bad-input'
  | 'self-removed'
  | 'not-a-file'
  | 'wrong-recipient'
  | 'sender-not-trusted'
  | 'cannot-open'
  | 'bad-payload';

export type TakeFileResult =
  | {
      readonly ok: true;
      /** The device whose key opened the file. */
      readonly from: string;
      readonly replica: Replica;
      readonly sets: Readonly<Record<string, Replica>>;
      readonly mailbox: Mailbox;
      /** Envelopes that came into the mailbox. */
      readonly received: readonly Envelope[];
      /** Changes merged (all sets). */
      readonly applied: number;
      /** The memory with the sender's stands in it: use it for the file you send back. */
      readonly memory: StandMemory;
      /** The sender's notice, exactly as it came (opaque; the app reads it). */
      readonly notice: string | null;
      /** Per data set: why its part was not taken (a refusal of the log, by code). Other sets are not affected. */
      readonly refused: Readonly<Record<string, string>>;
      /** The file did not hold everything the sender had for this device (a set was cut): ask for a file again. */
      readonly more: boolean;
      /** Codes of what was dropped (sets not registered, not allowed for the sender). */
      readonly dropped: Readonly<Record<string, number>>;
      /** With a removal notice instead of data: the verdict (`selfRemoved` says this device was removed). */
      readonly removal?: NoticeVerdict;
    }
  | { readonly ok: false; readonly reason: TakeFileRefusal; readonly detail?: string };

/**
 * Takes a file (the sealed bytes) into the replicas, as strictly as the relay path: the sender is the
 * trusted device whose key opens it, the payload is read by the strict reader, and every change is
 * judged by its signature and the app's rights; a set whose part fails (a forged change: the log's
 * refusal) is left out whole with its code and the others still count. A set that is not registered, or
 * that `mayExchange` refuses for the sender, is dropped (`unknown-set`, `set-not-allowed`). Envelopes
 * go through the mailbox's own rules (quota per sender and day). The sender's stands go into `memory`.
 */
export async function takeExchangeFile(
  cfg: ExchangeFileConfig,
  params: {
    readonly file: Uint8Array;
    readonly replica: Replica;
    readonly held?: SyncHeld;
    readonly memory?: StandMemory;
    readonly nowMs: number;
  },
): Promise<TakeFileResult> {
  const { appId, dataSet } = cfg.trust;
  const lim = resolveSyncLimits(cfg.limits);
  const refuse = (reason: TakeFileRefusal, detail?: string): TakeFileResult => ({
    ok: false,
    reason,
    ...(detail ? { detail } : {}),
  });
  const { own } = cfg;
  if (
    params.replica.device !== own.device ||
    !(params.file instanceof Uint8Array) ||
    !Number.isFinite(params.nowMs) ||
    !Number.isFinite(new Date(params.nowMs).getTime())
  ) {
    return refuse('bad-input');
  }
  const names = Object.keys(cfg.sets ?? {});
  if (names.length > lim.maxSets || names.some((n) => !isSetName(n) || n === dataSet)) {
    return refuse('bad-input');
  }
  const header = readFileHeader(appId, params.file);
  if (!header) return refuse('not-a-file');
  if (header.to !== own.device) return refuse('wrong-recipient');
  const direct = directOf(cfg);
  let main = params.replica;
  const trust: Trust = await computeTrust(main, direct, cfg.trust);
  if (trust.selfRemoved) return refuse('self-removed');
  const peer = trust.trusted.find((d) => d.device === header.from && d.device !== own.device);
  if (!peer) return refuse('sender-not-trusted');
  const opened = await openFile({
    appId,
    own: { device: own.device, agreement: own.keys.agreement },
    from: { device: peer.device, dh: peer.dh },
    file: params.file,
  });
  if (!opened.ok) return refuse('cannot-open', opened.reason);
  const valid = resolveValidators(cfg.trust.valid);
  if (looksLikeRemovalNotice(appId, opened.payload)) {
    // A removal notice is judged apart on a throw-away copy and never merged (docs/sync.md).
    const changes = readRemovalNotice(appId, opened.payload, {
      limits: cfg.log ?? {},
      deviceId: valid.deviceId,
      ...(cfg.trust.collection !== undefined ? { collection: cfg.trust.collection } : {}),
    });
    if (!changes) return refuse('bad-payload');
    const removal = await judgeRemovalNotice(main, direct, changes, cfg.trust);
    return {
      ok: true,
      from: peer.device,
      replica: main,
      sets: Object.fromEntries(
        Object.keys(cfg.sets ?? {}).map((n) => [
          n,
          params.held?.sets?.[n] ?? emptyReplica(own.device),
        ]),
      ),
      mailbox: params.held?.mailbox ?? EMPTY_MAILBOX,
      received: [],
      applied: 0,
      memory: params.memory ?? EMPTY_STANDS,
      notice: null,
      refused: {},
      more: false,
      dropped: {},
      removal,
    };
  }
  const payload = readExchangePayload(appId, opened.payload, cfg, valid.deviceId);
  if (!payload) return refuse('bad-payload');

  const dropped = dict<number>();
  const refused = dict<string>();
  const drop = (code: SyncCode | string): void => {
    dropped[code] = (dropped[code] ?? 0) + 1;
  };
  const roundLimits = (changes: number, chars: number): Partial<LogLimits> => ({
    ...cfg.log,
    maxSessionChanges: changes,
    maxSessionChars: chars,
  });
  const sessionOptions = (approval: SyncConfig['approval']): SessionOptions => ({
    limits: roundLimits(lim.answerChanges, lim.answerChars),
    signedOnly: true,
    deviceId: valid.deviceId,
    ...(approval ? { approval } : {}),
  });
  const rosterPeer = { device: peer.device, dh: peer.dh, relayId: peer.relayId ?? '' };
  const mayExchange = (set: string): boolean => {
    try {
      const rule = cfg.sets?.[set]?.mayExchange;
      return rule ? rule(rosterPeer, trust) === true : true;
    } catch {
      return false;
    }
  };
  const ownKey = { device: own.device, publicKey: own.keys.signing.publicKey };
  const otherKeys = channelKeys(trust, ownKey).keys;
  const sets: Record<string, Replica> = {};
  for (const name of names) sets[name] = params.held?.sets?.[name] ?? emptyReplica(own.device);
  let memory = params.memory ?? EMPTY_STANDS;
  let applied = 0;
  let more = false;
  let judgedMain: JudgeOptions | undefined;
  for (const [name, part] of payload.sets) {
    const isMain = name === dataSet;
    if (!isMain && !Object.hasOwn(sets, name)) {
      drop('unknown-set');
      continue;
    }
    if (!mayExchange(name)) {
      drop('set-not-allowed');
      continue;
    }
    const approval = isMain ? cfg.approval : cfg.sets?.[name]?.approval;
    const judged: JudgeOptions = isMain
      ? (judgedMain ??= {
          appId,
          dataSet,
          ownDevice: own.device,
          neverErase: deviceNeverErase(cfg.trust.collection),
          keys: deviceKeySource({ ...cfg.trust, direct, own: ownKey }),
          ...cfg.judge,
        })
      : {
          appId,
          dataSet: name,
          ownDevice: own.device,
          keys: otherKeys,
          ...cfg.sets?.[name]?.judge,
        };
    const options = sessionOptions(approval);
    let replica = isMain ? main : (sets[name] as Replica);
    let session = startSession(replica).session;
    let failure: string | undefined;
    let taken = 0;
    for (const piece of part.pieces) {
      const step = await receiveJudged(session, replica, piece, judged, options);
      if (step.session.refusal) {
        failure = `${step.session.refusal}:${step.session.refusalReason ?? ''}`;
        break;
      }
      session = step.session;
      replica = step.replica;
      taken = step.session.taken;
    }
    if (failure) {
      refused[name] = failure;
      continue;
    }
    applied += taken;
    more ||= session.peerMore === true || session.truncated === true;
    if (isMain) main = replica;
    else sets[name] = replica;
    memory = rememberStand(memory, peer.device, name, part.stand.vector, lim.maxRememberedPeers);
  }

  const today = new Date(params.nowMs).toISOString().slice(0, 10);
  const postLim = resolvePostLimits(cfg.post?.limits);
  let mailbox = params.held?.mailbox ?? EMPTY_MAILBOX;
  let received: readonly Envelope[] = [];
  if (payload.envelopes.length > 0) {
    if (!cfg.post) {
      drop('post-disabled');
    } else {
      const out = addEnvelopes(appId, mailbox, payload.envelopes, today, {
        from: peer.device,
        limits: postLim,
      });
      if (out.ok) {
        mailbox = out.mailbox;
        received = out.added;
      } else {
        drop('post-refused');
      }
    }
  }
  return {
    ok: true,
    from: peer.device,
    replica: main,
    sets,
    mailbox,
    received,
    applied,
    memory,
    notice: payload.notice,
    refused,
    more,
    dropped,
  };
}
