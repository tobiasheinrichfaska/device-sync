// One step of the sync driver. The app calls `syncOnce` when it likes (a timer, a poll loop, a
// visibility change); the step reads the clock only from its parameter, keeps no timer and never
// loops: collect, judge, answer, ask, drop, report.
//
// What is enforced here, not left to the caller (docs/sync.md):
//  - recipients come from the trust layer (`Trust.trusted`), never from the caller; a removed,
//    untrusted or unknown device gets nothing, and what was queued for it is dropped;
//  - what comes in is filtered at the transport, before any merge: first by the relay id (a bound on
//    what is assembled), then by the sender named in the file and the key that opens it;
//  - the sender is the device whose agreement key opens the file, never the relay's `from`.
import {
  openFile,
  readFileHeader,
  sealFile,
  type DeviceKeys,
  type Envelope,
} from '../core/index.ts';
import {
  deviceNeverErase,
  computeTrust,
  deviceKeySource,
  resolveValidators,
  type KnownDevice,
  type Trust,
  type TrustOptions,
} from '../trust/index.ts';
import { channelKeys } from '../channel/keys.ts';
import {
  EMPTY_MAILBOX,
  addEnvelopes,
  applyReceipts,
  keepNewest,
  mailboxCheck,
  postDone,
  postStart,
  postStep,
  pruneMailbox,
  readPostMessage,
  readReceipts,
  resolvePostLimits,
  type Mailbox,
} from '../post/index.ts';
import {
  emptyReplica,
  insertSignatures,
  onSyncMessage,
  receiveJudged,
  seen,
  signOwnChanges,
  startSession,
  type ApprovalOptions,
  type JudgeOptions,
  type Limits as LogLimits,
  type Replica,
  type SessionOptions,
  type SyncMessage,
  type VersionVector,
} from '../log/index.ts';
import {
  FRAMING_LIMITS,
  RECOMMENDED_POLL,
  type CollectAllValue,
  type CollectedMessage,
  type DropValue,
  type RelayFailure,
  type RelayResult,
} from '../relay/index.ts';
import type { RelayClient } from '../relay/index.ts';
import { resolveSyncLimits, type SyncCode, type SyncLimits } from './limits.ts';
import { buildRoster, type Peer, type Roster } from './roster.ts';
import {
  frameOf,
  peerState,
  queuedFrames,
  setPeer,
  type PeerState,
  type Queued,
  type Round,
  type SetPeerState,
  type SyncState,
} from './state.ts';
import type { PostConfig, SetConfig, SyncHeld } from './sets.ts';
import { isSetName, looksLikePacket, readPacket, writePacket, writePostPacket } from './wire.ts';

/** What the step needs from the relay client (a `RelayClient` is one; a test may wrap it). */
export type SyncRelay = Pick<RelayClient, 'deviceId' | 'collectAll' | 'drop'>;

export interface SyncConfig {
  /** App id, data set, strategy for who may vouch, validators: the trust layer's options. */
  readonly trust: TrustOptions;
  /** This device: its id and its keys (signing signs its own changes, agreement seals and opens files). */
  readonly own: { readonly device: string; readonly keys: DeviceKeys };
  readonly relay: SyncRelay;
  /** The devices met in person (the roots of the trust derivation); a function is asked on every step. */
  readonly direct: readonly KnownDevice[] | (() => readonly KnownDevice[]);
  /** Random bytes (exactly `n`): a parameter, never read from a global. */
  readonly random: (n: number) => Uint8Array;
  /** The app's hooks of the log layer (who may write, final deletion, quota, special cases). */
  readonly judge?: Pick<JudgeOptions, 'mayWrite' | 'allowFinalDelete' | 'quota' | 'special'>;
  /** Hold back until approved (`docs/approval.md`). */
  readonly approval?: ApprovalOptions;
  readonly limits?: Partial<SyncLimits>;
  /** Overrides of the log layer's limits (not the round budget, which `limits` sets). */
  readonly log?: Partial<LogLimits>;
  /**
   * More data sets besides the main one (`trust.dataSet`), by name, with the app's rules for each. A set
   * that is registered here is exchanged with every peer its `mayExchange` allows; its replica comes in
   * `held.sets` and goes out in `SyncResult.sets`. A set not registered is refused (`unknown-set`).
   */
  readonly sets?: Readonly<Record<string, SetConfig>>;
  /** Envelope traffic: with it the mailbox travels with the sync (`held.mailbox`); without it none does. */
  readonly post?: PostConfig;
}

export interface SyncEvent {
  readonly code: SyncCode;
  readonly device?: string;
  /** A short code of the cause (a refusal reason of the log, a relay kind), never a sentence. */
  readonly detail?: string;
}

export interface PassedFile {
  /** The trusted device whose key opened the file. */
  readonly from: string;
  /** The file as received (for example a key grant: hand it to `acceptGrant`). */
  readonly file: Uint8Array;
}

export interface SyncReport {
  /** The derived trust this step worked with (at its end). */
  readonly trust: Trust;
  /** This device's own removal counts: the step did nothing else. */
  readonly selfRemoved: boolean;
  /** Devices whose removal counted for the first time at this step (their keys may need rotating). */
  readonly newlyRemoved: readonly string[];
  /** Devices the step exchanges with: trusted, with a usable relay id. */
  readonly peers: readonly string[];
  /** Peers the relay said are present (collected within 30 s). */
  readonly present: readonly string[];
  readonly collected: number;
  /** Changes merged into the replica by this step. */
  readonly applied: number;
  /** Frames the relay took, and messages (one sealed packet or file) completed. */
  readonly framesSent: number;
  readonly messagesSent: number;
  /** What was dropped at the transport this step, by code. */
  readonly dropped: Readonly<Record<string, number>>;
  /** Files of trusted devices that are not sync packets. */
  readonly passed: readonly PassedFile[];
  /** Envelopes that came into the mailbox at this step (open the ones for this device: `openChannel`). */
  readonly received: readonly Envelope[];
  /** Envelopes dropped from the mailbox at this step because an allowed receipt covered them. */
  readonly acknowledged: number;
  readonly events: readonly SyncEvent[];
  /** Something is still going on (a round, queued frames, a cut answer): call again soon. */
  readonly busy: boolean;
  /** The relay call that failed, if any (the step went on with what it had). */
  readonly relay?: { readonly kind: string; readonly class: string };
  /** The wait before the next step that the relay layer recommends (busy: 1 s, idle: 10 s). */
  readonly nextMs: number;
}

export type SyncResult =
  | {
      readonly ok: true;
      /** The main replica. */
      readonly replica: Replica;
      /** The registered sets' replicas (every registered name, changed or not). */
      readonly sets: Readonly<Record<string, Replica>>;
      /** The mailbox (pruned, with what came in; the one given when there is no `cfg.post`). */
      readonly mailbox: Mailbox;
      readonly report: SyncReport;
    }
  | { readonly ok: false; readonly reason: 'busy' | 'not-enrolled' | 'bad-input' };

const vectorKey = (v: VersionVector): string => JSON.stringify(Object.entries(v).sort());

const isAhead = (theirs: VersionVector, ours: VersionVector): boolean =>
  Object.entries(theirs).some(([device, n]) => n > seen(ours, device));

/** Frames an answer packet of `bytes` needs at most (sealing: base64url plus the file members). */
const estimateFrames = (bytes: number, part: number): number =>
  Math.max(1, Math.ceil((Math.ceil(((bytes + 16) * 4) / 3) + 700) / part));

/**
 * One step. Order: sign own changes, derive trust and the roster, drop what belongs to devices that
 * are no peers any more, collect, take in what came (filtered, opened, judged, merged), answer asks,
 * ask the present peers that are due, drop what is queued. Returns the new replica and a report;
 * never throws on relay or peer input (a failure is a code in the report). The relay's failure of a
 * call does not end the step: what can be done without it is done.
 */
export async function syncOnce(
  cfg: SyncConfig,
  state: SyncState,
  replica: Replica,
  nowMs: number,
  held: SyncHeld = {},
): Promise<SyncResult> {
  if (state.busy) return { ok: false, reason: 'busy' };
  if (
    !Number.isFinite(nowMs) ||
    !Number.isFinite(new Date(nowMs).getTime()) ||
    replica.device !== cfg.own.device ||
    !registryOk(cfg, held)
  ) {
    return { ok: false, reason: 'bad-input' };
  }
  state.busy = true;
  try {
    return await run(cfg, state, replica, nowMs, held);
  } finally {
    state.busy = false;
  }
}

/** The registry is well-formed: names of one spelling, not the main set, at most `maxSets`; held replicas are this device's. */
function registryOk(cfg: SyncConfig, held: SyncHeld): boolean {
  const names = Object.keys(cfg.sets ?? {});
  if (names.length > resolveSyncLimits(cfg.limits).maxSets) return false;
  if (names.some((n) => !isSetName(n) || n === cfg.trust.dataSet)) return false;
  return Object.entries(held.sets ?? {}).every(
    ([n, r]) => names.includes(n) && r.device === cfg.own.device,
  );
}

interface SetCtx {
  readonly name: string;
  readonly isMain: boolean;
  replica: Replica;
  judged: JudgeOptions;
  readonly options: SessionOptions;
  readonly config: SetConfig | undefined;
}

async function run(
  cfg: SyncConfig,
  state: SyncState,
  start: Replica,
  now: number,
  held: SyncHeld,
): Promise<SyncResult> {
  const { appId, dataSet } = cfg.trust;
  const lim = resolveSyncLimits(cfg.limits);
  const ownRelay = await cfg.relay.deviceId();
  if (ownRelay === undefined) return { ok: false, reason: 'not-enrolled' };
  const own = cfg.own;
  const valid = resolveValidators(cfg.trust.valid);
  const directNow = (): readonly KnownDevice[] =>
    typeof cfg.direct === 'function' ? cfg.direct() : cfg.direct;

  const dropped: Record<string, number> = Object.create(null) as Record<string, number>;
  const events: SyncEvent[] = [];
  const note = (code: SyncCode, device?: string, detail?: string): void => {
    dropped[code] = (dropped[code] ?? 0) + 1;
    state.counters[code] = (state.counters[code] ?? 0) + 1;
    if (events.length < lim.maxEvents) {
      events.push({
        code,
        ...(device === undefined ? {} : { device }),
        ...(detail === undefined ? {} : { detail }),
      });
    }
  };
  const count = (code: string): void => {
    dropped[code] = (dropped[code] ?? 0) + 1;
    state.counters[code] = (state.counters[code] ?? 0) + 1;
  };

  // The log's session options: the round budget is the answer budget, in both directions.
  const roundLimits = (changes: number, chars: number): Partial<LogLimits> => ({
    ...cfg.log,
    maxSessionChanges: changes,
    maxSessionChars: chars,
  });
  const optionsFor = (approval: ApprovalOptions | undefined): SessionOptions => ({
    limits: roundLimits(lim.answerChanges, lim.answerChars),
    signedOnly: true,
    deviceId: valid.deviceId,
    ...(approval ? { approval } : {}),
  });
  const parseOptions = {
    limits: roundLimits(lim.answerChanges, lim.answerChars),
    deviceId: valid.deviceId,
  };
  const postCfg = cfg.post;
  const postLim = resolvePostLimits(postCfg?.limits);
  const today = new Date(now).toISOString().slice(0, 10);

  // 1. Own changes get their signatures (an unsigned change is never sent: numbering is gapless).
  const mainReplica = insertSignatures(
    start,
    await signOwnChanges(appId, own.keys.signing.privateKey, start, dataSet),
  );
  let replica = mainReplica;

  // 2. Trust and roster, from the replica as it stands.
  let direct = directNow();
  const judge = (): JudgeOptions => ({
    appId,
    dataSet,
    ownDevice: own.device,
    neverErase: deviceNeverErase(cfg.trust.collection),
    keys: deviceKeySource({
      ...cfg.trust,
      direct,
      own: { device: own.device, publicKey: own.keys.signing.publicKey },
    }),
    ...cfg.judge,
  });
  let trust = await computeTrust(replica, direct, cfg.trust);
  let trustedFor = replica;
  let roster = buildRoster(trust, own.device, ownRelay);

  // The data sets: the main one and the registered ones (keys for the others come from the same trust).
  const ctxs = new Map<string, SetCtx>();
  ctxs.set(dataSet, {
    name: dataSet,
    isMain: true,
    replica,
    judged: judge(),
    options: optionsFor(cfg.approval),
    config: undefined,
  });
  const otherKeys = channelKeys(() => trust, {
    device: own.device,
    publicKey: own.keys.signing.publicKey,
  }).keys;
  for (const [name, config] of Object.entries(cfg.sets ?? {})) {
    const held0 = held.sets?.[name] ?? emptyReplica(own.device);
    const signed = insertSignatures(
      held0,
      await signOwnChanges(appId, own.keys.signing.privateKey, held0, name),
    );
    ctxs.set(name, {
      name,
      isMain: false,
      replica: signed,
      judged: {
        appId,
        dataSet: name,
        ownDevice: own.device,
        keys: otherKeys,
        ...config.judge,
      },
      options: optionsFor(config.approval),
      config,
    });
  }
  const mainCtx = ctxs.get(dataSet) as SetCtx;
  const refresh = async (): Promise<void> => {
    if (trustedFor === mainCtx.replica) return;
    replica = mainCtx.replica;
    trust = await computeTrust(replica, direct, cfg.trust);
    trustedFor = replica;
    roster = buildRoster(trust, own.device, ownRelay);
  };
  const may = (ctx: SetCtx, peer: Peer): boolean => {
    try {
      return ctx.config?.mayExchange ? ctx.config.mayExchange(peer, trust) === true : true;
    } catch {
      return false;
    }
  };
  const mayCarry = (peer: Peer): boolean => {
    try {
      return postCfg?.mayCarry ? postCfg.mayCarry(peer, trust) === true : true;
    } catch {
      return false;
    }
  };

  // The mailbox: pruned once per step, kept only when envelope traffic is configured.
  let mailbox: Mailbox = held.mailbox ?? EMPTY_MAILBOX;
  if (postCfg) mailbox = pruneMailbox(appId, mailbox, today, postLim) ?? mailbox;
  const received: Envelope[] = [];
  let acknowledged = 0;

  let applied = 0;
  let collectedCount = 0;
  let collectFailed = false;
  let framesSent = 0;
  let messagesSent = 0;
  const passed: PassedFile[] = [];
  let present: readonly string[] = [];
  let relayFailure: { kind: string; class: string } | undefined;

  const nextDelay = (busy: boolean): number => {
    if (collectFailed) {
      const wait = Math.min(
        lim.failureCapMs,
        lim.failureBaseMs * 2 ** Math.max(0, state.failures - 1),
      );
      return Math.max(wait, RECOMMENDED_POLL.minMs);
    }
    return busy || now < state.busyUntil ? RECOMMENDED_POLL.busyMs : RECOMMENDED_POLL.idleMs;
  };
  const finish = (): SyncResult => {
    const newlyRemoved = trust.removed.filter((id) => !state.removed.has(id));
    state.removed = new Set(trust.removed);
    const busy =
      [...state.peers.values()].some(
        (p) =>
          p.post.round !== undefined ||
          [...p.sets.values()].some((sp) => sp.round !== undefined || sp.again),
      ) || [...state.outbox.values()].some((q) => q.length > 0);
    const report: SyncReport = {
      trust,
      selfRemoved: trust.selfRemoved,
      newlyRemoved,
      peers: [...roster.peers.keys()],
      present: roster.peers.size === 0 ? [] : present.filter((id) => roster.byRelay.has(id)),
      collected: collectedCount,
      applied,
      framesSent,
      messagesSent,
      dropped,
      passed,
      received,
      acknowledged,
      events,
      busy,
      ...(relayFailure ? { relay: relayFailure } : {}),
      nextMs: nextDelay(busy),
    };
    const sets: Record<string, Replica> = {};
    for (const [name, ctx] of ctxs) if (!ctx.isMain) sets[name] = ctx.replica;
    return { ok: true, replica: mainCtx.replica, sets, mailbox, report };
  };

  const forget = (device: string): void => {
    state.peers.delete(device);
    state.outbox.delete(device);
  };
  const purge = (): void => {
    for (const device of [...state.peers.keys()]) if (!roster.peers.has(device)) forget(device);
    for (const device of [...state.outbox.keys()]) {
      if (!roster.peers.has(device)) {
        const queued = state.outbox.get(device) ?? [];
        for (let i = 0; i < queued.length; i += 1) note('recipient-not-trusted', device);
        forget(device);
      }
    }
  };

  // 3. A removed device does nothing: no collect (its messages are not its to take), no sending.
  if (trust.selfRemoved) {
    for (const device of [...state.peers.keys()]) forget(device);
    for (const device of [...state.outbox.keys()]) forget(device);
    note('self-removed');
    return finish();
  }
  for (const x of roster.excluded) note(x.reason, x.device);
  purge();

  // 4. Time passes: rounds and queued frames the relay would have dropped by now.
  for (const [device, p] of state.peers) {
    for (const sp of p.sets.values()) {
      if (sp.round && now - sp.round.startedMs >= lim.roundMs) {
        sp.round = undefined;
        sp.again = true;
        sp.endedMs = now;
        note('round-timeout', device);
      }
    }
    if (p.post.round && now - p.post.round.startedMs >= lim.roundMs) {
      p.post.round = undefined;
      p.post.endedMs = now;
      note('round-timeout', device, 'post');
    }
  }
  for (const [device, list] of state.outbox) {
    const keep = list.filter((q) => now - q.queuedMs < lim.outboxMs);
    for (let i = keep.length; i < list.length; i += 1) note('outbox-expired', device);
    if (keep.length === 0) state.outbox.delete(device);
    else state.outbox.set(device, keep);
  }
  state.assembler.sweep(now);

  // 5. Collect (asking the presence of the peers in the same call).
  let collected: readonly CollectedMessage[] = [];
  const ask = [...roster.byRelay.keys()].slice(0, 200);
  const got: RelayResult<CollectAllValue> = await cfg.relay.collectAll({
    ask,
    maxCalls: lim.maxCollectCalls,
    maxMessages: lim.maxMessagesPerStep,
    maxBytes: lim.maxCollectBytes,
  });
  if (got.ok) {
    state.failures = 0;
    collected = got.value.messages;
    present = got.value.present;
    if (got.value.interrupted) {
      relayFailure = { kind: got.value.interrupted.kind, class: got.value.interrupted.class };
      note('collect-interrupted', undefined, got.value.interrupted.kind);
    }
  } else {
    relayFailure = { kind: got.kind, class: got.class };
    collectFailed = true;
    state.failures += 1;
    note('collect-failed', undefined, got.kind);
  }

  // 6. What came in.
  collectedCount = collected.length;
  if (collectedCount > 0) state.busyUntil = now + lim.busyHoldMs;
  for (const message of collected) {
    await takeIn(message);
  }
  takeReceipts();

  // 7. Ask the present peers that are due.
  await refresh();
  if (relayFailure === undefined || relayFailure.class === 'retry') {
    await askPeers();
    await askPost();
  }

  // 8. Drop what is queued.
  await drain();

  return finish();

  // ── inbound ─────────────────────────────────────────────────────────────────────────────────

  async function takeIn(message: CollectedMessage): Promise<void> {
    await refresh();
    // The relay's `from` is a routing hint: it bounds what is assembled (only peers' frames are),
    // and it is checked against the file's sender below. It identifies nobody.
    const device = roster.byRelay.get(message.from);
    if (device === undefined) {
      note(roster.removedRelay.has(message.from) ? 'removed-sender' : 'unknown-sender');
      return;
    }
    const piece = state.assembler.accept(message.from, message.content, now);
    if (piece.kind === 'pending') return;
    if (piece.kind === 'duplicate') return count('duplicate-frame');
    if (piece.kind === 'refused') return note('frame-refused', device, piece.reason);
    await takeFile(device, piece.id, piece.payload);
  }

  async function takeFile(expected: string, transfer: string, file: Uint8Array): Promise<void> {
    const header = readFileHeader(appId, file);
    if (!header) return note('not-a-file', expected);
    if (header.to !== own.device) return note('wrong-recipient', expected);
    if (header.from !== expected) return note('sender-mismatch', expected, header.from);
    const peer = roster.peers.get(header.from);
    if (!peer) return note('sender-not-trusted', header.from);
    const opened = await openFile({
      appId,
      own: { device: own.device, agreement: own.keys.agreement },
      from: { device: peer.device, dh: peer.dh },
      file,
    });
    if (!opened.ok) return note('cannot-open', peer.device, opened.reason);
    if (!looksLikePacket(appId, opened.payload)) {
      if (passed.length < lim.maxPassedPerStep) passed.push({ from: peer.device, file });
      return;
    }
    const packet = readPacket(appId, opened.payload, parseOptions, postCfg?.limits);
    if (!packet) return note('bad-packet', peer.device);
    if (packet.kind === 'post') return takePost(peer, packet.round, transfer, packet.text);
    const ctx = ctxs.get(packet.set);
    if (!ctx) return note('unknown-set', peer.device);
    if (!may(ctx, peer)) return note('set-not-allowed', peer.device);
    const m = packet.message;
    if (m.t === 'stand') return answerAsk(ctx, peer, packet.round, m);
    if (m.t === 'changes') {
      return takeAnswer(ctx, peer, packet.round, transfer, packet.raw, m.last);
    }
    if (m.t === 'overflow') return note('stand-too-large', peer.device);
    return note('ignored-message', peer.device, m.t);
  }

  async function takeAnswer(
    ctx: SetCtx,
    peer: Peer,
    roundId: string,
    transfer: string,
    raw: unknown,
    last: boolean,
  ): Promise<void> {
    const ps = state.peers.get(peer.device)?.sets.get(ctx.name);
    const round = ps?.round;
    if (!ps || !round || round.id !== roundId) return note('stale-round', peer.device);
    if (round.seen.has(transfer)) return note('duplicate-piece', peer.device);
    round.seen.add(transfer);
    round.pieces += 1;
    if (round.pieces > lim.maxPiecesPerRound) {
      ps.round = undefined;
      ps.endedMs = now;
      return note('round-overflow', peer.device);
    }
    const step = await receiveJudged(round.session, ctx.replica, raw, ctx.judged, ctx.options);
    if (step.session.refusal) {
      ps.round = undefined;
      ps.endedMs = now;
      return note(
        'round-refused',
        peer.device,
        `${step.session.refusal}:${step.session.refusalReason ?? ''}`,
      );
    }
    round.session = step.session;
    if (step.replica !== ctx.replica) {
      ctx.replica = step.replica;
    }
    if (!last) return;
    applied += step.session.taken;
    ps.round = undefined;
    ps.endedMs = now;
    ps.again =
      step.session.taken > 0 && (step.session.peerMore === true || step.session.truncated === true);
    await refresh();
  }

  async function answerAsk(
    ctx: SetCtx,
    peer: Peer,
    roundId: string,
    ask: Extract<SyncMessage, { t: 'stand' }>,
  ): Promise<void> {
    const ps = setPeer(state, peer.device, ctx.name);
    if (ps.answered.includes(roundId)) return note('duplicate-ask', peer.device);
    ps.asks = ps.asks.filter((t) => now - t < lim.askWindowMs);
    if (ps.asks.length >= lim.maxAsksPerWindow) return note('ask-rate-limited', peer.device);
    ps.asks.push(now);
    ps.answered.push(roundId);
    if (ps.answered.length > lim.rememberedAsks) ps.answered.shift();
    if (isAhead(ask.vector, ctx.replica.vector)) ps.ahead = true;

    let changes = lim.answerChanges;
    let chars = lim.answerChars;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const answer = onSyncMessage(startSession(ctx.replica).session, ctx.replica, ask, {
        ...ctx.options,
        limits: roundLimits(changes, chars),
      });
      if (answer.session.refusal) {
        return note(
          answer.session.refusal === 'diverged' ? 'diverged' : 'round-refused',
          peer.device,
          answer.session.subjectDevice ?? answer.session.refusalReason,
        );
      }
      const packets = answer.send.map((msg) => writePacket(appId, roundId, ctx.name, msg));
      const estimate = packets.reduce(
        (n, p) => n + estimateFrames(p.length, FRAMING_LIMITS.partBytes),
        0,
      );
      if (estimate <= lim.maxFramesPerAnswer) {
        return void (await sealAndQueue(peer, packets, lim.maxFramesPerAnswer));
      }
      if (changes <= 1 && chars <= 1) break;
      changes = Math.max(1, changes >> 1);
      chars = Math.max(1, chars >> 1);
    }
    note('answer-too-large', peer.device);
  }

  // ── envelope traffic ────────────────────────────────────────────────────────────────────────

  /** The bounded view the exchange works on: the newest envelopes only (frames of one answer are bounded). */
  function viewOf(box: Mailbox): Mailbox {
    return keepNewest(box, lim.maxExchangeEnvelopes);
  }

  /** What a step of the exchange brought into the view goes into the full mailbox (quota counted once). */
  function intake(added: readonly Envelope[], from: string): void {
    if (added.length === 0) return;
    const out = addEnvelopes(appId, mailbox, added, today, { from, limits: postLim });
    if (out.ok) {
      mailbox = out.mailbox;
      received.push(...out.added);
    }
  }

  async function takePost(
    peer: Peer,
    roundId: string,
    transfer: string,
    text: string,
  ): Promise<void> {
    if (!postCfg) return note('post-disabled', peer.device);
    if (!mayCarry(peer)) return note('set-not-allowed', peer.device, 'post');
    const pp = peerState(state, peer.device).post;
    const message = readPostMessage(appId, text, postLim);
    if (!message) return note('bad-packet', peer.device);
    let round = pp.round;
    let reply: string[] = [];
    if (!round || round.id !== roundId) {
      // only a `days` message opens an exchange; two that open at once: the smaller id wins
      if (message.t !== 'days') return note('stale-round', peer.device);
      if (pp.answered.includes(roundId)) return note('duplicate-ask', peer.device);
      if (round && roundId > round.id) return note('stale-round', peer.device);
      pp.asks = pp.asks.filter((t) => now - t < lim.askWindowMs);
      if (pp.asks.length >= lim.maxAsksPerWindow) return note('ask-rate-limited', peer.device);
      pp.asks.push(now);
      pp.answered.push(roundId);
      if (pp.answered.length > lim.rememberedAsks) pp.answered.shift();
      const begun = postStart({ appId, mailbox: viewOf(mailbox), today, limits: postLim });
      if (!begun.ok) return note('post-refused', peer.device, begun.reason);
      round = {
        id: roundId,
        startedMs: now,
        session: begun.session,
        view: begun.mailbox,
        pieces: 0,
        seen: new Set(),
      };
      pp.round = round;
      reply = [...begun.send];
    }
    if (round.seen.has(transfer)) return note('duplicate-piece', peer.device);
    round.seen.add(transfer);
    round.pieces += 1;
    if (round.pieces > lim.maxPiecesPerRound) {
      pp.round = undefined;
      pp.endedMs = now;
      return note('round-overflow', peer.device, 'post');
    }
    const step = postStep({
      appId,
      session: round.session,
      mailbox: round.view,
      message: text,
      today,
      from: peer.device,
      limits: postLim,
    });
    if (!step.ok) {
      pp.round = undefined;
      pp.endedMs = now;
      return note('post-refused', peer.device, step.reason);
    }
    round.session = step.session;
    round.view = step.mailbox;
    intake(step.added, peer.device);
    reply.push(...step.send);
    if (postDone(step.session)) {
      pp.round = undefined;
      pp.endedMs = now;
    }
    if (reply.length > 0) {
      const packets = reply.map((t) => writePostPacket(appId, roundId, t));
      if (!(await sealAndQueue(peer, packets, lim.maxFramesPerAnswer))) {
        pp.round = undefined;
        pp.endedMs = now;
      }
    }
  }

  /** Receipts of the app's data drop what they cover (strict reader; the app says who may acknowledge). */
  function takeReceipts(): void {
    if (!postCfg?.receipts || mailbox.items.length === 0) return;
    let raw: unknown;
    try {
      raw = postCfg.receipts(new Map([...ctxs].map(([name, ctx]) => [name, ctx.replica])));
    } catch {
      return;
    }
    const receipts = readReceipts(raw, postLim);
    if (!receipts) return;
    const out = applyReceipts(
      appId,
      mailbox,
      receipts,
      (by) => {
        try {
          return postCfg.mayAcknowledge?.(by, trust) === true;
        } catch {
          return false;
        }
      },
      today,
      postLim,
    );
    if (out.ok) {
      mailbox = out.mailbox;
      acknowledged += out.dropped;
    }
  }

  async function askPost(): Promise<void> {
    if (!postCfg) return;
    const presentIds = new Set(present);
    let check: string | undefined;
    for (const peer of roster.peers.values()) {
      if (!presentIds.has(peer.relayId) || !mayCarry(peer)) continue;
      const pp = peerState(state, peer.device).post;
      if (pp.round) continue;
      check ??= mailboxCheck(appId, mailbox);
      const due =
        pp.askedCheck !== check || pp.endedMs === undefined || now - pp.endedMs >= lim.idleRoundMs;
      if (!due) continue;
      const begun = postStart({ appId, mailbox: viewOf(mailbox), today, limits: postLim });
      if (!begun.ok) continue;
      const id = Array.from(cfg.random(8), (b) => b.toString(16).padStart(2, '0')).join('');
      const packets = begun.send.map((t) => writePostPacket(appId, id, t));
      if (!(await sealAndQueue(peer, packets, lim.maxFramesPerAnswer))) continue;
      pp.round = {
        id,
        startedMs: now,
        session: begun.session,
        view: begun.mailbox,
        pieces: 0,
        seen: new Set(),
      };
      pp.askedCheck = check;
    }
  }

  // ── outbound ────────────────────────────────────────────────────────────────────────────────

  /** Seals each packet for the peer, frames it and queues it, all or nothing. */
  async function sealAndQueue(
    peer: Peer,
    packets: readonly Uint8Array[],
    maxFrames: number,
  ): Promise<boolean> {
    const queued: Queued[] = [];
    let total = 0;
    for (const payload of packets) {
      const sealed = await sealFile({
        appId,
        own: { device: own.device, agreement: own.keys.agreement },
        to: { device: peer.device, dh: peer.dh },
        payload,
        random: cfg.random(12),
      });
      if (!sealed.ok) {
        note('seal-failed', peer.device, sealed.reason);
        return false;
      }
      const frames = frameOf(appId, sealed.file, cfg.random);
      if (!frames) {
        note('seal-failed', peer.device, 'framing');
        return false;
      }
      total += frames.length;
      queued.push({ frames, queuedMs: now, next: 0 });
    }
    if (total > maxFrames) {
      note('answer-too-large', peer.device);
      return false;
    }
    if (queuedFrames(state, peer.device) + total > lim.maxQueuedFrames) {
      note('outbox-full', peer.device);
      return false;
    }
    state.outbox.set(peer.device, [...(state.outbox.get(peer.device) ?? []), ...queued]);
    return true;
  }

  async function askPeers(): Promise<void> {
    const presentIds = new Set(present);
    for (const ctx of ctxs.values()) {
      const here = vectorKey(ctx.replica.vector);
      for (const peer of roster.peers.values()) {
        if (!presentIds.has(peer.relayId) || !may(ctx, peer)) continue;
        const ps: SetPeerState = setPeer(state, peer.device, ctx.name);
        if (ps.round) continue;
        const due =
          ps.ahead ||
          ps.again ||
          ps.askedVector !== here ||
          ps.endedMs === undefined ||
          now - ps.endedMs >= lim.idleRoundMs;
        if (!due) continue;
        const started = startSession(ctx.replica);
        const id = Array.from(cfg.random(8), (b) => b.toString(16).padStart(2, '0')).join('');
        const first = started.send[0];
        if (!first) continue;
        if (
          !(await sealAndQueue(
            peer,
            [writePacket(appId, id, ctx.name, first)],
            lim.maxFramesPerAnswer,
          ))
        ) {
          continue;
        }
        const round: Round = {
          id,
          startedMs: now,
          session: started.session,
          pieces: 0,
          seen: new Set(),
        };
        ps.round = round;
        ps.ahead = false;
        ps.again = false;
        ps.askedVector = here;
      }
    }
  }

  async function drain(): Promise<void> {
    for (let call = 0; call < lim.maxDropsPerStep; call += 1) {
      const batch: { device: string; content: Uint8Array; q: Queued }[] = [];
      for (const [device, list] of state.outbox) {
        const peer = roster.peers.get(device);
        if (!peer) continue;
        const q = list[0];
        if (!q) continue;
        const content = q.frames[q.next];
        if (content) batch.push({ device, content, q });
        if (batch.length >= 50) break;
      }
      if (batch.length === 0) return;
      const result: RelayResult<DropValue> = await cfg.relay.drop(
        batch.map((b) => ({
          device: roster.peers.get(b.device)?.relayId ?? '',
          content: b.content,
        })),
      );
      if (!result.ok) {
        relayFailure = { kind: result.kind, class: result.class };
        for (const b of batch) discard(b.device, 'drop-failed', result.kind);
        if (result.class === 'fatal' || result.class === 'reenrol') return;
        continue;
      }
      for (const [i, b] of batch.entries()) {
        const r = result.value.results[i];
        if (!r || !r.ok) {
          discard(b.device, 'drop-refused', r && !r.ok ? r.kind : 'missing');
          continue;
        }
        framesSent += 1;
        state.busyUntil = now + lim.busyHoldMs;
        b.q.next += 1;
        if (b.q.next >= b.q.frames.length) {
          messagesSent += 1;
          const list = state.outbox.get(b.device) ?? [];
          list.shift();
          if (list.length === 0) state.outbox.delete(b.device);
        }
      }
    }
  }

  /** A frame the relay did not take: the rest of that message is useless (a gap), so it goes. */
  function discard(device: string, code: SyncCode, detail: string): void {
    note(code, device, detail);
    const list = state.outbox.get(device) ?? [];
    list.shift();
    if (list.length === 0) state.outbox.delete(device);
  }
}

export type { PeerState, Roster, RelayFailure };

/** Peers of this replica, as a step would see them (diagnostics and UI: who gets content). */
export async function currentRoster(
  cfg: SyncConfig,
  replica: Replica,
  ownRelayId: string,
): Promise<{ readonly trust: Trust; readonly roster: Roster }> {
  const direct = typeof cfg.direct === 'function' ? cfg.direct() : cfg.direct;
  const trust = await computeTrust(replica, direct, cfg.trust);
  return { trust, roster: buildRoster(trust, cfg.own.device, ownRelayId) };
}

/**
 * Queues a file that is already sealed (for example a key grant) for a trusted device. Nothing is
 * checked against the roster here: the step does that when it drops (a device that is no peer by
 * then is dropped with `recipient-not-trusted`), so a removal between queueing and sending holds.
 */
export function queueFile(
  cfg: Pick<SyncConfig, 'trust' | 'random' | 'limits'>,
  state: SyncState,
  device: string,
  file: Uint8Array,
  nowMs: number,
): { readonly ok: true } | { readonly ok: false; readonly reason: 'bad-input' | 'outbox-full' } {
  const lim = resolveSyncLimits(cfg.limits);
  const frames =
    file instanceof Uint8Array ? frameOf(cfg.trust.appId, file, cfg.random) : undefined;
  if (!frames || !Number.isFinite(nowMs) || typeof device !== 'string') {
    return { ok: false, reason: 'bad-input' };
  }
  if (queuedFrames(state, device) + frames.length > lim.maxQueuedFrames) {
    return { ok: false, reason: 'outbox-full' };
  }
  state.outbox.set(device, [
    ...(state.outbox.get(device) ?? []),
    { frames, queuedMs: nowMs, next: 0 },
  ]);
  return { ok: true };
}
