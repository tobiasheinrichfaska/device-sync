// The handshake of a direct connection as a pure state machine: no clock, no network, no randomness.
// Time comes in with each event (`now`, milliseconds on a clock that does not jump back), the deadlines are
// parameters. The caller makes an offer text and takes an answer text; the callee takes an offer text and
// makes an answer text. A text that does not fit (wrong role, another session) is refused and changes nothing.
import type { DirectText } from './direct-text.ts';

export type DirectPhase =
  | 'idle'
  | 'awaiting-offer'
  | 'gathering'
  | 'awaiting-answer'
  | 'connecting'
  | 'open'
  | 'closed'
  | 'failed';

export type DirectFailure =
  | 'offer-timeout'
  | 'gather-timeout'
  | 'answer-timeout'
  | 'connect-timeout'
  | 'ice-failed'
  | 'channel-closed'
  | 'setup-failed';

export interface HandshakeConfig {
  /** The callee waits this long for the offer text. */
  readonly offerMs: number;
  /** Making a description (collecting candidates) may take this long in all. */
  readonly setupMs: number;
  /** The caller waits this long for the answer text. */
  readonly answerMs: number;
  /** From the exchanged texts to an open channel. */
  readonly connectMs: number;
}

export const HANDSHAKE_DEFAULTS: HandshakeConfig = {
  offerMs: 300_000,
  setupMs: 15_000,
  answerMs: 120_000,
  connectMs: 15_000,
};

/** The configuration problem as a code, or undefined. */
export function handshakeConfigProblem(c: HandshakeConfig): 'bad-config' | undefined {
  for (const k of ['offerMs', 'setupMs', 'answerMs', 'connectMs'] as const) {
    const v = c?.[k];
    if (!Number.isInteger(v) || v < 1 || v > 3_600_000) return 'bad-config';
  }
  return undefined;
}

export interface DirectState {
  readonly role: 'caller' | 'callee';
  readonly phase: DirectPhase;
  readonly session: string | undefined;
  /** When the current phase fails if nothing happened (absolute, on the caller's clock). */
  readonly deadline: number | undefined;
  readonly failure: DirectFailure | undefined;
}

export type DirectEvent =
  | { readonly t: 'begin'; readonly now: number; readonly session?: string }
  | { readonly t: 'remote-text'; readonly now: number; readonly text: DirectText }
  | { readonly t: 'local-text'; readonly now: number }
  | { readonly t: 'setup-failed' }
  | { readonly t: 'channel-open'; readonly now: number }
  | { readonly t: 'ice-failed' }
  | { readonly t: 'channel-closed' }
  | { readonly t: 'tick'; readonly now: number }
  | { readonly t: 'cancel' };

export type DirectAction = 'create-offer' | 'apply-offer' | 'apply-answer' | 'close';

export type DirectRefusal = 'unexpected' | 'wrong-role' | 'wrong-session' | 'bad-session';

export interface DirectStepResult {
  readonly state: DirectState;
  readonly actions: readonly DirectAction[];
  /** Set when the event was refused; the state is then the old one. */
  readonly refusal?: DirectRefusal;
}

export function initialState(role: 'caller' | 'callee'): DirectState {
  return { role, phase: 'idle', session: undefined, deadline: undefined, failure: undefined };
}

const TERMINAL: ReadonlySet<DirectPhase> = new Set(['closed', 'failed']);
const SESSION = /^[0-9a-f]{16}$/;

const TIMEOUT_OF: Partial<Record<DirectPhase, DirectFailure>> = {
  'awaiting-offer': 'offer-timeout',
  gathering: 'gather-timeout',
  'awaiting-answer': 'answer-timeout',
  connecting: 'connect-timeout',
};

const FAIL_ACTIONS: readonly DirectAction[] = ['close'];

const failed = (s: DirectState, failure: DirectFailure): DirectStepResult => ({
  state: { ...s, phase: 'failed', deadline: undefined, failure },
  actions: FAIL_ACTIONS,
});

/** One step. Terminal states ignore everything (so a late event after a failure is harmless). */
export function directStep(s: DirectState, e: DirectEvent, c: HandshakeConfig): DirectStepResult {
  if (TERMINAL.has(s.phase)) return { state: s, actions: [] };
  const refuse = (refusal: DirectRefusal): DirectStepResult => ({ state: s, actions: [], refusal });
  const go = (
    phase: DirectPhase,
    now: number,
    ms: number | undefined,
    extra = {},
  ): DirectState => ({
    ...s,
    phase,
    deadline: ms === undefined ? undefined : now + ms,
    ...extra,
  });
  switch (e.t) {
    case 'cancel':
      return {
        state: { ...s, phase: 'closed', deadline: undefined },
        actions: FAIL_ACTIONS,
      };
    case 'tick': {
      if (s.deadline !== undefined && e.now >= s.deadline) {
        const f = TIMEOUT_OF[s.phase];
        if (f) return failed(s, f);
      }
      return { state: s, actions: [] };
    }
    case 'ice-failed':
      return s.phase === 'connecting' || s.phase === 'open'
        ? failed(s, 'ice-failed')
        : { state: s, actions: [], refusal: 'unexpected' };
    case 'setup-failed':
      return s.phase === 'gathering' ? failed(s, 'setup-failed') : refuse('unexpected');
    case 'channel-closed':
      return s.phase === 'open'
        ? { state: { ...s, phase: 'closed', deadline: undefined }, actions: FAIL_ACTIONS }
        : s.phase === 'idle'
          ? refuse('unexpected')
          : failed(s, 'channel-closed');
    case 'channel-open':
      return s.phase === 'connecting'
        ? { state: go('open', e.now, undefined), actions: [] }
        : refuse('unexpected');
    case 'begin':
      if (s.phase !== 'idle') return refuse('unexpected');
      if (s.role === 'callee')
        return { state: go('awaiting-offer', e.now, c.offerMs), actions: [] };
      if (typeof e.session !== 'string' || !SESSION.test(e.session)) return refuse('bad-session');
      return {
        state: go('gathering', e.now, c.setupMs, { session: e.session }),
        actions: ['create-offer'],
      };
    case 'remote-text': {
      if (s.role === 'callee' && s.phase === 'awaiting-offer') {
        if (e.text.role !== 'offer') return refuse('wrong-role');
        return {
          state: go('gathering', e.now, c.setupMs, { session: e.text.session }),
          actions: ['apply-offer'],
        };
      }
      if (s.role === 'caller' && s.phase === 'awaiting-answer') {
        if (e.text.role !== 'answer') return refuse('wrong-role');
        if (e.text.session !== s.session) return refuse('wrong-session');
        return { state: go('connecting', e.now, c.connectMs), actions: ['apply-answer'] };
      }
      return refuse('unexpected');
    }
    case 'local-text':
      if (s.phase !== 'gathering') return refuse('unexpected');
      return s.role === 'caller'
        ? { state: go('awaiting-answer', e.now, c.answerMs), actions: [] }
        : { state: go('connecting', e.now, c.connectMs), actions: [] };
  }
}
