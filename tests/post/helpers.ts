import {
  EMPTY_MAILBOX,
  base64url,
  buildEnvelope,
  postDone,
  postStart,
  postStep,
  readPostMessage,
  type Envelope,
  type Mailbox,
  type PostLimits,
  type PostSession,
} from '../../src/index.ts';

export const APP = 'demo';
export const TODAY = '2026-11-10';
export const A = 'device-a';
export const B = 'device-b';

const EPH = base64url(Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 4 : (i * 7) % 256)));
let counter = 0;

/**
 * A well-formed envelope that holds nothing sealed (no crypto): unique content, the id computed as
 * for a real one. `extra` makes the content that many bytes longer.
 */
export function fake(day = TODAY, extra = 0, appId = APP): Envelope {
  counter += 1;
  const ct = new Uint8Array(24 + extra).fill(1);
  new DataView(ct.buffer).setUint32(0, counter);
  return buildEnvelope(appId, {
    day,
    eph: EPH,
    iv: 'A'.repeat(16),
    ct: base64url(ct),
    k: Array.from({ length: 8 }, () => 'C'.repeat(64)),
  });
}

/** A look-alike object (not made by this package): it is read again when it is added. */
export const plain = (e: Envelope): Envelope => ({ id: e.id, day: e.day, text: e.text });

export const mailboxOf = (...items: Envelope[]): Mailbox => ({ items });
export const ids = (m: Mailbox): string[] => m.items.map((e) => e.id).sort();
export { EMPTY_MAILBOX };

/** Runs an exchange between two devices over message texts until both are done. */
export function meet(
  a: Mailbox,
  b: Mailbox,
  options: { limits?: Partial<PostLimits>; today?: string } = {},
) {
  const today = options.today ?? TODAY;
  const common = { today, ...(options.limits ? { limits: options.limits } : {}) };
  const sa = postStart({ appId: APP, mailbox: a, ...common });
  const sb = postStart({ appId: APP, mailbox: b, ...common });
  if (!sa.ok || !sb.ok) throw new Error('postStart refused');
  let stateA: { session: PostSession; mailbox: Mailbox } = {
    session: sa.session,
    mailbox: sa.mailbox,
  };
  let stateB: { session: PostSession; mailbox: Mailbox } = {
    session: sb.session,
    mailbox: sb.mailbox,
  };
  const toA = [...sb.send];
  const toB = [...sa.send];
  const travelled = { toA: 0, toB: 0, ids: 0, messages: 0 };
  const count = (text: string, side: 'toA' | 'toB'): void => {
    const m = readPostMessage(APP, text, options.limits);
    travelled.messages += 1;
    if (m?.t === 'envelopes') travelled[side] += m.envelopes.length;
    if (m?.t === 'ids') travelled.ids += m.ids.length;
  };
  const step = (
    state: typeof stateA,
    text: string,
    from: string,
  ): { session: PostSession; mailbox: Mailbox; send: readonly string[] } => {
    const r = postStep({
      appId: APP,
      ...state,
      message: text,
      from,
      ...common,
    });
    if (!r.ok) throw new Error(`postStep refused: ${r.reason}`);
    return r;
  };
  for (let i = 0; i < 2000 && !(postDone(stateA.session) && postDone(stateB.session)); i += 1) {
    const ma = toA.shift();
    if (ma !== undefined) {
      count(ma, 'toA');
      const r = step(stateA, ma, B);
      stateA = r;
      toB.push(...r.send);
    }
    const mb = toB.shift();
    if (mb !== undefined) {
      count(mb, 'toB');
      const r = step(stateB, mb, A);
      stateB = r;
      toA.push(...r.send);
    }
  }
  return {
    a: stateA.mailbox,
    b: stateB.mailbox,
    sessionA: stateA.session,
    sessionB: stateB.session,
    done: postDone(stateA.session) && postDone(stateB.session),
    travelled,
  };
}
