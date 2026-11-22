import { postStart } from '../../src/index.ts';
import { APP, TODAY, fake, mailboxOf } from './helpers.ts';

/** The first message of an exchange (a `days` message) of a small mailbox. */
export function startMessage(): string {
  const r = postStart({ appId: APP, mailbox: mailboxOf(fake(), fake('2026-11-09')), today: TODAY });
  if (!r.ok) throw new Error(r.reason);
  return r.send[0] as string;
}
