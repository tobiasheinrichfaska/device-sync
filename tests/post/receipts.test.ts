// The record of receipts (`post/receipts.ts`): per day, ids sorted, days out of the window cleared;
// the author of a receipt is whoever signed the field. The earlier app's receipt cases, re-expressed.
import { describe, expect, it } from 'vitest';
import { emptyReplica, merge, write, type Replica } from '../../src/log/index.ts';
import {
  EMPTY_MAILBOX,
  RECEIPT_COLLECTION,
  addEnvelopes,
  applyReceipts,
  inWindow,
  readReceipts,
  receiptsOf,
  writeReceiptRecord,
} from '../../src/post/index.ts';
import { fake as fakeEnvelope } from './helpers.ts';

const TODAY = '2026-11-20';
const id = (n: number): string =>
  Buffer.from(Uint8Array.from({ length: 16 }, () => n)).toString('base64url');
const rec = (r: Replica, taken: { id: string; day: string }[], today = TODAY): Replica => {
  const out = writeReceiptRecord(r, taken, today, { time: 1 });
  if (!out.ok) throw new Error(out.reason);
  return out.replica;
};

describe('the receipt record', () => {
  it('writes one field per day with the sorted ids; writing the same again writes nothing', () => {
    let r = emptyReplica('office');
    r = rec(r, [
      { id: id(3), day: '2026-11-20' },
      { id: id(1), day: '2026-11-20' },
      { id: id(2), day: '2026-11-19' },
    ]);
    const fields = r.collections[RECEIPT_COLLECTION]?.office?.fields;
    expect(fields?.['2026-11-20']?.value).toEqual([id(1), id(3)]);
    expect(fields?.['2026-11-19']?.value).toEqual([id(2)]);
    const again = writeReceiptRecord(r, [{ id: id(1), day: '2026-11-20' }], TODAY, {});
    expect(again).toMatchObject({ ok: true, written: false });
    expect(r.log.length).toBe(1);
    expect(again.ok && again.replica).toBe(r);
  });

  it('a receipt grows: ids of earlier writes of the same day stay', () => {
    let r = rec(emptyReplica('office'), [{ id: id(1), day: TODAY }]);
    r = rec(r, [{ id: id(2), day: TODAY }]);
    expect(r.collections[RECEIPT_COLLECTION]?.office?.fields[TODAY]?.value).toEqual([id(1), id(2)]);
  });

  it('days that left the window are cleared, others are not written', () => {
    let r = rec(emptyReplica('office'), [{ id: id(1), day: '2026-11-01' }], '2026-11-02');
    expect(r.collections[RECEIPT_COLLECTION]?.office?.fields['2026-11-01']?.value).toEqual([id(1)]);
    // 30 days later the day is out of the window: cleared; an envelope of that day is not noted
    r = rec(
      r,
      [
        { id: id(2), day: '2026-11-01' },
        { id: id(3), day: '2026-12-02' },
      ],
      '2026-12-02',
    );
    const f = r.collections[RECEIPT_COLLECTION]?.office?.fields;
    expect(f?.['2026-11-01']?.value).toBeNull();
    expect(f?.['2026-12-02']?.value).toEqual([id(3)]);
    expect(inWindow('2026-11-01', '2026-12-02')).toBe(false);
    expect(inWindow('2026-11-04', '2026-12-02')).toBe(true);
    expect(inWindow('2026-12-04', '2026-12-02')).toBe(true);
    expect(inWindow('2026-12-05', '2026-12-02')).toBe(false);
    expect(inWindow('nonsense', '2026-12-02')).toBe(false);
  });

  it('keeps junk out: ids that are not ids, days that are not days', () => {
    const r = rec(emptyReplica('office'), [
      { id: 'x', day: TODAY },
      { id: id(1), day: 'not-a-day' },
      { id: id(2), day: TODAY },
    ]);
    expect(r.collections[RECEIPT_COLLECTION]?.office?.fields[TODAY]?.value).toEqual([id(2)]);
    expect(writeReceiptRecord(emptyReplica('o'), [], 'bad', {})).toMatchObject({ ok: false });
  });

  it('`receiptsOf` names the device that wrote the field, not a name in the data, and drops what is no receipt', () => {
    let office = rec(emptyReplica('office'), [{ id: id(1), day: TODAY }]);
    // another device writes a field into the office's record (a forged claim) and a non-day field
    let other = merge(emptyReplica('other'), office.log).replica;
    const forged = write(other, RECEIPT_COLLECTION, 'office', {
      '2026-11-19': [id(9)],
      note: [id(8)],
      '2026-11-18': 'x',
    });
    if (!forged.ok) throw new Error(forged.reason);
    other = forged.replica;
    office = merge(office, other.log).replica;
    const receipts = receiptsOf(office);
    expect(receipts).toEqual([
      { by: 'office', ids: [id(1)] },
      { by: 'other', ids: [id(9)] },
    ]);
    // the strict reader takes exactly this shape
    expect(readReceipts(JSON.parse(JSON.stringify(receipts)))).toEqual(receipts);
  });

  it('is bounded and chunked; a finally deleted record counts for nothing', () => {
    let r = emptyReplica('office');
    const many = Array.from({ length: 650 }, (_, i) => ({
      id: Buffer.from(
        new Uint8Array(16).fill(0).map((_, k) => (k === 0 ? i & 255 : k === 1 ? i >> 8 : 7)),
      ).toString('base64url'),
      day: TODAY,
    }));
    r = rec(r, many);
    // one day holds at most what one field of the log may hold (200)
    expect(
      (r.collections[RECEIPT_COLLECTION]?.office?.fields[TODAY]?.value as string[]).length,
    ).toBe(200);
    const list = receiptsOf(r, { limits: { maxReceiptIds: 50, maxReceipts: 3 } });
    expect(list.length).toBe(3);
    expect(list.every((x) => x.ids.length <= 50)).toBe(true);
  });

  it('end to end: a carrier that holds the envelope drops it once an allowed device receipted it', () => {
    const e = fakeEnvelope(TODAY, 1);
    const box = addEnvelopes('demo', EMPTY_MAILBOX, [e], TODAY);
    if (!box.ok) throw new Error(box.reason);
    const r = rec(emptyReplica('office'), [{ id: e.id, day: e.day }]);
    const receipts = receiptsOf(r);
    const refused = applyReceipts('demo', box.mailbox, receipts, () => false, TODAY);
    expect(refused).toMatchObject({ ok: true, dropped: 0 });
    const dropped = applyReceipts('demo', box.mailbox, receipts, (by) => by === 'office', TODAY);
    expect(dropped).toMatchObject({ ok: true, dropped: 1 });
  });
});
