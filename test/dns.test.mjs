import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeName, parseMessage, encodeName, DnsFormatError, TYPES } from '../src/dns.mjs';
import { buildResponse, encodeRecord, aData, txtData, srvData } from '../src/receiver.mjs';

function message(records, header = {}) {
  const body = records.map(record => Buffer.isBuffer(record) ? record : encodeRecord(record));
  const head = Buffer.alloc(12);
  head.writeUInt16BE(header.id ?? 0, 0);
  head.writeUInt16BE(header.flags ?? 0x8400, 2);
  head.writeUInt16BE(header.qdcount ?? 0, 4);
  head.writeUInt16BE(header.ancount ?? body.length, 6);
  head.writeUInt16BE(header.nscount ?? 0, 8);
  head.writeUInt16BE(header.arcount ?? 0, 10);
  return Buffer.concat([head, ...body]);
}

test('名称压缩可以指向报文中更早的名称，一个包内的多段记录都保留区段', () => {
  const first = encodeRecord({ name: '_collect._tcp.local', type: TYPES.PTR, ttl: 60, data: encodeName('station._collect._tcp.local') });
  // PTR 的数据从 first 内的偏移 0 处 (service 名称) 用指针回指。
  const srvName = Buffer.concat([Buffer.from([7]), Buffer.from('station'), Buffer.from([0xc0, 12])]);
  const srv = Buffer.concat([srvName, Buffer.from([0x00, 0x21, 0x80, 0x01, 0, 0, 0, 60, 0, srvData(8080, 'gateway.local').length]), srvData(8080, 'gateway.local')]);
  const additional = encodeRecord({ name: 'gateway.local', type: TYPES.A, ttl: 60, data: aData('10.0.0.9') });
  const packet = message([first, srv, additional], { ancount: 2, arcount: 1 });
  const parsed = parseMessage(packet);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.records.map(record => record.section), ['answer', 'answer', 'additional']);
  assert.equal(parsed.records[0].data.target, 'station._collect._tcp.local');
  assert.equal(parsed.records[1].data.target, 'gateway.local');
  assert.equal(parsed.records[1].data.port, 8080);
  assert.equal(parsed.records[2].data.address, '10.0.0.9');
});

test('压缩指针不能形成循环或指向报文之外', () => {
  const loop = message([], { ancount: 1, flags: 0x8400 }).subarray(0, 12);
  const record = Buffer.concat([Buffer.from([0xc0, 12]), Buffer.alloc(10)]);
  const packet = Buffer.concat([loop, record]);
  const parsed = parseMessage(packet);
  assert.equal(parsed.records.length, 0);
  assert.equal(parsed.rejected[0].code, 'NAME_POINTER_FORWARD');

  const target = Buffer.concat([Buffer.from([0xc0, 0xff]), Buffer.alloc(10)]);
  const out = parseMessage(Buffer.concat([message([], { ancount: 1 }), target]));
  assert.equal(out.records.length, 0);
  assert.match(out.rejected[0].code, /NAME_POINTER_OUT_OF_BOUNDS|NAME_OUT_OF_BOUNDS/);
});

test('越过记录边界的标签与 RDATA 被拒绝，但同包其他记录仍可使用', () => {
  const good = encodeRecord({ name: 'gateway.local', type: TYPES.A, ttl: 30, data: aData('192.0.2.7') });
  // PTR 的 RDATA 声明了一个长度为 9 的标签，但 RDLENGTH 只有 4 字节。
  const overflowing = Buffer.concat([Buffer.from([0x09, 0x67, 0x61, 0x74])]);
  const bad = Buffer.concat([
    encodeName('_collect._tcp.local'),
    Buffer.from([0x00, 0x0c, 0x00, 0x01, 0, 0, 0, 30, 0, overflowing.length]),
    overflowing
  ]);
  const parsed = parseMessage(message([good, bad]));
  assert.equal(parsed.records.length, 1);
  assert.equal(parsed.records[0].data.address, '192.0.2.7');
  assert.equal(parsed.rejected.length, 1);
  assert.equal(parsed.rejected[0].code, 'NAME_LABEL_OUT_OF_BOUNDS');
});

test('损坏的报文头整包拒收，坏记录不中断后续记录', () => {
  assert.equal(parseMessage(Buffer.from([0, 1, 2])).ok, false);
  const good = encodeRecord({ name: 'gateway.local', type: TYPES.A, ttl: 30, data: aData('192.0.2.7') });
  const badTxt = encodeRecord({ name: 'station._collect._tcp.local', type: TYPES.TXT, ttl: 30, data: txtData(['ok']).subarray(0, 2) });
  const parsed = parseMessage(message([badTxt, good]));
  assert.equal(parsed.records.length, 1);
  assert.equal(parsed.rejected[0].code, 'TXT_STRING_OUT_OF_BOUNDS');
});

test('名称解码有明确的起点与边界，编码器拒绝超长标签', () => {
  assert.throws(() => decodeName(Buffer.from([0, 0, 0, 0x09, 1]), 3, { encodedEnd: 4 }), DnsFormatError);
  assert.throws(() => decodeName(Buffer.alloc(4), 5, { encodedEnd: 4 }), DnsFormatError);
  assert.throws(() => encodeName('a'.repeat(64) + '.local'), /标签过长/);
  assert.equal(encodeName('a.b').toString('hex'), '0161016200');
});
