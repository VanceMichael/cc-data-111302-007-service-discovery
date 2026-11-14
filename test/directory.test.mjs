import test from 'node:test';
import assert from 'node:assert/strict';
import { createDirectory } from '../src/directory.mjs';
import { manualClock } from '../src/clock.mjs';
import {
  packet, ptrRecord, srvRecord, txtRecord, aRecord, aaaaRecord,
  fullAnnouncement, SERVICE, INSTANCE, GATEWAY, ALTERNATE
} from './helpers/packets.mjs';
import { encodeName, TYPES } from '../src/dns.mjs';

function fixture(options = {}) {
  const clock = manualClock(options.start ?? 0);
  const directory = createDirectory({ clock });
  return { clock, directory, ingest: (bytes, iface = 'if-a', at = clock.now()) => directory.ingest({ packet: bytes, interfaceId: iface, interfaceName: iface, capturedAt: at }) };
}

function instances(snapshot) {
  return snapshot.services.flatMap(service => service.instances);
}

function instanceByName(snapshot, name = 'station') {
  return instances(snapshot).find(instance => instance.instanceName === name);
}

test('PTR、SRV、TXT、A、AAAA 按各自 TTL 过期；地址过期不删除服务实例', () => {
  const { directory, clock, ingest } = fixture();
  ingest(fullAnnouncement({ ttl: 120 }));
  assert.equal(instanceByName(directory.snapshot()).state, 'ready');

  // 地址记录先于 SRV 过期：实例仍在，但端点消失并说明缺什么。
  ingest(packet([aRecord({ ttl: 20 }), aaaaRecord({ ttl: 20 })]), 'if-a');
  clock.advance(21_000);
  let snapshot = directory.snapshot();
  let station = instanceByName(snapshot);
  assert.equal(station.state, 'incomplete');
  assert.equal(station.endpoints.length, 0);
  assert.deepEqual(station.missing.map(entry => entry.dependency), ['address']);
  assert.equal(snapshot.services[0].serviceType, SERVICE);

  // 地址迟到后补回，不需要重新收到 PTR。
  ingest(packet([aRecord({ address: '127.0.0.9', ttl: 500 })]), 'if-a');
  snapshot = directory.snapshot();
  station = instanceByName(snapshot);
  assert.equal(station.state, 'ready');
  assert.equal(station.endpoints[0].address, '127.0.0.9');

  // SRV 过期不会让 PTR 消失。
  ingest(packet([ptrRecord(INSTANCE, 300)]), 'if-a');
  clock.advance(100_000);
  snapshot = directory.snapshot();
  station = snapshot.services.flatMap(entry => entry.instances).find(entry => entry.instanceName === 'station');
  assert.equal(station.advertised, true);
  assert.equal(station.state, 'incomplete');
  assert.deepEqual(station.missing.map(entry => entry.dependency), ['srv', 'txt']);
});

test('依赖未到齐时列出缺少项，迟到记录可补齐同一实例', () => {
  const { directory, ingest } = fixture();
  ingest(packet([ptrRecord()]));
  let station = instanceByName(directory.snapshot());
  assert.equal(station.state, 'incomplete');
  assert.deepEqual(station.missing.map(entry => entry.dependency), ['srv', 'txt']);

  // SRV/TXT 先于 PTR 到达时也会归并到同一实例身份。
  const second = fixture();
  second.ingest(packet([srvRecord(), txtRecord()]));
  second.ingest(packet([ptrRecord()]));
  const snapshot = second.directory.snapshot();
  assert.equal(instances(snapshot).length, 1);
  assert.equal(instanceByName(snapshot).state, 'incomplete');
  second.ingest(packet([aRecord()]));
  assert.equal(instanceByName(second.directory.snapshot()).state, 'ready');
});

test('TTL 为零的 PTR 告别撤回实例，但地址缓存与主机记录保留', () => {
  const { directory, clock, ingest } = fixture();
  ingest(fullAnnouncement({ ttl: 300 }));
  clock.advance(5_000);
  ingest(packet([ptrRecord(INSTANCE, 0)]));
  const snapshot = directory.snapshot();
  assert.equal(instances(snapshot).length, 0, '默认目录不再显示已撤回的实例');
  assert.equal(snapshot.hosts.length, 1, '地址不会随 PTR 告别一起消失');
  const all = directory.snapshot({ includeWithdrawn: true });
  const withdrawn = instanceByName(all);
  assert.equal(withdrawn.state, 'withdrawn');
  assert.equal(withdrawn.withdrawReason, 'goodbye');
  assert.ok(withdrawn.endpoints.every(endpoint => endpoint.connectable === false));
  const ghost = instanceByName(directory.snapshot({ includeWithdrawn: true }));
  assert.ok(!ghost.endpoints.some(endpoint => endpoint.connectable));
});

test('TTL 为零的 A 记录只移除该地址，不撤回服务实例', () => {
  const { directory, ingest } = fixture();
  ingest(fullAnnouncement({ ttl: 300 }));
  ingest(packet([aRecord({ ttl: 0 })]));
  const snapshot = directory.snapshot();
  const station = instanceByName(snapshot);
  assert.equal(station.advertised, true);
  assert.deepEqual(station.target.addresses.map(entry => entry.family), ['AAAA']);
  assert.ok(station.endpoints.every(endpoint => endpoint.family === 'AAAA'));
});

test('同名实例出现在两个接口时保持独立，端点不跨接口拼接', () => {
  const { directory, ingest } = fixture();
  ingest(packet([ptrRecord(), srvRecord({ target: GATEWAY })]), 'if-a');
  ingest(packet([aRecord({ name: GATEWAY, address: '10.0.0.5' })]), 'if-b');
  ingest(packet([ptrRecord(), srvRecord({ target: GATEWAY })]), 'if-b');
  ingest(packet([aRecord({ name: GATEWAY, address: '10.0.1.5' })]), 'if-b');

  const snapshot = directory.snapshot();
  const station = instances(snapshot).filter(instance => instance.instanceName === 'station');
  assert.equal(station.length, 2);
  assert.deepEqual(station.map(instance => instance.interface.id).sort(), ['if-a', 'if-b']);
  const ifA = station.find(instance => instance.interface.id === 'if-a');
  assert.equal(ifA.endpoints.length, 0, 'if-a 上没有任何地址证据');
  assert.ok(ifA.missing.some(entry => entry.dependency === 'address'));
  const ifB = station.find(instance => instance.interface.id === 'if-b');
  assert.deepEqual(ifB.endpoints.map(endpoint => endpoint.address), ['10.0.1.5']);
  assert.equal(snapshot.duplicates.length, 1);
  assert.equal(snapshot.duplicates[0].interfaces.length, 2);
});

test('设备改目标主机后，旧目标地址不再出现在可连接端点', () => {
  const { directory, ingest } = fixture();
  ingest(fullAnnouncement({ target: GATEWAY, address: '10.0.0.7', ttl: 300 }));
  ingest(packet([srvRecord({ target: ALTERNATE }), aRecord({ name: ALTERNATE, address: '10.0.0.8', ttl: 300 })]));

  const snapshot = directory.snapshot();
  const station = instanceByName(snapshot);
  assert.equal(station.target.host, ALTERNATE);
  assert.deepEqual(station.endpoints.map(endpoint => endpoint.address), ['10.0.0.8']);
  const change = snapshot.recentChanges.filter(event => event.type === 'target-changed').at(-1);
  assert.equal(change.detail.previous.target, GATEWAY);
  assert.equal(change.detail.next.target, ALTERNATE);
  // 旧主机记录仍然缓存（它没有过期），但不再是该实例的目标。
  assert.ok(snapshot.hosts.some(host => host.name === GATEWAY));
});

test('缓存刷新只替换同一 RRset 中的旧记录，同包其他区段的记录照常处理', () => {
  const { directory, ingest } = fixture();
  ingest(packet([aRecord({ address: '10.0.0.1', ttl: 300 }), aaaaRecord({ ttl: 300 })]));
  ingest(packet([aRecord({ address: '10.0.0.2', ttl: 300, flush: true })]));
  let host = directory.snapshot().hosts.find(entry => entry.name === GATEWAY);
  assert.deepEqual(host.addresses.map(entry => entry.address).sort(), ['0:0:0:0:0:0:0:1', '10.0.0.2']);
  assert.ok(directory.changes().some(event => event.type === 'address-flushed'));

  ingest(packet([ptrRecord(), srvRecord({ target: GATEWAY }), aRecord({ address: '10.0.0.3', ttl: 300, flush: true })]));
  host = directory.snapshot().hosts.find(entry => entry.name === GATEWAY);
  assert.deepEqual(host.addresses.map(entry => entry.address).sort(), ['0:0:0:0:0:0:0:1', '10.0.0.3']);
});

test('目录保留接口范围、来源包和端点依据', () => {
  const { directory, ingest } = fixture();
  ingest(fullAnnouncement({ ttl: 60 }));
  const snapshot = directory.snapshot();
  const station = instanceByName(snapshot);
  assert.equal(station.interface.id, 'if-a');
  const endpoint = station.endpoints[0];
  assert.equal(endpoint.basis.interfaceId, 'if-a');
  assert.match(endpoint.basis.srv.packetId, /^pkt-\d+/);
  assert.match(endpoint.basis.srv.packetDigest, /^[0-9a-f]{64}$/);
  assert.equal(endpoint.basis.srv.interfaceId, 'if-a');
  assert.ok(Number.isInteger(endpoint.basis.srv.offset));
  assert.equal(endpoint.basis.address.interfaceId, 'if-a');
  assert.equal(snapshot.packets.length, 1);
  assert.equal(snapshot.packets[0].interfaceId, 'if-a');
});

test('损坏或超边界的名称记录拒收原因，且不阻断后续合法包', () => {
  const { directory, ingest } = fixture();
  const bad = Buffer.concat([
    Buffer.alloc(12),
    Buffer.from([0x3f, 0x61])
  ]);
  bad.writeUInt16BE(1, 6);
  ingest(bad);
  let snapshot = directory.snapshot();
  assert.equal(snapshot.rejects.length, 1);
  assert.match(snapshot.rejects[0].code, /NAME_|RECORD_/);
  assert.ok(snapshot.rejects[0].reason.length > 0);

  ingest(fullAnnouncement({ ttl: 60 }));
  snapshot = directory.snapshot();
  assert.equal(instanceByName(snapshot).state, 'ready');
  assert.equal(snapshot.summary.rejectedRecords, 1);
});

test('离线回放由手动时钟推进，重启后旧观察不获得新的完整寿命', () => {
  const { directory, clock, ingest } = fixture({ start: 1_000 });
  ingest(fullAnnouncement({ ttl: 120 }));
  clock.advance(60_000);
  const saved = directory.serialize();
  assert.equal(saved.instances[0].ptr.expiresAt, 121_000);

  // 在新进程里从零开始，载入 60 秒时的快照。
  const restartedClock = manualClock(0);
  const restarted = createDirectory({ clock: restartedClock });
  restartedClock.advance(saved.savedAt ?? 0);
  restarted.restore(saved);
  const station = instanceByName(restarted.snapshot());
  assert.equal(station.state, 'ready');
  assert.equal(station.expiresAt, 121_000, '绝对过期时间被保留');
  restartedClock.advance(59_999);
  assert.ok(instanceByName(restarted.snapshot()));
  restartedClock.advance(1);
  assert.equal(instances(restarted.snapshot()).length, 0);

  // 已经过期的记录载入时被丢弃，而不是刷新。
  const lateClock = manualClock(0);
  const late = createDirectory({ clock: lateClock });
  lateClock.advance(200_000);
  late.restore(saved);
  assert.equal(instances(late.snapshot()).length, 0);
  assert.ok(late.changes().some(event => event.type === 'state-restored' && event.detail.droppedRecords > 0));
});

test('刷新只延长被刷新记录的寿命，不延长其他记录', () => {
  const { directory, clock, ingest } = fixture();
  ingest(packet([ptrRecord(INSTANCE, 60), srvRecord({ ttl: 60 }), aRecord({ ttl: 60 })]));
  clock.advance(30_000);
  ingest(packet([ptrRecord(INSTANCE, 60)]));
  clock.advance(31_000);
  const station = instanceByName(directory.snapshot());
  assert.equal(station.advertised, true);
  assert.deepEqual(station.missing.map(entry => entry.dependency), ['srv', 'txt']);
  assert.equal(station.expiresAt, 90_000);
});

test('同一包中不同区段的同名记录各自按区段登记，重复 SRV 不会产生重复实例', () => {
  const { directory, ingest } = fixture();
  const records = [ptrRecord(), srvRecord(), srvRecord({ port: 9090 })];
  ingest(packet(records));
  const snapshot = directory.snapshot();
  assert.equal(instances(snapshot).length, 1);
  assert.equal(instanceByName(snapshot).service.port, 9090);
});

test('同一服务类型下实例改名：旧 PTR 被 cache-flush 换掉后旧实例撤出', () => {
  const { directory, ingest } = fixture();
  ingest(packet([ptrRecord(INSTANCE), srvRecord({ instance: INSTANCE }), aRecord({ ttl: 300 })]));
  ingest(packet([ptrRecord('station-2._collect._tcp.local', 120, true)]));
  const snapshot = directory.snapshot();
  assert.deepEqual(instances(snapshot).map(instance => instance.instanceName), ['station-2']);
  const withdrawn = directory.snapshot({ includeWithdrawn: true })
    .services.flatMap(service => service.instances)
    .find(instance => instance.instanceName === 'station');
  assert.equal(withdrawn.state, 'withdrawn');
  assert.equal(withdrawn.withdrawReason, 'cache-flush');
});

test('刷新后延迟到达的旧包不会复活或延长已过期记录', () => {
  const { directory, clock, ingest } = fixture();
  ingest(fullAnnouncement({ ttl: 30 }));
  clock.advance(31_000);
  // 该包在 0ms 被采集、TTL 30，到 31s 才回放；过期时间已过。
  ingest(packet([ptrRecord(INSTANCE, 30), srvRecord({ ttl: 30 })]), 'if-a', 0);
  const snapshot = directory.snapshot();
  assert.equal(instances(snapshot).length, 0);
  assert.ok(snapshot.recentChanges.some(event => event.type === 'record-stale'));
});

test('告别的 A 记录只影响它自己；SRV 的 TTL 独立于 PTR', () => {
  const { directory, clock, ingest } = fixture();
  ingest(packet([ptrRecord(INSTANCE, 200), srvRecord({ ttl: 30 }), aRecord({ ttl: 200 }), aaaaRecord({ ttl: 200 })]));
  clock.advance(31_000);
  let station = instanceByName(directory.snapshot());
  assert.equal(station.advertised, true);
  assert.deepEqual(station.missing.map(entry => entry.dependency), ['srv', 'txt']);
  ingest(packet([srvRecord({ port: 9090, ttl: 200 })]));
  station = instanceByName(directory.snapshot());
  assert.equal(station.state, 'ready');
  assert.equal(station.service.port, 9090);

  ingest(packet([aaaaRecord({ ttl: 0 })]));
  station = instanceByName(directory.snapshot());
  assert.deepEqual(station.endpoints.map(endpoint => endpoint.family), ['A']);
});
