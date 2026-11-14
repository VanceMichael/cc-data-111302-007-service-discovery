import test from 'node:test';
import assert from 'node:assert/strict';
import { createSource } from '../src/source.mjs';
import { parseMessage } from '../src/dns.mjs';
import { announcement, header, compressedName } from '../src/discovery.mjs';
import { readFile } from 'node:fs/promises';

async function withSource(options, callback) {
  const source = await createSource(options);
  try { return await callback(source); } finally { await source.close(); }
}
function api(source) {
  return async (path, options = {}) => {
    const response = await fetch(source.url + path, {
      method: options.method || 'GET',
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: AbortSignal.timeout(4000)
    });
    const text = await response.text();
    let value = text;
    try { value = JSON.parse(text); } catch {}
    return { status: response.status, value };
  };
}

const FLEET = {
  clock: { mode: 'replay', start: 0 },
  emitters: [
    {
      id: 'eth0', source: '127.0.0.1', interface: { id: 'wlan0', name: 'wlan0', address: '10.0.0.1' },
      service: '_collect._tcp.local', instance: 'station', target: 'gateway.local',
      port: 8080, ttl: 90, address: [10, 0, 0, 20], address6: '::1'
    },
    {
      id: 'eth1', source: '127.0.0.2', interface: { id: 'eth0', name: 'eth0', address: '10.0.1.1' },
      service: '_collect._tcp.local', instance: 'station', target: 'gateway.local',
      port: 8080, ttl: 90, address: [10, 0, 1, 20], address6: '::1'
    }
  ],
  persistence: {}
};

test('来源把收到的包交给目录，目录可从 HTTP 读取', () => withSource({ receive: true, fixture: FLEET }, async source => {
  const client = api(source);
  const receiver = await client('/receiver');
  assert.ok(receiver.value.port >= 1024);
  const sent = await client('/emit', { method: 'POST', body: { port: receiver.value.port, id: 'eth0' } });
  assert.equal(sent.status, 200);
  // UDP 投递在本地异步完成；轮询到序号出现即可，无需 sleep。
  const deadline = Date.now() + 2000;
  let directory;
  do {
    directory = (await client('/directory')).value;
    if (directory.packets.length > 0) break;
  } while (Date.now() < deadline);
  assert.ok(directory.packets.length >= 1);
  const station = directory.services.flatMap(service => service.instances)[0];
  assert.equal(station.interface.id, 'wlan0');
  assert.equal(station.state, 'ready');
  assert.equal(station.endpoints.length, 2);
  assert.equal(station.endpoints[0].basis.interfaceId, 'wlan0');
  assert.ok(directory.packets[0].packetDigest);
}));

test('两台不同网卡的设备可用同一来源分别发送，接口范围互不混淆', () => withSource({ receive: true, fixture: FLEET }, async source => {
  const client = api(source);
  const receiver = await client('/receiver');
  await client('/emit', { method: 'POST', body: { port: receiver.value.port, id: 'eth0' } });
  await client('/emit', { method: 'POST', body: { port: receiver.value.port, id: 'eth1' } });
  const deadline = Date.now() + 2000;
  let directory;
  do {
    directory = (await client('/directory')).value;
    if (directory.packets.length >= 2) break;
  } while (Date.now() < deadline);
  assert.equal(directory.packets.length, 2);
  const stations = directory.services.flatMap(service => service.instances);
  assert.equal(stations.length, 2);
  assert.deepEqual(stations.map(station => station.interface.id).sort(), ['eth0', 'wlan0']);
  assert.deepEqual(stations.find(station => station.interface.id === 'eth0').endpoints.map(endpoint => endpoint.address), ['10.0.1.20', '0:0:0:0:0:0:0:1']);
  assert.deepEqual(directory.duplicates.map(group => group.interfaces.length), [2]);
}));

test('推进时钟会触发过期，目录不再等待真实时间', () => withSource({ receive: true, fixture: FLEET }, async source => {
  const client = api(source);
  const receiver = await client('/receiver');
  await client('/emit', { method: 'POST', body: { port: receiver.value.port, id: 'eth0' } });
  const deadline = Date.now() + 2000;
  let directory;
  do {
    directory = (await client('/directory')).value;
    if (directory.packets.length) break;
  } while (Date.now() < deadline);
  const advanced = await client('/advance', { method: 'POST', body: { ms: 91_000, since: 0 } });
  assert.equal(advanced.status, 200);
  assert.ok(advanced.value.events.some(event => event.type === 'instance-withdrawn'));
  const after = (await client('/directory')).value;
  assert.equal(after.summary.instances, 0);
  assert.equal(after.now, 91_000);
}));

test('状态文件保存后重启，缓存寿命不会重新起算', async () => {
  const directory = await import('node:fs/promises').then(fs => fs.mkdtemp('/tmp/dir-state-'));
  const statePath = `${directory}/state.json`;
  const first = await createSource({ receive: true, fixture: FLEET, statePath });
  const client = api(first);
  const receiver = await client('/receiver');
  await client('/emit', { method: 'POST', body: { port: receiver.value.port, id: 'eth0' } });
  await client('/advance', { method: 'POST', body: { ms: 40_000 } });
  const saved = await client('/save', { method: 'POST' });
  assert.equal(saved.status, 200);
  await first.close();

  const second = await createSource({ receive: false, fixture: FLEET, statePath });
  try {
    const restored = (await api(second)('/directory')).value;
    const station = restored.services.flatMap(service => service.instances)[0];
    assert.ok(station, '快照中仍然有效的观察应恢复');
    assert.equal(restored.now, 40_000, '回放时钟从保存点继续');
    assert.equal(station.expiresAt, 90_000, '过期时间是绝对值，不是新的完整寿命');
    await api(second)('/advance', { method: 'POST', body: { ms: 50_000 } });
    assert.equal((await api(second)('/directory')).value.summary.instances, 0);
  } finally {
    await second.close();
  }
});

test('来源单次通告仍包含 PTR/SRV/TXT/A/AAAA，压缩样本可解析', () => withSource({ receive: true }, async source => {
  const emitter = source.emitters[0];
  const packet = announcement(source.state, emitter);
  const parsed = parseMessage(packet);
  assert.equal(parsed.records.length, 5);
  assert.deepEqual(parsed.records.map(record => record.typeName), ['PTR', 'SRV', 'TXT', 'A', 'AAAA']);
  assert.equal(parsed.records[1].data.target, emitter.target);
  assert.equal(parsed.records[1].data.port, emitter.port);
  assert.equal(parsed.records[0].data.target, `${emitter.instance}.${emitter.service}`);
  assert.ok(compressedName.at(-2) === 0xc0);
  // compressedName 指向自身第 0 字节；这是回环，必须被拒绝而不是读到无限循环。
  const pointerPacket = Buffer.concat([
    Buffer.alloc(12),
    Buffer.from([0xc0, 0x00, 0, 1, 0, 1, 0, 0, 0, 9, 0, 4, 1, 2, 3, 4])
  ]);
  pointerPacket.writeUInt16BE(1, 6);
  const rejected = parseMessage(pointerPacket);
  assert.equal(rejected.records.length, 0);
  assert.match(rejected.rejected[0].code, /NAME_POINTER/);
}));

test('坏报文的拒收原因通过目录接口可见，且不阻断后续流量', () => withSource({ receive: true }, async source => {
  const client = api(source);
  const bad = Buffer.alloc(20);
  bad.writeUInt16BE(1, 6);
  bad[12] = 0x3f;
  const response = await client('/receive', { method: 'POST', body: { hex: bad.toString('hex'), interfaceId: 'wlan0' } });
  assert.equal(response.status, 200);
  const directory = (await client('/directory')).value;
  assert.equal(directory.rejects.length, 1);
  assert.ok(directory.rejects[0].reason);
  assert.equal(directory.rejects[0].packetId, response.value.packet.packetId);
  const receiver = await client('/receiver');
  await client('/emit', { method: 'POST', body: { port: receiver.value.port } });
  const deadline = Date.now() + 2000;
  let after;
  do {
    after = (await client('/directory')).value;
    if (after.summary.instances > 0) break;
  } while (Date.now() < deadline);
  assert.equal(after.services.flatMap(service => service.instances)[0].state, 'ready');
}));

test('健康检查、未知路径与坏控制请求的既有行为不变', () => withSource({}, async source => {
  const client = api(source);
  assert.equal((await client('/health')).value.status, 'ok');
  assert.equal((await client('/missing')).status, 404);
  const invalid = await fetch(source.url + '/control', { method: 'POST', body: 'not-json' });
  assert.equal(invalid.status, 400);
  const emitted = await client('/emit', { method: 'POST', body: { port: 80 } });
  assert.equal(emitted.status, 400);
  const NaNAdvance = await client('/advance', { method: 'POST', body: { ms: 'x' } });
  assert.equal(NaNAdvance.status, 400);
  const negative = await client('/advance', { method: 'POST', body: { ms: -1 } });
  assert.equal(negative.status, 400);
}));

test('真实时钟模式拒绝手动推进，避免过期语义失真', () => withSource({ clockMode: 'real' }, async source => {
  const client = api(source);
  const rejected = await client('/advance', { method: 'POST', body: { ms: 1000 } });
  assert.equal(rejected.status, 409);
  assert.match(rejected.value.error, /CLOCK=replay/);
  const directory = (await client('/directory')).value;
  assert.equal(directory.clock.mode, 'real');
  assert.ok(directory.now > 0);
}));
