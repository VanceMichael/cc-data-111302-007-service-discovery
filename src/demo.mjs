import { createSource } from './source.mjs';
import { setTimeout as delay } from 'node:timers/promises';

/**
 * 展馆演示：两个接口同时采集，按顺序回放
 *   1) 双接口重名  2) 设备改目标主机  3) 地址先到期后补齐  4) 正常离网
 * 全程用可推进的时钟，不等待真实时间。
 */
const source = await createSource({ receive: true });
const { directory, clock, receiver } = source;

async function post(path, body = {}) {
  const response = await fetch(source.url + path, { method: 'POST', body: JSON.stringify(body) });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error ?? `HTTP ${response.status}`);
  return value;
}

async function emit(id, overrides = {}) {
  const before = directory.snapshot().summary.packets;
  await post('/emit', { port: receiver.port, id, ...overrides });
  const deadline = Date.now() + 2000;
  while (directory.snapshot().summary.packets === before && Date.now() < deadline) await delay(5);
}

function line(instance) {
  const endpoints = instance.endpoints.filter(endpoint => endpoint.connectable);
  let targets;
  if (endpoints.length) {
    targets = endpoints.map(endpoint => `${endpoint.address}:${endpoint.port} (${endpoint.family})`).join('，');
  } else if (instance.endpoints.length) {
    targets = `${instance.endpoints.map(endpoint => `${endpoint.address}:${endpoint.port}`).join('，')} 不可连接（已撤回）`;
  } else {
    targets = `无端点（缺 ${instance.missing.map(item => item.dependency).join('/') || '记录'}）`;
  }
  return `  ${instance.interface.id.padEnd(6)} ${instance.label.padEnd(11)} ${targets.padEnd(46)} [${instance.state}]`;
}

function show(title, note) {
  console.log(`\n${title}  t=${clock.now()}ms`);
  if (note) console.log(`  ${note}`);
  const snapshot = directory.snapshot({ includeWithdrawn: true });
  for (const instance of snapshot.services.flatMap(service => service.instances)) console.log(line(instance));
  if (snapshot.duplicates.length) {
    console.log(`  同名实例出现在 ${snapshot.duplicates[0].interfaces.map(iface => iface.id).join(' 与 ')}：${snapshot.duplicates[0].note}`);
  }
  if (snapshot.hosts.length) {
    console.log(`  缓存主机：${snapshot.hosts.map(host => `${host.interface.id}/${host.name}(${host.addresses.map(address => address.address).join(' ')})`).join('，')}`);
  }
}

console.log(JSON.stringify({ status: '目录采集演示', receiver: `udp://127.0.0.1:${receiver.port}`, clock: directory.snapshot().clock }));

await emit('hall-a');
await emit('hall-b');
show('1. 双接口重名：两个网卡都听到 gateway-01', '两台接口各自缓存自己的地址；不会把 wlan0 的 SRV 和 eth0 的地址拼成一条实际上不通的连接。');

clock.advance(10_000);
await emit('hall-a', { target: 'gateway-alt.local', address: [10, 20, 0, 22] });
show('2. 设备改目标主机：wlan0 上的实例换到 gateway-alt.local', '旧的 gateway-01.local 地址仍在缓存，但不再出现在 wlan0 的可连接端点上。');

clock.advance(20_000);
await emit('hall-a', { target: 'gateway-alt.local', address: [10, 20, 0, 22], ttl: 90, ttlA: 20, ttlAaaa: 20 });
await emit('hall-b', { ttl: 90 });
show('3. 只有 wlan0 的地址记录拿到较短的缓存期限', 'PTR/SRV/TXT 仍是 90 秒寿命，A/AAAA 只有 20 秒；各记录按自己的 TTL 计算。');

clock.advance(20_001);
show('4. wlan0 的地址先过期，服务本身没有消失', '实例仍被通告，目录明确显示缺 address；地址记录过期不等于整个服务结束。');

clock.advance(5_000);
await emit('hall-a', { target: 'gateway-alt.local', address: [10, 20, 0, 23], ttl: 60 });
show('5. 迟到的 A 记录补齐同一实例', '不需要重新收到 PTR，端点依据里给出了新的来源包。');

clock.advance(10_000);
// 只发 PTR 的告别，模拟设备退出但旧地址记录仍在缓存里。
await emit('hall-b', { goodbye: true, srv: false, txt: false, a: false, aaaa: false });
show('6. 正常离网：eth0 上的实例发出 PTR 的 TTL=0 告别', 'PTR 退出后该接口的实例被撤回；缓存中的地址记录不能当作仍可连接。');
const withdrawnView = directory.snapshot({ includeWithdrawn: true })
  .services.flatMap(service => service.instances)
  .find(instance => !instance.advertised);
if (withdrawnView) console.log(`  includeWithdrawn 明细：${withdrawnView.interface.id} ${withdrawnView.instanceName} 撤回原因=${withdrawnView.withdrawReason}，端点 connectable=${withdrawnView.endpoints.map(endpoint => endpoint.connectable).join(',')}`);

console.log('\n最近变化：');
for (const event of directory.changes().slice(-14)) {
  console.log(`  ${String(event.at).padStart(6)}ms  ${event.type.padEnd(19)} ${event.interfaceId}${event.instance ? '  ' + event.instance : ''}`);
}
console.log(JSON.stringify({
  now: clock.now(),
  summary: directory.snapshot().summary,
  rejects: directory.snapshot().rejects,
  sampleEndpointBasis: directory.snapshot().services
    .flatMap(service => service.instances)
    .flatMap(instance => instance.endpoints)
    .slice(0, 1)
    .map(endpoint => ({ address: endpoint.address, interface: endpoint.basis.interfaceId, srvPacket: endpoint.basis.srv.packetId, addressPacket: endpoint.basis.address.packetId }))
}));
await source.close();
