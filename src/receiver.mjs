import { createSocket } from 'node:dgram';
import { parseMessage, encodeName, TYPES, CLASS_IN, CACHE_FLUSH } from './dns.mjs';

/**
 * Listen on a local UDP endpoint and attribute every received packet to the
 * interface (and, where available, the source address) recorded by the capture
 * layer. The socket only receives; it never sends queries or probes ports.
 */
export async function createReceiver({ port = 0, host = '127.0.0.1', clock, socketType = 'udp4', bindAddress = host, sourceAddress, interfaces } = {}) {
  const receiveTime = clock ?? null;
  const socket = createSocket(socketType);
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(port, bindAddress, () => {
      socket.off('error', reject);
      resolve();
    });
  });
  const bound = socket.address();
  const listeners = new Set();
  const defaultInterface = sourceAddress ?? `${bound.address}/${bound.port}`;
  let sequence = 0;

  socket.on('message', (packet, remote) => {
    const capturedAt = receiveTime ? receiveTime.now() : Date.now();
    const iface = resolveInterface({ remote, interfaces, fallback: defaultInterface });
    const packetSequence = ++sequence;
    const packetId = `pkt-${String(packetSequence).padStart(6, '0')}`;
    const observation = {
      packet,
      capturedAt,
      interfaceId: iface.id,
      interfaceName: iface.name,
      interfaceAddress: iface.address,
      sourceAddress: remote.address,
      sourcePort: remote.port,
      packetId
    };
    for (const listener of listeners) {
      try { listener(observation); } catch (error) { listener.onError?.(error); }
    }
  });

  return {
    address: bound.address,
    port: bound.port,
    url: `udp://${bound.address}:${bound.port}`,
    onMessage(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    close: () => new Promise(resolve => {
      try { socket.close(resolve); } catch { resolve(); }
    })
  };
}

function resolveInterface({ remote, interfaces, fallback }) {
  const explicit = interfaces?.[remote.address];
  if (explicit) {
    return typeof explicit === 'string'
      ? { id: explicit, name: explicit, address: remote.address }
      : { id: explicit.id ?? explicit.name ?? explicit.address ?? fallback, name: explicit.name ?? explicit.id ?? fallback, address: explicit.address ?? remote.address };
  }
  return { id: fallback, name: fallback, address: remote.address };
}

/** Build a DNS response-style packet for local emitters. */
export function buildResponse(records, { id = 0, flags = 0x8400 } = {}) {
  const entries = records.map(record => encodeRecord(record));
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(0, 4);
  header.writeUInt16BE(entries.length, 6);
  return Buffer.concat([header, ...entries]);
}

export function encodeRecord({ name, type, ttl = 0, flush = false, data }) {
  const nameBytes = Buffer.isBuffer(name) ? name : encodeName(name);
  const rdata = Buffer.isBuffer(data) ? data : Buffer.from(data ?? []);
  const header = Buffer.alloc(10);
  header.writeUInt16BE(type, 0);
  header.writeUInt16BE(CLASS_IN | (flush ? CACHE_FLUSH : 0), 2);
  header.writeUInt32BE(ttl >>> 0, 4);
  header.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([nameBytes, header, rdata]);
}

/** A DNS-SD service instance target, used by emitters and tests. */
export function srvData(port, targetName) {
  const bytes = Buffer.alloc(6);
  bytes.writeUInt16BE(0, 0);
  bytes.writeUInt16BE(0, 2);
  bytes.writeUInt16BE(port, 4);
  return Buffer.concat([bytes, encodeName(targetName)]);
}

export function txtData(entries) {
  return Buffer.concat(entries.map(entry => {
    const bytes = Buffer.isBuffer(entry) ? entry : Buffer.from(entry, 'utf8');
    return Buffer.concat([Buffer.from([bytes.length]), bytes]);
  }));
}

export function aData(address) {
  const parts = String(address).split('.').map(part => Number(part));
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) throw new Error('IPv4 地址无效');
  return Buffer.from(parts);
}

export function aaaaData(address) {
  const text = String(address).replace(/^::1$/, '::1');
  const groups = parseIpv6(text);
  const bytes = Buffer.alloc(16);
  for (let index = 0; index < 8; index += 1) bytes.writeUInt16BE(groups[index], index * 2);
  return bytes;
}

function parseIpv6(text) {
  const [head, tail] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = tail !== undefined && tail !== '' ? tail.split(':') : [];
  if (text.split('::').length > 2) throw new Error('IPv6 地址无效');
  const fill = 8 - left.length - right.length;
  if (fill < 0 || (text.includes('::') && fill === 0)) throw new Error('IPv6 地址无效');
  const groups = [...left, ...(text.includes('::') ? Array(fill).fill('0') : []), ...right];
  return groups.map(part => {
    const value = Number.parseInt(part, 16);
    if (!Number.isFinite(value) || value < 0 || value > 0xffff) throw new Error('IPv6 地址无效');
    return value;
  });
}

export { parseMessage, encodeName, TYPES };
