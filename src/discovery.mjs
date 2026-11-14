import dgram from 'node:dgram';
import { buildResponse, srvData, txtData, aData, aaaaData, parseMessage } from './receiver.mjs';
import { encodeName, TYPES } from './dns.mjs';

export const SERVICE = '_collect._tcp.local';
export const INSTANCE = `station.${SERVICE}`;

export function dnsName(text) {
  return encodeName(text);
}

export function header(packet) {
  if (packet.length < 12) throw new Error('DNS头不完整');
  return { answers: packet.readUInt16BE(6), flags: packet.readUInt16BE(2) };
}

function number(value) {
  return Number.isFinite(Number(value)) ? Number(value) : undefined;
}

/**
 * Build the packet for one emitter. `state` is the source-level default,
 * `emitter` adds per-interface overrides, and `overrides` come from /emit.
 * All three levels may carry `records` for replaying arbitrary captures.
 */
export function announcement(state = {}, emitter = {}, overrides = {}) {
  // Precedence: per-emit overrides, then source-level /control values, then
  // the emitter's own fixture defaults.
  const merged = { ...emitter, ...state, ...overrides };
  const ttl = merged.goodbye ? 0 : merged.ttl;
  const ttlFor = (kind, fallback = ttl) => {
    const value = merged[`ttl${kind}`];
    return Number.isFinite(Number(value)) ? Number(value) : fallback;
  };
  const service = merged.service ?? SERVICE;
  const shortInstance = merged.instance ?? 'station';
  // PTR RDATA and SRV owner must carry the fully qualified instance name;
  // fixtures may use the short label.
  const instance = shortInstance.toLowerCase().endsWith(`.${service.toLowerCase()}`)
    ? shortInstance
    : `${shortInstance}.${service}`;
  const target = merged.target ?? 'gateway.local';
  const port = number(merged.port) ?? 8080;
  const records = [];

  records.push({ name: service, type: TYPES.PTR, ttl: ttlFor('Ptr', ttl), data: encodeName(instance) });
  if (merged.srv !== false) records.push({ name: instance, type: TYPES.SRV, ttl: ttlFor('Srv', ttl), flush: true, data: srvData(port, target) });
  if (merged.txt !== false) {
    const entries = merged.txt ?? (merged.txtStrings ?? ['id=17']);
    records.push({ name: instance, type: TYPES.TXT, ttl: ttlFor('Txt', ttl), flush: true, data: txtData(entries) });
  }
  const address = merged.a === false ? null : addressText(merged.address, '127.0.0.2');
  if (address) records.push({ name: target, type: TYPES.A, ttl: ttlFor('A', ttl), flush: true, data: aData(address) });
  const address6 = merged.aaaa === false ? null : (merged.address6 ?? '::1');
  if (address6) records.push({ name: target, type: TYPES.AAAA, ttl: ttlFor('Aaaa', ttl), flush: true, data: aaaaData(address6) });

  if (Array.isArray(merged.records)) {
    // Extra records for replay scenarios; exact malformed bytes belong to
    // POST /receive, which takes a whole captured packet.
    for (const extra of merged.records) {
      records.push({
        name: extra.name,
        type: extra.type,
        ttl: Number.isFinite(extra.ttl) ? extra.ttl : ttl,
        flush: Boolean(extra.flush),
        data: extra.data
      });
    }
  }
  return buildResponse(records);
}

export function addressText(value, fallback) {
  if (Array.isArray(value)) return value.join('.');
  if (typeof value === 'string' && value) return value;
  return fallback;
}

export const compressedName = Buffer.concat([encodeName('gateway.local'), Buffer.from([0xc0, 0])]);

export { parseMessage };

export async function attach({ bind = '127.0.0.1' } = {}) {
  const socket = dgram.createSocket('udp4');
  await new Promise(resolve => socket.bind(0, bind, resolve));
  return {
    send: (packet, port) => new Promise((resolve, reject) => socket.send(packet, port, '127.0.0.1', error => error ? reject(error) : resolve())),
    close: () => new Promise(resolve => socket.close(resolve))
  };
}
