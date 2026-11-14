import test from 'node:test';
import assert from 'node:assert/strict';
import { buildResponse, srvData, txtData, aData, aaaaData } from '../../src/receiver.mjs';
import { encodeName, TYPES } from '../../src/dns.mjs';

export const SERVICE = '_collect._tcp.local';
export const INSTANCE = `station.${SERVICE}`;
export const GATEWAY = 'gateway.local';
export const ALTERNATE = 'gateway-alt.local';

export function ptrRecord(instance = INSTANCE, ttl = 120, flush = false) {
  return { name: SERVICE, type: TYPES.PTR, ttl, flush, data: encodeName(instance) };
}
export function srvRecord({ instance = INSTANCE, target = GATEWAY, port = 8080, ttl = 120, flush = true } = {}) {
  return { name: instance, type: TYPES.SRV, ttl, flush, data: srvData(port, target) };
}
export function txtRecord({ instance = INSTANCE, strings = ['id=17'], ttl = 120, flush = true } = {}) {
  return { name: instance, type: TYPES.TXT, ttl, flush, data: txtData(strings) };
}
export function aRecord({ name = GATEWAY, address = '127.0.0.2', ttl = 120, flush = true } = {}) {
  return { name, type: TYPES.A, ttl, flush, data: aData(address) };
}
export function aaaaRecord({ name = GATEWAY, address = '::1', ttl = 120, flush = true } = {}) {
  return { name, type: TYPES.AAAA, ttl, flush, data: aaaaData(address) };
}

export function packet(records) {
  return buildResponse(records);
}

export function fullAnnouncement({ instance = INSTANCE, target = GATEWAY, port = 8080, ttl = 120, address = '127.0.0.2' } = {}) {
  return packet([
    ptrRecord(instance, ttl, true),
    srvRecord({ instance, target, port, ttl }),
    txtRecord({ instance, ttl }),
    aRecord({ name: target, address, ttl }),
    aaaaRecord({ name: target, ttl })
  ]);
}
