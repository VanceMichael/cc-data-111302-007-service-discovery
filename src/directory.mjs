import { createHash } from 'node:crypto';
import { parseMessage, TYPES, CLASS_IN } from './dns.mjs';

const EVENT_LIMIT = 2000;
const PACKET_LIMIT = 500;
const REJECT_LIMIT = 300;
const SNAPSHOT_EVENT_LIMIT = 100;

const TYPE_NAME = new Map([
  [TYPES.A, 'A'],
  [TYPES.AAAA, 'AAAA'],
  [TYPES.PTR, 'PTR'],
  [TYPES.SRV, 'SRV'],
  [TYPES.TXT, 'TXT']
]);

export function normalizeName(value) {
  return String(value ?? '').replace(/\.$/, '').toLowerCase();
}

function lower(value) {
  return normalizeName(value);
}

/**
 * DNS-SD cache and directory.
 *
 * Identity is deliberately split into three scopes:
 *  - instance: interface + service type + instance name
 *  - target host: interface + host name
 *  - address: interface + host name + address family + address
 *
 * Addresses are never borrowed from another interface and an address record
 * never creates or destroys a service instance by itself.
 */
export function createDirectory({ clock, snapshot, captureRaw = false } = {}) {
  if (!clock || typeof clock.now !== 'function') throw new Error('目录需要一个可推进的时钟');
  const directory = new Directory(clock, captureRaw);
  if (snapshot) directory.restore(snapshot);
  return directory;
}

class Directory {
  constructor(clock, captureRaw) {
    this.clock = clock;
    this.captureRaw = captureRaw;
    this.interfaces = new Map();
    this.instances = new Map();
    this.hosts = new Map();
    this.services = new Map();
    this.events = [];
    this.rejects = [];
    this.packets = [];
    this.packetSequence = 0;
  }

  get now() {
    return this.clock.now();
  }

  advance(milliseconds) {
    this.clock.advance(milliseconds);
    this.sweep();
    return this.snapshot();
  }

  /** Ingest one captured datagram. Never throws because one bad packet must not stop the stream. */
  ingest(observation) {
    const receivedAt = Number.isFinite(observation?.capturedAt) ? observation.capturedAt : this.clock.now();
    const packet = Buffer.isBuffer(observation?.packet) ? observation.packet : Buffer.from(observation?.packet ?? []);
    const digest = observation?.packetDigest ?? createHash('sha256').update(packet).digest('hex');
    const interfaceInfo = this.#interfaceFor(observation, receivedAt);
    const packetId = observation?.packetId ?? `pkt-${String(this.packetSequence + 1).padStart(6, '0')}`;
    this.packetSequence += 1;
    const packetEntry = {
      sequence: this.packetSequence,
      packetId,
      packetDigest: digest,
      interfaceId: interfaceInfo.id,
      interfaceName: interfaceInfo.name,
      source: { address: observation?.sourceAddress ?? null, port: observation?.sourcePort ?? null },
      capturedAt: receivedAt,
      bytes: packet.length,
      recordCount: 0,
      rejectedCount: 0
    };
    if (this.captureRaw) packetEntry.raw = packet.toString('base64');

    try {
      const parsed = parseMessage(packet);
      packetEntry.recordCount = parsed.records.length;
      packetEntry.rejectedCount = parsed.rejected.length;
      packetEntry.counts = parsed.counts ?? null;

      for (const rejected of parsed.rejected) {
        this.#recordReject(rejected, { packetId, digest, packetEntry, interfaceInfo, receivedAt });
      }

      const supported = [];
      let ignored = 0;
      for (const parsedRecord of parsed.records) {
        if (!TYPE_NAME.has(parsedRecord.type) || parsedRecord.class !== CLASS_IN) {
          ignored += 1;
          continue;
        }
        supported.push(parsedRecord);
      }
      packetEntry.ignoredCount = ignored;

      this.#applyRecords(supported, { packetId, digest, packetEntry, interfaceInfo, receivedAt, observation });
    } catch (error) {
      packetEntry.rejectedCount += 1;
      this.#recordReject(errorReject(error), { packetId, digest, packetEntry, interfaceInfo, receivedAt });
    }

    this.#trimPackets();
    this.#pushEvent({ at: receivedAt, type: 'packet-received', packetId, interfaceId: interfaceInfo.id, detail: { records: packetEntry.recordCount, rejected: packetEntry.rejectedCount } });
    this.packets.push(packetEntry);
    this.sweep();
    return packetEntry;
  }

  ingestPacket(packet, options = {}) {
    return this.ingest({ ...options, packet });
  }

  observe(observation) {
    return this.ingest(observation);
  }

  sweep(at = this.clock.now()) {
    for (const instance of this.instances.values()) {
      if (instance.ptr && instance.ptr.expiresAt <= at) {
        this.#withdrawPtr(instance, instance.ptr.expiresAt, 'ttl-expired');
      }
      if (instance.srv && instance.srv.expiresAt <= at) {
        this.#expireRecord(instance.srv, 'SRV', instance);
        instance.srv = null;
      }
      if (instance.txt && instance.txt.expiresAt <= at) {
        this.#expireRecord(instance.txt, 'TXT', instance);
        instance.txt = null;
      }
    }
    for (const host of this.hosts.values()) {
      for (const [addressKey, address] of host.addresses) {
        if (address.expiresAt <= at) {
          host.addresses.delete(addressKey);
          this.#pushEvent({
            at: address.expiresAt,
            type: 'address-expired',
            interfaceId: host.interfaceId,
            serviceType: null,
            instance: null,
            detail: { host: host.name, address: address.data.address, family: address.typeName, expiredAt: address.expiresAt }
          });
        }
      }
      if (host.addresses.size === 0) {
        // Keep an empty host out of the visible output but retain the key so a
        // late A/AAAA record does not create a second identity.
        host.emptySince = host.emptySince ?? at;
      } else {
        host.emptySince = null;
      }
    }
    return this;
  }

  snapshot({ includeWithdrawn = false } = {}) {
    this.sweep();
    const now = this.clock.now();
    const visible = [...this.instances.values()]
      .filter(instance => this.#visible(instance, includeWithdrawn))
      .map(instance => this.#instanceView(instance, now));
    const groups = new Map();
    for (const view of visible) {
      const key = lower(view.serviceType);
      if (!groups.has(key)) groups.set(key, { serviceType: view.serviceType, instances: [] });
      groups.get(key).instances.push(view);
    }
    const services = [...groups.values()].sort((a, b) => a.serviceType.localeCompare(b.serviceType));
    for (const service of services) service.instances.sort((a, b) => a.instanceName.localeCompare(b.instanceName) || a.interface.id.localeCompare(b.interface.id));

    const duplicates = this.#duplicates(visible);
    const hosts = [...this.hosts.values()]
      .filter(host => host.addresses.size > 0)
      .map(host => this.#hostView(host, now))
      .sort((a, b) => a.interface.id.localeCompare(b.interface.id) || a.name.localeCompare(b.name));

    const interfaces = [...this.interfaces.values()]
      .map(entry => ({ ...entry }))
      .sort((a, b) => a.id.localeCompare(b.id));

    const endpoints = visible.reduce((sum, instance) => sum + instance.endpoints.length, 0);
    return {
      version: 1,
      now,
      clock: { mode: this.clock.real ? 'real' : 'replay', generation: this.clock.generation ?? 0 },
      summary: {
        interfaces: interfaces.length,
        services: services.length,
        instances: visible.length,
        advertised: visible.filter(instance => instance.advertised).length,
        endpoints,
        incomplete: visible.filter(instance => instance.state === 'incomplete').length,
        packets: this.packets.length,
        rejectedRecords: this.rejects.length
      },
      interfaces,
      services,
      hosts,
      duplicates,
      recentChanges: this.events.slice(-SNAPSHOT_EVENT_LIMIT),
      rejects: this.rejects.slice(-REJECT_LIMIT),
      packets: this.packets.slice(-PACKET_LIMIT)
    };
  }

  inventory(options) {
    return this.snapshot(options);
  }

  changes({ since = null } = {}) {
    if (since === null) return [...this.events];
    return this.events.filter(event => event.at >= since);
  }

  clearChanges() {
    this.events = [];
  }

  /** Record a directory-level problem (e.g. an unreadable saved state file). */
  recordSystemEvent(type, detail = {}) {
    this.#pushEvent({ at: this.clock.now(), type, interfaceId: null, detail });
    return this;
  }

  /**
   * Absolute expiry times are stored. A restart therefore keeps the original
   * lifetime; stale observations are dropped instead of being renewed.
   */
  serialize() {
    this.sweep();
    const now = this.clock.now();
    const instances = [];
    for (const instance of this.instances.values()) {
      if (!instance.ptr && !instance.srv && !instance.txt) continue;
      instances.push({
        serviceType: instance.serviceType,
        instanceName: instance.instanceName,
        interfaceId: instance.interfaceId,
        firstSeenAt: instance.firstSeenAt,
        lastSeenAt: instance.lastSeenAt,
        withdrawnAt: instance.withdrawnAt,
        withdrawReason: instance.withdrawReason,
        ptr: instance.ptr ? cloneRecord(instance.ptr) : null,
        srv: instance.srv ? cloneRecord(instance.srv) : null,
        txt: instance.txt ? cloneRecord(instance.txt) : null
      });
    }
    const hosts = [...this.hosts.values()]
      .filter(host => host.addresses.size > 0)
      .map(host => ({
        name: host.name,
        interfaceId: host.interfaceId,
        firstSeenAt: host.firstSeenAt,
        lastSeenAt: host.lastSeenAt,
        addresses: [...host.addresses.values()].map(cloneRecord)
      }));
    return {
      version: 1,
      savedAt: now,
      clockMode: this.clock.real ? 'real' : 'replay',
      interfaces: [...this.interfaces.values()].map(entry => ({ ...entry })),
      instances,
      hosts,
      events: this.events.slice(-500),
      rejects: this.rejects.slice(-REJECT_LIMIT)
    };
  }

  save() {
    return this.serialize();
  }

  restore(state) {
    if (!state || state.version !== 1) throw new Error('目录快照版本不受支持');
    const now = this.clock.now();
    let dropped = 0;
    for (const entry of state.interfaces ?? []) {
      if (!entry?.id) continue;
      this.interfaces.set(entry.id, { ...entry });
    }
    for (const saved of state.instances ?? []) {
      const keep = record => {
        if (!record) return null;
        if (!Number.isFinite(record.expiresAt) || !Number.isFinite(record.capturedAt)) { dropped += 1; return null; }
        if (record.expiresAt <= now) { dropped += 1; return null; }
        return cloneRecord(record);
      };
      const ptr = keep(saved.ptr);
      const srv = keep(saved.srv);
      const txt = keep(saved.txt);
      if (!ptr && !srv && !txt) continue;
      const instance = this.#ensureInstance({
        serviceType: saved.serviceType,
        instanceName: saved.instanceName,
        interfaceId: saved.interfaceId,
        at: saved.firstSeenAt ?? now
      });
      instance.ptr = ptr;
      instance.srv = srv;
      instance.txt = txt;
      instance.firstSeenAt = Math.min(instance.firstSeenAt, saved.firstSeenAt ?? now);
      instance.lastSeenAt = Math.max(instance.lastSeenAt, saved.lastSeenAt ?? now);
      // A PTR that is gone after restore is still gone; do not renew it.
      if (!ptr) {
        instance.withdrawnAt = saved.withdrawnAt ?? (saved.ptr?.expiresAt ?? now);
        instance.withdrawReason = saved.withdrawReason ?? 'expired-before-restart';
      } else {
        instance.withdrawnAt = saved.withdrawnAt ?? null;
        instance.withdrawReason = saved.withdrawReason ?? null;
      }
    }
    for (const saved of state.hosts ?? []) {
      if (!saved?.name) continue;
      const host = this.#ensureHost(saved.name, saved.interfaceId, now);
      host.firstSeenAt = Math.min(host.firstSeenAt, saved.firstSeenAt ?? now);
      host.lastSeenAt = Math.max(host.lastSeenAt, saved.lastSeenAt ?? now);
      for (const record of saved.addresses ?? []) {
        if (!record || !Number.isFinite(record.expiresAt) || record.expiresAt <= now) { dropped += 1; continue; }
        host.addresses.set(addressKey(record.type, record.data?.address), cloneRecord(record));
      }
      if (host.addresses.size === 0) host.emptySince = host.emptySince ?? now;
    }
    this.events = Array.isArray(state.events) ? state.events.slice(-EVENT_LIMIT) : [];
    this.rejects = Array.isArray(state.rejects) ? state.rejects.slice(-REJECT_LIMIT) : [];
    this.#pushEvent({ at: now, type: 'state-restored', detail: { savedAt: state.savedAt ?? null, droppedRecords: dropped, remainingInstances: this.instances.size, remainingHosts: this.hosts.size } });
    return { dropped, instances: this.instances.size, hosts: this.hosts.size };
  }

  load(state) {
    return this.restore(state);
  }

  #applyRecords(records, context) {
    const { packetId, digest, packetEntry, interfaceInfo, receivedAt } = context;
    const byRrset = new Map();
    for (const parsed of records) {
      const ownerLower = lower(parsed.name);
      const key = `${ownerLower}|${parsed.type}`;
      if (!byRrset.has(key)) byRrset.set(key, []);
      byRrset.get(key).push(parsed);
    }

    // Cache-flush replacement applies to a whole RRset, so look at the incoming
    // records together before storing any of them.
    for (const group of byRrset.values()) {
      const flush = group.some(record => record.cacheFlush && record.ttl > 0);
      if (!flush) continue;
      const incoming = new Set(group.map(record => rrIdentity(record)));
      this.#dropRrset(interfaceInfo.id, group[0], incoming, receivedAt, packetId);
    }

    for (const parsed of records) {
      const record = this.#recordFromParsed(parsed, { packetId, digest, packetEntry, interfaceInfo, receivedAt });
      if (parsed.ttl === 0) {
        this.#applyGoodbye(record, receivedAt);
        continue;
      }
      if (record.expiresAt <= this.clock.now()) {
        // Replaying a stale packet must not resurrect or extend an observation.
        this.#pushEvent({ at: receivedAt, type: 'record-stale', interfaceId: interfaceInfo.id, detail: { name: record.name, type: record.typeName, expiredAt: record.expiresAt } });
        continue;
      }
      this.#store(record, receivedAt);
    }
  }

  #recordFromParsed(parsed, { packetId, digest, packetEntry, interfaceInfo, receivedAt }) {
    return {
      name: parsed.name,
      nameLower: lower(parsed.name),
      type: parsed.type,
      typeName: parsed.typeName,
      class: parsed.class,
      cacheFlush: parsed.cacheFlush,
      ttl: parsed.ttl,
      data: parsed.data,
      capturedAt: receivedAt,
      expiresAt: receivedAt + parsed.ttl * 1000,
      firstSeenAt: receivedAt,
      lastSeenAt: receivedAt,
      refreshCount: 0,
      interfaceId: interfaceInfo.id,
      interfaceName: interfaceInfo.name,
      packetId,
      packetDigest: digest,
      packetSequence: packetEntry.sequence,
      section: parsed.section,
      offset: parsed.offset,
      rdataStart: parsed.rdataStart,
      rdataEnd: parsed.rdataEnd
    };
  }

  #store(record, receivedAt) {
    switch (record.type) {
      case TYPES.PTR: return this.#storePtr(record, receivedAt);
      case TYPES.SRV: return this.#storeSrv(record, receivedAt);
      case TYPES.TXT: return this.#storeTxt(record, receivedAt);
      case TYPES.A:
      case TYPES.AAAA: return this.#storeAddress(record, receivedAt);
      default: return undefined;
    }
  }

  #storePtr(record, receivedAt) {
    const serviceType = record.name;
    const fullName = record.data.target;
    // Register the service type before resolving, so an SRV/TXT seen earlier
    // can join this instance instead of creating a twin.
    const serviceKey = `${lower(serviceType)}\0${record.interfaceId}`;
    const existingService = this.services.get(serviceKey) ?? { serviceType, interfaceId: record.interfaceId, typeNames: [] };
    existingService.typeNames = [...new Set([...(existingService.typeNames ?? []), serviceType])];
    this.services.set(serviceKey, existingService);
    const { instanceName, serviceType: resolved } = this.#resolveInstance(fullName, record.interfaceId, receivedAt);
    const instance = this.#ensureInstance({ serviceType: resolved || serviceType, instanceName, interfaceId: record.interfaceId, at: receivedAt });
    const existed = instance.ptr !== null;
    const targetChanged = instance.ptr && lower(instance.ptr.data.target) !== lower(record.data.target);
    instance.ptr = mergeRecord(instance.ptr, record);
    instance.lastSeenAt = Math.max(instance.lastSeenAt, receivedAt);
    instance.withdrawnAt = null;
    instance.withdrawReason = null;
    if (!existed || targetChanged) {
      this.#pushEvent({
        at: receivedAt,
        type: 'instance-advertised',
        interfaceId: record.interfaceId,
        serviceType,
        instance: instanceName,
        detail: { packetId: record.packetId, service: serviceType }
      });
    }
  }

  #storeSrv(record, receivedAt) {
    const resolved = this.#resolveInstance(record.name, record.interfaceId, receivedAt);
    const instance = this.#ensureInstance({ ...resolved, interfaceId: record.interfaceId, at: receivedAt });
    // A cache-flush RRset drops the old SRV before storing the new one; keep
    // its value long enough to report a target change with both sides.
    const previous = instance.srv ?? instance.flushedSrv ?? null;
    instance.flushedSrv = null;
    instance.srv = mergeRecord(previous ?? undefined, record);
    instance.lastSeenAt = Math.max(instance.lastSeenAt, receivedAt);
    const changed = !previous
      || lower(previous.data.target) !== lower(record.data.target)
      || previous.data.port !== record.data.port;
    if (changed) {
      this.#pushEvent({
        at: receivedAt,
        type: 'target-changed',
        interfaceId: record.interfaceId,
        serviceType: instance.serviceType,
        instance: instance.instanceName,
        detail: {
          previous: previous ? { target: previous.data.target, port: previous.data.port } : null,
          next: { target: record.data.target, port: record.data.port },
          packetId: record.packetId
        }
      });
    }
  }

  #storeTxt(record, receivedAt) {
    const resolved = this.#resolveInstance(record.name, record.interfaceId, receivedAt);
    const instance = this.#ensureInstance({ ...resolved, interfaceId: record.interfaceId, at: receivedAt });
    const previous = instance.txt;
    instance.txt = mergeRecord(instance.txt, record);
    instance.lastSeenAt = Math.max(instance.lastSeenAt, receivedAt);
    const changed = !previous || txtKey(previous) !== txtKey(record);
    if (changed) {
      this.#pushEvent({
        at: receivedAt,
        type: 'txt-changed',
        interfaceId: record.interfaceId,
        serviceType: instance.serviceType,
        instance: instance.instanceName,
        detail: { attributes: txtAttributes(record.data.strings), packetId: record.packetId }
      });
    }
  }

  #storeAddress(record, receivedAt) {
    const host = this.#ensureHost(record.name, record.interfaceId, receivedAt);
    const key = addressKey(record.type, record.data.address);
    const previous = host.addresses.get(key);
    host.addresses.set(key, mergeRecord(previous, record));
    host.lastSeenAt = Math.max(host.lastSeenAt, receivedAt);
    host.emptySince = null;
    if (!previous) {
      this.#pushEvent({
        at: receivedAt,
        type: 'address-added',
        interfaceId: record.interfaceId,
        detail: { host: host.name, address: record.data.address, family: record.typeName, packetId: record.packetId }
      });
    }
  }

  #applyGoodbye(record, receivedAt) {
    switch (record.type) {
      case TYPES.PTR: {
        const instance = this.#existingInstance(record.name, this.#ptrInstanceName(record.name, record.data.target), record.interfaceId);
        if (instance?.ptr) {
          instance.ptr = null;
          instance.withdrawnAt = receivedAt;
          instance.withdrawReason = 'goodbye';
          this.#pushEvent({
            at: receivedAt,
            type: 'instance-withdrawn',
            interfaceId: record.interfaceId,
            serviceType: instance.serviceType,
            instance: instance.instanceName,
            detail: { cause: 'goodbye', packetId: record.packetId, addressStillCached: this.#hasHostAddresses(instance) }
          });
        }
        return;
      }
      case TYPES.SRV: {
        const instance = this.#existingInstanceByName(record.name, record.interfaceId);
        if (instance?.srv && sameRr(instance.srv, record)) {
          instance.srv = null;
          this.#pushEvent({ at: receivedAt, type: 'srv-withdrawn', interfaceId: record.interfaceId, serviceType: instance.serviceType, instance: instance.instanceName, detail: { cause: 'goodbye', packetId: record.packetId } });
        }
        return;
      }
      case TYPES.TXT: {
        const instance = this.#existingInstanceByName(record.name, record.interfaceId);
        if (instance?.txt && sameRr(instance.txt, record)) {
          instance.txt = null;
          this.#pushEvent({ at: receivedAt, type: 'txt-withdrawn', interfaceId: record.interfaceId, serviceType: instance.serviceType, instance: instance.instanceName, detail: { cause: 'goodbye', packetId: record.packetId } });
        }
        return;
      }
      case TYPES.A:
      case TYPES.AAAA: {
        const host = this.#findHost(record.nameLower, record.interfaceId);
        const key = addressKey(record.type, record.data.address);
        if (host?.addresses.has(key)) {
          host.addresses.delete(key);
          if (host.addresses.size === 0) host.emptySince = receivedAt;
          this.#pushEvent({ at: receivedAt, type: 'address-withdrawn', interfaceId: record.interfaceId, detail: { host: host.name, address: record.data.address, family: record.typeName, cause: 'goodbye', packetId: record.packetId } });
        }
        return;
      }
      default: return;
    }
  }

  #dropRrset(interfaceId, parsedRecord, incoming, at, packetId) {
    switch (parsedRecord.type) {
      case TYPES.PTR: {
        const owner = lower(parsedRecord.name);
        for (const instance of this.instances.values()) {
          if (instance.interfaceId !== interfaceId || !instance.ptr) continue;
          if (instance.ptr.nameLower !== owner) continue;
          if (incoming.has(rrIdentity(instance.ptr))) continue;
          this.#withdrawPtr(instance, at, 'cache-flush', packetId);
        }
        return;
      }
      case TYPES.SRV: {
        const owner = lower(parsedRecord.name);
        for (const instance of this.instances.values()) {
          if (instance.interfaceId !== interfaceId || !instance.srv) continue;
          if (instance.srv.nameLower !== owner) continue;
          if (incoming.has(rrIdentity(instance.srv))) continue;
          instance.flushedSrv = instance.srv;
          instance.srv = null;
          this.#pushEvent({ at, type: 'srv-flushed', interfaceId, serviceType: instance.serviceType, instance: instance.instanceName, detail: { cause: 'cache-flush', packetId } });
        }
        return;
      }
      case TYPES.TXT: {
        const owner = lower(parsedRecord.name);
        for (const instance of this.instances.values()) {
          if (instance.interfaceId !== interfaceId || !instance.txt) continue;
          if (instance.txt.nameLower !== owner) continue;
          if (incoming.has(rrIdentity(instance.txt))) continue;
          instance.txt = null;
          this.#pushEvent({ at, type: 'txt-flushed', interfaceId, serviceType: instance.serviceType, instance: instance.instanceName, detail: { cause: 'cache-flush', packetId } });
        }
        return;
      }
      case TYPES.A:
      case TYPES.AAAA: {
        const owner = lower(parsedRecord.name);
        for (const host of this.hosts.values()) {
          if (host.interfaceId !== interfaceId || host.nameLower !== owner) continue;
          for (const [key, existing] of host.addresses) {
            if (existing.type !== parsedRecord.type) continue;
            if (incoming.has(rrIdentity(existing))) continue;
            host.addresses.delete(key);
            this.#pushEvent({ at, type: 'address-flushed', interfaceId, detail: { host: host.name, address: existing.data.address, family: existing.typeName, cause: 'cache-flush', packetId } });
          }
          if (host.addresses.size === 0) host.emptySince = at;
        }
        return;
      }
      default: return;
    }
  }

  #withdrawPtr(instance, at, cause, packetId = null) {
    if (!instance.ptr) return;
    instance.ptr = null;
    instance.withdrawnAt = at;
    instance.withdrawReason = cause;
    this.#pushEvent({
      at,
      type: 'instance-withdrawn',
      interfaceId: instance.interfaceId,
      serviceType: instance.serviceType,
      instance: instance.instanceName,
      detail: { cause, packetId }
    });
  }

  #expireRecord(record, kind, instance) {
    this.#pushEvent({
      at: record.expiresAt,
      type: `${kind.toLowerCase()}-expired`,
      interfaceId: instance.interfaceId,
      serviceType: instance.serviceType,
      instance: instance.instanceName,
      detail: { expiredAt: record.expiresAt, packetId: record.packetId }
    });
  }

  #visible(instance, includeWithdrawn) {
    if (instance.ptr) return true;
    // Withdrawn instances stay out of the default directory, but are kept for
    // audit under includeWithdrawn even when every record was goodbyed.
    if (instance.withdrawnAt !== null) return includeWithdrawn;
    return instance.srv !== null || instance.txt !== null;
  }

  #instanceView(instance, now) {
    const advertised = instance.ptr !== null;
    // Reachability depends on the address still being cached at this instant.
    // Do not sweep here: an expired address must drop out of endpoints even if
    // the caller reads the snapshot before the next explicit sweep.
    const addresses = instance.srv
      ? this.#addressesFor(instance.srv.data.target, instance.interfaceId, now)
      : [];
    const srv = instance.srv ? recordView(instance.srv) : null;
    const missing = [];
    if (!advertised && instance.withdrawnAt === null) {
      missing.push({ dependency: 'ptr', required: true, reason: '尚未收到服务类型 PTR 记录，实例未被通告', since: instance.firstSeenAt });
    }
    if (!instance.srv) {
      missing.push({ dependency: 'srv', required: true, reason: '缺少 SRV 记录，无法确定目标主机和端口', since: instance.firstSeenAt });
    } else if (addresses.length === 0) {
      missing.push({
        dependency: 'address',
        required: true,
        reason: `目标主机 ${instance.srv.data.target} 在接口 ${instance.interfaceId} 上没有有效的同接口 A/AAAA 记录`,
        since: instance.srv.lastSeenAt
      });
    }
    if (!instance.txt) {
      missing.push({ dependency: 'txt', required: false, reason: '尚未收到 TXT 记录，服务属性未知', since: instance.firstSeenAt });
    }

    const endpoints = [];
    if (instance.srv) {
      for (const address of addresses) {
        endpoints.push({
          address: address.data.address,
          family: address.typeName,
          host: instance.srv.data.target,
          port: instance.srv.data.port,
          connectable: advertised,
          reason: advertised ? null : '实例已被 PTR 退出通知撤回，缓存中的地址不再作为可连接端点',
          expiresAt: Math.min(instance.srv.expiresAt, address.expiresAt),
          basis: {
            srv: sourceRef(instance.srv),
            address: sourceRef(address),
            interfaceId: instance.interfaceId
          }
        });
      }
    }

    return {
      key: instance.key,
      serviceType: instance.serviceType,
      instanceName: instance.instanceName,
      label: instance.instanceName.includes('.') ? instance.instanceName.slice(0, instance.instanceName.indexOf('.')) : instance.instanceName,
      interface: {
        id: instance.interfaceId,
        name: this.interfaces.get(instance.interfaceId)?.name ?? instance.interfaceId,
        address: this.interfaces.get(instance.interfaceId)?.address ?? null
      },
      state: instance.withdrawnAt !== null && !advertised
        ? 'withdrawn'
        : missing.some(entry => entry.required) ? 'incomplete' : 'ready',
      advertised,
      withdrawnAt: instance.withdrawnAt,
      withdrawReason: instance.withdrawReason,
      firstSeenAt: instance.firstSeenAt,
      lastSeenAt: instance.lastSeenAt,
      expiresAt: instance.ptr?.expiresAt ?? instance.srv?.expiresAt ?? instance.txt?.expiresAt ?? null,
      service: instance.srv ? {
        target: instance.srv.data.target,
        port: instance.srv.data.port,
        priority: instance.srv.data.priority,
        weight: instance.srv.data.weight,
        ttl: instance.srv.ttl,
        expiresAt: instance.srv.expiresAt,
        source: sourceRef(instance.srv)
      } : null,
      txt: instance.txt ? {
        strings: instance.txt.data.strings.map(value => value.toString('utf8')),
        attributes: txtAttributes(instance.txt.data.strings),
        ttl: instance.txt.ttl,
        expiresAt: instance.txt.expiresAt,
        source: sourceRef(instance.txt)
      } : null,
      target: instance.srv ? {
        host: instance.srv.data.target,
        addresses: addresses.map(address => ({
          address: address.data.address,
          family: address.typeName,
          ttl: address.ttl,
          expiresAt: address.expiresAt,
          source: sourceRef(address)
        }))
      } : null,
      endpoints,
      missing,
      ptr: instance.ptr ? { source: sourceRef(instance.ptr), ttl: instance.ptr.ttl, expiresAt: instance.ptr.expiresAt } : null,
      evidence: {
        interface: { id: instance.interfaceId, name: this.interfaces.get(instance.interfaceId)?.name ?? instance.interfaceId, address: this.interfaces.get(instance.interfaceId)?.address ?? null },
        records: [instance.ptr, instance.srv, instance.txt, ...addresses].filter(Boolean).map(sourceRef)
      }
    };
  }

  #hostView(host, now) {
    const addresses = [...host.addresses.values()].sort((a, b) => a.type - b.type || a.data.address.localeCompare(b.data.address));
    const referenced = [...this.instances.values()].some(instance => instance.srv
      && instance.interfaceId === host.interfaceId
      && lower(instance.srv.data.target) === host.nameLower);
    return {
      name: host.name,
      interface: { id: host.interfaceId, name: this.interfaces.get(host.interfaceId)?.name ?? host.interfaceId, address: this.interfaces.get(host.interfaceId)?.address ?? null },
      firstSeenAt: host.firstSeenAt,
      lastSeenAt: host.lastSeenAt,
      referencedByService: referenced,
      addresses: addresses.map(address => ({
        address: address.data.address,
        family: address.typeName,
        ttl: address.ttl,
        expiresAt: address.expiresAt,
        secondsRemaining: Math.max(0, Math.round((address.expiresAt - now) / 1000)),
        source: sourceRef(address)
      }))
    };
  }

  #duplicates(visible) {
    const groups = new Map();
    for (const instance of visible) {
      if (!instance.advertised) continue;
      const key = `${lower(instance.serviceType)}\0${lower(instance.instanceName)}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(instance);
    }
    return [...groups.values()]
      .filter(group => new Set(group.map(instance => instance.interface.id)).size > 1)
      .map(group => ({
        serviceType: group[0].serviceType,
        instanceName: group[0].instanceName,
        interfaces: group.map(instance => instance.interface),
        note: '同名实例在不同接口独立缓存；端点不会跨接口拼接'
      }));
  }

  #addressesFor(hostName, interfaceId, at = this.clock.now()) {
    const host = this.#findHost(lower(hostName), interfaceId);
    if (!host) return [];
    return [...host.addresses.values()].filter(address => address.expiresAt > at);
  }

  #hasHostAddresses(instance) {
    return instance.srv ? this.#addressesFor(instance.srv.data.target, instance.interfaceId).length > 0 : false;
  }

  #resolveInstance(fullName, interfaceId, at) {
    const normalized = lower(fullName);
    let best = null;
    for (const service of this.services.values()) {
      if (service.interfaceId !== interfaceId) continue;
      const suffix = lower(service.serviceType);
      if (!suffix) continue;
      if (normalized === suffix) continue;
      if (normalized.endsWith(`.${suffix}`) && (!best || suffix.length > lower(best.serviceType).length)) best = service;
      if (service.typeNames) {
        for (const typeName of service.typeNames) {
          const typeLower = lower(typeName);
          if (typeLower && normalized.endsWith(`.${typeLower}`) && (!best || typeLower.length > lower(best.serviceType).length)) {
            best = { serviceType: typeName, interfaceId: service.interfaceId };
          }
        }
      }
    }
    if (best) {
      const serviceType = best.serviceType;
      const instanceName = fullName.slice(0, fullName.length - serviceType.length - 1);
      return { serviceType, instanceName };
    }
    const labels = fullName.split('.');
    const firstServiceLabel = labels.findIndex(label => label.startsWith('_'));
    if (firstServiceLabel > 0) {
      return {
        serviceType: labels.slice(firstServiceLabel).join('.'),
        instanceName: labels.slice(0, firstServiceLabel).join('.')
      };
    }
    const dot = fullName.indexOf('.');
    if (dot > 0) return { serviceType: fullName.slice(dot + 1), instanceName: fullName.slice(0, dot) };
    return { serviceType: '', instanceName: fullName };
  }

  #ensureInstance({ serviceType, instanceName, interfaceId, at }) {
    const key = `${interfaceId}\0${lower(serviceType)}\0${lower(instanceName)}`;
    let instance = this.instances.get(key);
    if (!instance) {
      instance = {
        key,
        serviceType: serviceType || '',
        instanceName: instanceName || '',
        interfaceId,
        ptr: null,
        srv: null,
        txt: null,
        firstSeenAt: at,
        lastSeenAt: at,
        withdrawnAt: null,
        withdrawReason: null
      };
      this.instances.set(key, instance);
    }
    const serviceKey = `${lower(serviceType)}\0${interfaceId}`;
    if (!this.services.has(serviceKey)) {
      this.services.set(serviceKey, { serviceType: serviceType || '', interfaceId, typeNames: serviceType ? [serviceType] : [] });
    }
    return instance;
  }

  #existingInstance(serviceType, instanceName, interfaceId) {
    return this.instances.get(`${interfaceId}\0${lower(serviceType)}\0${lower(instanceName)}`) ?? null;
  }

  #existingInstanceByName(fullName, interfaceId) {
    const { serviceType, instanceName } = this.#resolveInstance(fullName, interfaceId, this.clock.now());
    return this.#existingInstance(serviceType, instanceName, interfaceId);
  }

  /** PTR RDATA is the full instance name; use the PTR owner as its service type. */
  #ptrInstanceName(serviceType, target) {
    const suffix = lower(serviceType);
    if (target && lower(target).endsWith(`.${suffix}`)) {
      return target.slice(0, target.length - serviceType.length - 1);
    }
    const resolved = this.#resolveInstance(target, null, this.clock.now());
    return resolved.instanceName;
  }

  #ensureHost(name, interfaceId, at) {
    const key = `${interfaceId}\0${lower(name)}`;
    let host = this.hosts.get(key);
    if (!host) {
      host = {
        key,
        name: name || '',
        nameLower: lower(name),
        interfaceId,
        addresses: new Map(),
        firstSeenAt: at,
        lastSeenAt: at,
        emptySince: null
      };
      this.hosts.set(key, host);
    }
    return host;
  }

  #findHost(nameLower, interfaceId) {
    return this.hosts.get(`${interfaceId}\0${nameLower}`) ?? null;
  }

  #interfaceFor(observation, at) {
    const raw = observation?.interface ?? {};
    const id = observation?.interfaceId ?? raw.id ?? raw.name ?? observation?.interfaceName
      ?? observation?.sourceAddress ?? `${observation?.interfaceAddress ?? 'local'}`;
    const name = observation?.interfaceName ?? raw.name ?? observation?.interfaceId ?? id;
    const address = observation?.interfaceAddress ?? raw.address ?? observation?.sourceAddress ?? null;
    let entry = this.interfaces.get(id);
    if (!entry) {
      entry = { id, name, address, firstSeenAt: at, lastSeenAt: at, packets: 0 };
      this.interfaces.set(id, entry);
    }
    entry.lastSeenAt = Math.max(entry.lastSeenAt, at);
    entry.packets += 1;
    if (address && !entry.address) entry.address = address;
    return entry;
  }

  #recordReject(rejected, { packetId, digest, packetEntry, interfaceInfo, receivedAt }) {
    const entry = {
      packetId,
      packetDigest: digest,
      interfaceId: interfaceInfo.id,
      interfaceName: interfaceInfo.name,
      source: packetEntry.source,
      capturedAt: receivedAt,
      scope: rejected.scope ?? 'packet',
      sectionIndex: rejected.sectionIndex ?? null,
      code: rejected.code ?? 'REJECTED',
      reason: rejected.reason ?? '报文无法解析',
      offset: rejected.offset ?? null
    };
    this.rejects.push(entry);
    if (this.rejects.length > REJECT_LIMIT) this.rejects.shift();
    this.#pushEvent({ at: receivedAt, type: 'packet-rejected', packetId, interfaceId: interfaceInfo.id, detail: { code: entry.code, reason: entry.reason, offset: entry.offset } });
  }

  #pushEvent(event) {
    this.events.push(event);
    if (this.events.length > EVENT_LIMIT) this.events.shift();
  }

  #trimPackets() {
    while (this.packets.length > PACKET_LIMIT) this.packets.shift();
  }
}

function errorReject(error) {
  return {
    scope: 'packet',
    code: error?.code ?? 'PACKET_REJECTED',
    reason: error?.reason ?? error?.message ?? '报文无法解析',
    offset: Number.isInteger(error?.offset) ? error.offset : null
  };
}

function rrIdentity(record) {
  switch (record.type) {
    case TYPES.PTR: return `ptr|${lower(record.data.target)}`;
    case TYPES.SRV: return `srv|${lower(record.data.target)}|${record.data.port}|${record.data.priority}|${record.data.weight}`;
    case TYPES.TXT: return `txt|${txtKey(record)}`;
    case TYPES.A:
    case TYPES.AAAA: return `${record.type}|${record.data.address}`;
    default: return `${record.type}|${record.nameLower}`;
  }
}

function sameRr(a, b) {
  return rrIdentity(a) === rrIdentity(b);
}

function mergeRecord(existing, incoming) {
  if (!existing) {
    return { ...incoming, data: cloneData(incoming.data), firstSeenAt: incoming.capturedAt, lastSeenAt: incoming.capturedAt, refreshCount: 0 };
  }
  return {
    ...existing,
    ...incoming,
    data: cloneData(incoming.data),
    firstSeenAt: existing.firstSeenAt,
    refreshCount: existing.refreshCount + 1
  };
}

function cloneData(data) {
  if (!data) return data;
  if (data.strings) return { ...data, strings: data.strings.map(value => Buffer.from(value)) };
  return { ...data };
}

function cloneRecord(record) {
  return { ...record, data: cloneData(record.data) };
}

function addressKey(type, address) {
  return `${type}|${address}`;
}

function txtKey(record) {
  return record.data.strings.map(value => value.toString('hex')).join('\0');
}

function txtAttributes(strings) {
  const attributes = {};
  for (const buffer of strings) {
    const text = Buffer.isBuffer(buffer) ? buffer.toString('utf8') : String(buffer);
    const index = text.indexOf('=');
    if (index === -1) attributes[text] = true;
    else attributes[text.slice(0, index)] = text.slice(index + 1);
  }
  return attributes;
}

function recordView(record) {
  return {
    ttl: record.ttl,
    expiresAt: record.expiresAt,
    firstSeenAt: record.firstSeenAt,
    lastSeenAt: record.lastSeenAt,
    refreshCount: record.refreshCount,
    source: sourceRef(record)
  };
}

function sourceRef(record) {
  return {
    packetId: record.packetId,
    packetDigest: record.packetDigest,
    capturedAt: record.capturedAt,
    interfaceId: record.interfaceId,
    section: record.section,
    offset: record.offset,
    rdataOffset: record.rdataStart,
    rdataLength: record.rdataEnd - record.rdataStart
  };
}
