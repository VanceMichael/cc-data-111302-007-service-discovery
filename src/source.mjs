import http from 'node:http';
import { readFile } from 'node:fs/promises';
import dgram from 'node:dgram';
import { announcement, addressText } from './discovery.mjs';
import { createClock } from './clock.mjs';
import { createDirectory } from './directory.mjs';
import { createReceiver } from './receiver.mjs';
import { loadSnapshot, saveSnapshot, attachPersistence } from './persist.mjs';

export function json(response, value, status = 200) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(value));
}

function interfaceOf(value, fallback) {
  if (value && typeof value === 'object') return { id: value.id ?? value.name ?? fallback, name: value.name ?? value.id ?? fallback, address: value.address ?? null };
  return { id: value ?? fallback, name: value ?? fallback, address: null };
}

/**
 * Fixtures may describe a single device (legacy fields) or a small fleet with
 * `emitters`. Each emitter is sent from its own loopback source address so the
 * receiver can attribute the packet to an interface.
 */
export function emittersOf(state) {
  if (Array.isArray(state.emitters) && state.emitters.length > 0) {
    return state.emitters.map((emitter, index) => {
      const iface = interfaceOf(emitter.interface, emitter.id ?? `if${index}`);
      return {
        ...emitter,
        id: emitter.id ?? iface.id ?? `if${index}`,
        interface: iface,
        source: emitter.source ?? `127.0.0.${index + 1}`
      };
    });
  }
  const iface = interfaceOf(state.interface, 'local');
  // Only identity travels with the single fixture emitter; device values stay
  // taken from `state` so /control updates still apply.
  return [{
    id: iface.id,
    interface: iface,
    source: state.source ?? '127.0.0.1'
  }];
}

export async function createSource({ port = 0, host = '127.0.0.1', fixture, clock, clockMode, startTime, statePath, receive = true, persistIntervalMs = 0, captureRaw = false, receiverHost = '127.0.0.1', interfaces } = {}) {
  const state = fixture ? structuredClone(fixture) : JSON.parse(await readFile(new URL('../fixtures/source.json', import.meta.url), 'utf8'));
  const mode = clockMode ?? process.env.CLOCK ?? state.clock?.mode ?? 'replay';
  const directoryClock = clock ?? createClock({
    now: startTime ?? state.clock?.start ?? (mode === 'real' ? Date.now() : 0),
    real: mode === 'real'
  });

  const emitters = emittersOf(state);
  // `interfaces` lets a replay caller pin interface identity per source
  // address; otherwise each emitter's own description is used.
  const interfaceMap = { ...(interfaces ?? {}) };
  for (const emitter of emitters) {
    interfaceMap[emitter.source] = interfaceMap[emitter.source] ?? {
      id: emitter.interface.id,
      name: emitter.interface.name,
      address: emitter.interface.address ?? null
    };
  }

  const directory = createDirectory({ clock: directoryClock, captureRaw });
  const snapshotPath = statePath ?? process.env.STATE_PATH ?? state.persistence?.path ?? null;

  if (snapshotPath) {
    const saved = await loadSnapshot(snapshotPath);
    if (saved && !saved.invalid && saved.version === 1) {
      // A replayed clock starts at zero again; jump to the save point so an
      // absolute expiry is never mistaken for a fresh lifetime.
      if (!directoryClock.real && Number.isFinite(saved.savedAt) && saved.savedAt > directoryClock.now()) {
        directoryClock.advance(saved.savedAt - directoryClock.now());
      }
      directory.restore(saved);
    } else if (saved?.invalid) {
      directory.recordSystemEvent('state-load-rejected', { reason: saved.reason ?? '状态文件不可读' });
    }
  }

  const receiver = receive ? await createReceiver({
    host: receiverHost,
    clock: directoryClock,
    interfaces: interfaceMap
  }) : null;
  if (receiver) receiver.onMessage(observation => directory.ingest(observation));

  const senders = new Map();
  async function senderFor(bindAddress) {
    if (senders.has(bindAddress)) return senders.get(bindAddress);
    const socket = dgram.createSocket('udp4');
    await new Promise((resolve, reject) => {
      socket.once('error', reject);
      socket.bind(0, bindAddress, () => { socket.off('error', reject); resolve(); });
    });
    senders.set(bindAddress, socket);
    return socket;
  }
  function send(socket, packet, targetPort) {
    return new Promise((resolve, reject) => socket.send(packet, targetPort, '127.0.0.1', error => error ? reject(error) : resolve()));
  }

  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://local.test');
      let text = '';
      for await (const chunk of request) {
        text += chunk;
        if (text.length > 8 * 1024 * 1024) { json(response, { error: '控制请求过大' }, 413); return; }
      }
      let body = {};
      if (text) { try { body = JSON.parse(text); } catch { return json(response, { error: 'JSON无效' }, 400); } }

      if (url.pathname === '/health') return json(response, { status: 'ok' });
      if (url.pathname === '/state' || url.pathname === '/inventory') return json(response, state);
      if (url.pathname === '/control' && request.method === 'POST') { Object.assign(state, body); return json(response, state); }
      if (url.pathname === '/receiver') {
        return json(response, receiver ? { address: receiver.address, port: receiver.port, url: receiver.url } : { status: '未启用接收' });
      }
      if (url.pathname === '/directory') {
        return json(response, directory.snapshot({ includeWithdrawn: url.searchParams.get('includeWithdrawn') === '1' }));
      }
      if (url.pathname === '/events') {
        const since = url.searchParams.has('since') ? Number(url.searchParams.get('since')) : null;
        const events = directory.changes({ since });
        const limit = Number(url.searchParams.get('limit') ?? 0);
        return json(response, { now: directoryClock.now(), events: limit > 0 ? events.slice(-limit) : events });
      }
      if (url.pathname === '/advance' && request.method === 'POST') {
        if (directoryClock.real) return json(response, { error: '真实时钟模式不能手动推进，改用 CLOCK=replay' }, 409);
        if (!Number.isFinite(body.ms) || body.ms < 0) return json(response, { error: '推进时长无效' }, 400);
        const since = Number.isFinite(body.since) ? body.since : null;
        const now = directory.advance(body.ms);
        return json(response, { now: now.now, clock: now.clock, events: since === null ? now.recentChanges : directory.changes({ since }) });
      }
      if (url.pathname === '/receive' && request.method === 'POST') {
        const bytes = body.hex ? Buffer.from(body.hex, 'hex') : body.base64 ? Buffer.from(body.base64, 'base64') : null;
        if (!bytes) return json(response, { error: '需要 hex 或 base64 报文' }, 400);
        const entry = directory.ingest({
          packet: bytes,
          capturedAt: Number.isFinite(body.capturedAt) ? body.capturedAt : directoryClock.now(),
          interfaceId: body.interfaceId,
          interfaceName: body.interfaceName,
          interfaceAddress: body.interfaceAddress,
          sourceAddress: body.sourceAddress,
          sourcePort: body.sourcePort,
          packetId: body.packetId
        });
        return json(response, { packet: entry, rejects: directory.snapshot().rejects.slice(-5) });
      }
      if (url.pathname === '/snapshot') return json(response, directory.serialize());
      if (url.pathname === '/save' && request.method === 'POST') {
        if (!snapshotPath) return json(response, { error: '未配置状态路径' }, 400);
        await saveSnapshot(snapshotPath, directory.serialize());
        return json(response, { savedAt: directoryClock.now(), path: snapshotPath });
      }
      if (url.pathname === '/emit' && request.method === 'POST') {
        const emitter = emitters.find(entry => entry.id === (body.id ?? emitters[0].id)) ?? emitters[0];
        const targetPort = body.port ?? receiver?.port;
        if (!Number.isInteger(targetPort) || targetPort < 1024 || targetPort > 65535) return json(response, { error: '接收端口无效' }, 400);
        const overrides = { ...body };
        delete overrides.port;
        delete overrides.id;
        const packet = announcement(state, emitter, overrides);
        const socket = await senderFor(emitter.source);
        await send(socket, packet, targetPort);
        return json(response, {
          bytes: packet.length,
          interface: emitter.interface.id,
          source: emitter.source,
          receiver: receiver?.port ?? null,
          emitter: emitter.id
        });
      }
      return json(response, { error: '资源不存在' }, 404);
    } catch (error) {
      if (!response.headersSent) json(response, { error: error.message }, 500);
      else response.destroy();
    }
  });

  await new Promise(resolve => server.listen(port, host, resolve));
  const persistence = attachPersistence(directory, snapshotPath, persistIntervalMs);
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    state,
    directory,
    parser: directory,
    clock: directoryClock,
    receiver,
    emitters,
    interfaceMap,
    snapshot: options => directory.snapshot(options),
    save: async () => { await persistence.save(); },
    close: async () => {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
      await persistence.stop();
      if (snapshotPath) await saveSnapshot(snapshotPath, directory.serialize());
      if (receiver) await receiver.close();
      for (const socket of senders.values()) await new Promise(resolve => socket.close(resolve));
    }
  };
}
