import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDirectory } from '../src/directory.mjs';
import { manualClock } from '../src/clock.mjs';
import { loadSnapshot, saveSnapshot, attachPersistence } from '../src/persist.mjs';
import { fullAnnouncement } from './helpers/packets.mjs';

async function tempState() {
  const dir = await mkdtemp(join(tmpdir(), 'sd-state-'));
  return join(dir, 'state.json');
}

test('状态文件以原子方式写入，读取不存在或损坏的路径有明确结果', async () => {
  const path = await tempState();
  assert.equal(await loadSnapshot(path), null);
  await writeFile(path, '{not json');
  assert.equal((await loadSnapshot(path)).invalid, true);
  await saveSnapshot(path, { version: 1, savedAt: 5 });
  assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), { version: 1, savedAt: 5 });
});

test('保存与恢复保留绝对过期时间，恢复时丢弃已经过期的记录', () => {
  const clock = manualClock(0);
  const directory = createDirectory({ clock });
  directory.ingest({ packet: fullAnnouncement({ ttl: 60 }), interfaceId: 'if-a', capturedAt: 0 });
  clock.advance(20_000);
  const saved = directory.serialize();
  assert.equal(saved.savedAt, 20_000);
  assert.equal(saved.instances[0].ptr.expiresAt, 60_000);

  const freshClock = manualClock(20_000);
  const fresh = createDirectory({ clock: freshClock });
  const result = fresh.restore(saved);
  assert.equal(result.dropped, 0);
  assert.equal(fresh.snapshot().services[0].instances[0].expiresAt, 60_000);

  const laterClock = manualClock(61_000);
  const later = createDirectory({ clock: laterClock });
  const dropped = later.restore(saved);
  assert.ok(dropped.dropped > 0);
  assert.equal(later.snapshot().services.length, 0);
});

test('周期持久化可以由 close 排空，不会在关闭后继续写', async () => {
  const path = await tempState();
  const clock = manualClock(0);
  const directory = createDirectory({ clock });
  directory.ingest({ packet: fullAnnouncement({ ttl: 60 }), interfaceId: 'if-a', capturedAt: 0 });
  const persistence = attachPersistence(directory, path, 10);
  await persistence.save();
  await persistence.stop();
  const saved = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(saved.instances.length, 1);
  assert.equal(saved.instances[0].interfaceId, 'if-a');
});
