import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

/** Atomic JSON persistence. The directory itself never waits on the clock. */
export async function loadSnapshot(path) {
  if (!path) return null;
  try {
    const text = await readFile(path, 'utf8');
    return JSON.parse(text);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error instanceof SyntaxError) return { invalid: true, reason: '状态文件不是有效 JSON' };
    throw error;
  }
}

export async function saveSnapshot(path, value) {
  if (!path) return;
  const target = path;
  await mkdir(dirname(target), { recursive: true });
  const temporary = `${target}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify(value, null, 2), 'utf8');
  await rename(temporary, target);
}

export function attachPersistence(directory, path, intervalMs = 0) {
  if (!path) return { save: async () => {}, stop: () => {} };
  let inFlight = null;
  const save = () => {
    inFlight = saveSnapshot(path, directory.serialize()).catch(error => {
      console.error(JSON.stringify({ status: '状态写入失败', error: error.message }));
    });
    return inFlight;
  };
  const timer = intervalMs > 0 ? setInterval(save, intervalMs) : null;
  timer?.unref?.();
  return {
    save,
    stop: () => { if (timer) clearInterval(timer); return inFlight ?? Promise.resolve(); }
  };
}
