import { performance } from 'node:perf_hooks';

/**
 * A single advancing clock for the directory. Timestamps are milliseconds.
 * `real` can also be advanced manually, so offline replay never waits.
 */
export function createClock({ now, real = false } = {}) {
  const initial = Number.isFinite(now) ? now : real ? Date.now() : 0;
  let current = initial;
  let generation = 0;
  const listeners = new Set();
  const clock = {
    get real() { return real; },
    now() { return real ? Date.now() : current; },
    get generation() { return generation; },
    /** Move forward. A backward jump would make expiry arithmetic unsound. */
    advance(milliseconds) {
      const step = Number(milliseconds);
      if (real) throw new Error('真实时钟不接受手动推进');
      if (!Number.isFinite(step) || step < 0) throw new Error('时钟只能向前推进');
      if (step === 0) return current;
      current += step;
      generation += 1;
      for (const listener of listeners) listener(current, generation);
      return current;
    },
    /** Wait for real time in a `real` clock; a no-op in replay mode. */
    async wait(milliseconds) {
      if (real) await new Promise(resolve => setTimeout(resolve, milliseconds));
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    }
  };
  return clock;
}

export function realClock(start = Date.now()) {
  return createClock({ now: start, real: true });
}

/**
 * A replayed clock whose `now` only changes through `advance`. This keeps
 * tests and offline analysis deterministic while real receipt still records
 * observation order.
 */
export function manualClock(start = 0) {
  return createClock({ now: start, real: false });
}

export function nowPerformance() {
  return performance.now();
}
