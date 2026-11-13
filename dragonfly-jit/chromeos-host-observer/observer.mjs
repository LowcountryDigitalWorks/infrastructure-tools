// Source-only ChromeOS browser host-memory proof. No JIT admission, storage, network or privileged host control.
export const MARKER = 'LDW_REDRIX_CHROMEOS_HOST_MEMORY_V1';
export const SAMPLE_COUNT = 5;
export const SAMPLE_INTERVAL_MS = 1000;
const MAX_REASONABLE_CAPACITY_BYTES = 2 ** 48;
const MAX_CAPTURE_ELAPSED_MS = 15000;
const MIB = 1024 * 1024;

function checkedTime(value) {
  if (!(value instanceof Date) || !Number.isFinite(value.valueOf())) throw Error('CLOCK_UNAVAILABLE');
  return value.valueOf();
}

export function normalizeHostMemory(info, when) {
  if (!info || typeof info !== 'object' || Array.isArray(info)) throw Error('MEMORY_DATA_INVALID');
  const { capacity, availableCapacity } = info;
  if (!Number.isSafeInteger(capacity) || !Number.isSafeInteger(availableCapacity)
      || capacity <= 0 || capacity > MAX_REASONABLE_CAPACITY_BYTES
      || availableCapacity < 0 || availableCapacity > capacity) {
    throw Error('MEMORY_DATA_INVALID');
  }
  const timestamp = checkedTime(when);
  return Object.freeze({
    observed_at_utc: new Date(timestamp).toISOString(),
    host_total_mib: Math.floor(capacity / MIB),
    host_available_mib: Math.floor(availableCapacity / MIB),
  });
}

export async function observeHostMemory({ getInfo, now = () => new Date(), pause = ms => new Promise(resolve => setTimeout(resolve, ms)) },
                                         count = SAMPLE_COUNT, intervalMs = SAMPLE_INTERVAL_MS) {
  if (typeof getInfo !== 'function' || typeof now !== 'function' || typeof pause !== 'function'
      || !Number.isInteger(count) || count < 3 || count > 6
      || !Number.isInteger(intervalMs) || intervalMs < 0 || intervalMs > 5000) {
    throw Error('OBSERVER_CONFIG_INVALID');
  }
  const start = checkedTime(now());
  const samples = [];
  for (let i = 0; i < count; i++) {
    // chrome.system.memory.getInfo() is a read-only provider API; never query Linux/container memory here.
    const result = await getInfo();
    const reading = normalizeHostMemory(result, now());
    if (Date.parse(reading.observed_at_utc) < start ||
        (i > 0 && Date.parse(reading.observed_at_utc) < Date.parse(samples[i - 1].observed_at_utc))) {
      throw Error('CLOCK_UNRELIABLE');
    }
    samples.push(reading);
    if (i + 1 < count) await pause(intervalMs);
  }
  const elapsed = Date.parse(samples.at(-1).observed_at_utc) - start;
  if (elapsed < 0 || elapsed > MAX_CAPTURE_ELAPSED_MS) throw Error('CLOCK_UNRELIABLE');
  if (samples.some(x => x.host_total_mib !== samples[0].host_total_mib)) throw Error('CAPACITY_CHANGED');
  return {
    schema: 1,
    marker: MARKER,
    mode: 'OBSERVE_ONLY',
    source: 'CHROME_SYSTEM_MEMORY_API',
    memory_sample_scope: 'CHROMEOS_BROWSER_HOST_PHYSICAL',
    capture_clock_source: 'BROWSER_WALLCLOCK_UNATTESTED',
    capture_started_utc: new Date(start).toISOString(),
    capture_finished_utc: samples.at(-1).observed_at_utc,
    capture_elapsed_ms: elapsed,
    sample_count: samples.length,
    host_min_available_mib: Math.min(...samples.map(s => s.host_available_mib)),
    samples,
    classification: 'HOST_REPORTED_NOT_ATTESTED',
    crostini_guest_corroboration: 'NOT_COLLECTED_BY_THIS_EXTENSION',
    nested_guest_peak: 'UNMEASURED',
    ci_dispatch_authorized: false,
    jit_admission_authorized: false,
    memory_policy_change_authorized: false,
  };
}
