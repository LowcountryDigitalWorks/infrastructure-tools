import { observeHostMemory } from './observer.mjs';

const run = document.getElementById('run');
const status = document.getElementById('status');
const output = document.getElementById('output');
const theme = document.getElementById('theme');

theme.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  theme.textContent = next === 'dark' ? 'Light mode' : 'Dark mode';
});

run.addEventListener('click', async () => {
  run.disabled = true;
  output.value = '';
  status.textContent = 'Measuring host memory…';
  try {
    if (!globalThis.chrome?.system?.memory?.getInfo) throw Error('API_UNAVAILABLE');
    const result = await observeHostMemory({
      getInfo: () => globalThis.chrome.system.memory.getInfo(),
    });
    output.value = JSON.stringify(result, null, 2);
    status.textContent = 'Observed minimum: ' + result.host_min_available_mib
      + ' MiB (host only; not JIT authority).';
  } catch (err) {
    const reason = err instanceof Error && /^[A-Z_]+$/.test(err.message)
      ? err.message : 'COLLECTION_FAILED';
    output.value = JSON.stringify({
      marker: 'LDW_REDRIX_CHROMEOS_HOST_MEMORY_V1', classification: 'HOLD',
      reason, ci_dispatch_authorized: false, jit_admission_authorized: false,
    }, null, 2);
    status.textContent = 'Reading unavailable. No host or guest action performed.';
  } finally {
    run.disabled = false;
  }
});
