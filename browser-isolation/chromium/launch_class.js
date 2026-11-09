"use strict";
/* Fixed vocabulary for an actual Playwright Chromium launch failure.
 * Membership tests only. Never return raw stderr, argv, paths, or URLs.
 * A token is a NO_START reason, never permission to start or weaken policy.
 */
const ACTUAL_LAUNCH_SIGNATURES = Object.freeze([
  ["NO_USABLE_SANDBOX", "no usable sandbox"],
  ["NAMESPACE_DENIED", "failed to move to new namespace"],
  ["OPERATION_DENIED", "operation not permitted"],
  ["PERMISSION_DENIED", "permission denied"],
  ["READ_ONLY_FILESYSTEM", "read-only file system"],
  ["SHARED_LIBRARY", "error while loading shared libraries"],
  ["ZYGOTE_LAUNCH_FAILED", "failed to launch zygote process"],
  ["ZYGOTE_INVALID_BOOT_PID", "received invalid process id for zygote"],
  ["ZYGOTE_FORK_FAILED", "failed to fork zygote"],
  // Current zygote_host_impl_linux.cc startup lines. Checked before the
  // filename so a log prefix cannot hide the phase. Parentheses are part
  // of Chromium's own premature-exit text.
  ["ZYGOTE_PREMATURE_EXIT_NAMESPACE", "(namespace sandbox)"],
  ["ZYGOTE_PREMATURE_EXIT_SETUID", "(setuid sandbox"],
  ["ZYGOTE_BOOT_MESSAGE_MISSING", "failed to receive boot message from zygote"],
  ["ZYGOTE_HELLO_MESSAGE_MISSING", "failed to receive hello message from zygote"],
  ["ZYGOTE_PREMATURE_EXIT", "zygote process exited prematurely"],
  ["ZYGOTE_HOST", "zygote_host_impl_linux.cc"],
  ["ZYGOTE_MAIN", "zygote_main_linux.cc"],
  ["ZYGOTE_COMMUNICATION", "zygote_communication_linux.cc"],
  ["ZYGOTE", "zygote"],
  ["SECCOMP", "seccomp"],
  ["CHROME_SANDBOX_HELPER", "chrome-sandbox"],
  ["PARENT_CLOSED", "target page, context or browser has been closed"],
]);

function classifyActualLaunchFailure(message) {
  const raw = String(message == null ? "" : message).toLowerCase();
  for (const [category, needle] of ACTUAL_LAUNCH_SIGNATURES) {
    if (raw.includes(needle)) return "GUEST_BROWSER_LAUNCH_ACTUAL_" + category;
  }
  return "GUEST_BROWSER_LAUNCH_ACTUAL_UNKNOWN";
}

module.exports = { classifyActualLaunchFailure, ACTUAL_LAUNCH_SIGNATURES };
