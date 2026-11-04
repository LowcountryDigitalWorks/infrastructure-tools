"""Static contract only. Hosted Docker+Chromium is the actual network proof."""
import unittest
from host_proof import command, verify_guest, verified_seccomp_path, BoundaryError, VECTORS


class RealBrowserGuestGateTests(unittest.TestCase):
    image = "sha256:" + "a" * 64
    def test_isolated_exact_image_command(self):
        args = command("/usr/bin/docker", self.image, "172.17.0.1", 32001)
        for flag in ("--pull=never", "--network=none", "--read-only",
                     "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
                     "--user=10001:10001", "--ipc=private"):
            self.assertIn(flag, args)
        self.assertIn("--security-opt=seccomp=" + verified_seccomp_path(), args)
        for flag in ("--privileged", "--network=host", "--ipc=host",
                     "--pid=host", "--cap-add", "--mount", "--volume"):
            self.assertNotIn(flag, args)
        self.assertFalse(any(s.startswith("--pid=") for s in args))
        self.assertNotIn("--security-opt=seccomp=unconfined", args)
        self.assertEqual(args[-4:], [self.image, "--probe", "172.17.0.1", "32001"])

    def test_mutable_tag_or_changed_port_refused(self):
        for image in ("mcr.microsoft.com/playwright:latest", "sha256:x",
                      "sha256:" + "g" * 64):
            with self.subTest(image=image), self.assertRaises(BoundaryError):
                command("/usr/bin/docker", image, "172.17.0.1", 32001)
        for port in (0, 65536, -1, False):
            with self.subTest(port=port), self.assertRaises(BoundaryError):
                command("/usr/bin/docker", self.image, "172.17.0.1", port)

    def test_no_start_phase_is_sanitized(self):
        for phase in ("GUEST_BROWSER_LAUNCH_ERROR", "GUEST_LOCAL_NAVIGATION_ERROR",
                      "GUEST_SERVICE_WORKER_ERROR"):
            with self.assertRaises(BoundaryError) as caught:
                verify_guest({"result": "NO_START", "reason": phase}, 1)
            self.assertEqual(str(caught.exception), "CHROMIUM_NO_START_" + phase)
        with self.assertRaises(BoundaryError) as caught:
            verify_guest({"result": "NO_START", "reason": "secret /home/runner/.env"}, 1)
        self.assertEqual(str(caught.exception), "CHROMIUM_NO_START_UNCLASSIFIED")

    def test_guest_proof_must_reject_skipped_vectors(self):
        valid = {
            "result":"PASS", "local_chromium":"PASS", "interactions":"PASS",
            "vectors": VECTORS, "redirect":"BLOCKED", "direct_tcp":"BLOCKED",
            "sandbox_requested":True, "source":"SYNTHETIC_GUEST_ONLY",
        }
        verify_guest(valid, 0)
        for altered in (
            {**valid, "vectors": VECTORS[:-1]},
            {**valid, "vectors": []},
            {**valid, "redirect": "ALLOWED"},
            {**valid, "sandbox_requested": False},
            {**valid, "extra": "attacker"},
            {**valid, "local_chromium": "SKIPPED"},
        ):
            with self.assertRaises(BoundaryError):
                verify_guest(altered, 0)
        with self.assertRaises(BoundaryError):
            verify_guest(valid, 1)


if __name__ == "__main__":
    unittest.main()
