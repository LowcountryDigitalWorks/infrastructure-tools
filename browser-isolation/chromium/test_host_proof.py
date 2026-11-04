"""Static contract only. Hosted Docker+Chromium is the actual network proof."""
import unittest
import contextlib
import io
from unittest.mock import patch
import subprocess
from host_proof import (command, verify_guest, verified_seccomp_path,
    BoundaryError, VECTORS, guarded_container_cleanup, run_bound_guest,
    host_policy_readback, clone3_invalid_argument_precheck,
    clone_newuser_precheck)


class RealBrowserGuestGateTests(unittest.TestCase):
    image = "sha256:" + "a" * 64
    nonce = "b" * 24
    name = "ldw-chromium-proof-" + nonce
    def test_isolated_exact_image_command(self):
        args = command("/usr/bin/docker", self.image, "172.17.0.1", 32001, nonce=self.nonce)
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
                command("/usr/bin/docker", image, "172.17.0.1", 32001, nonce=self.nonce)
        for port in (0, 65536, -1, False):
            with self.subTest(port=port), self.assertRaises(BoundaryError):
                command("/usr/bin/docker", self.image, "172.17.0.1", port, nonce=self.nonce)

    def test_trusted_synthetic_is_explicit_not_strict_acceptance(self):
        args = command("/usr/bin/docker", self.image, "172.17.0.1", 32001, True, nonce=self.nonce)
        self.assertEqual(args[-5:], [self.image, "--probe", "172.17.0.1", "32001",
                                     "--trusted-synthetic-only"])
        self.assertIn("--network=none", args)
        self.assertIn("--cap-drop=ALL", args)
        with self.assertRaises(BoundaryError):
            command("/usr/bin/docker", self.image, "172.17.0.1", 32001, "true", nonce=self.nonce)
        synthetic = {
            "result":"PASS", "local_chromium":"PASS", "interactions":"PASS",
            "vectors": VECTORS, "redirect":"BLOCKED", "direct_tcp":"BLOCKED",
            "sandbox_requested":False, "source":"TRUSTED_SYNTHETIC_NO_CHROMIUM_SANDBOX",
        }
        verify_guest(synthetic, 0, True)
        with self.assertRaises(BoundaryError):
            verify_guest(synthetic, 0, False)

    def test_host_security_readback_only_fixed_statuses(self):
        sink = io.StringIO()
        with patch("host_proof.pathlib.Path.read_text",
                   side_effect=["Y", "1", "0"]):
            with contextlib.redirect_stdout(sink):
                host_policy_readback()
        value = sink.getvalue()
        self.assertIn("HOST_APPARMOR_MODULE=ENABLED", value)
        self.assertIn("HOST_APPARMOR_RESTRICT_UNPRIV_USERNS=ENABLED", value)
        self.assertIn("HOST_UNPRIV_USERNS_CLONE=DISABLED", value)
        self.assertNotIn("/proc/", value)
        unknown = io.StringIO()
        with patch("host_proof.pathlib.Path.read_text",
                   side_effect=OSError("secret hidden path")):
            with contextlib.redirect_stdout(unknown):
                host_policy_readback()
        self.assertEqual(unknown.getvalue().count("UNAVAILABLE"), 3)
        self.assertNotIn("secret", unknown.getvalue())

    def test_clone3_invalid_argument_readback_is_immutable_and_redacted(self):
        valid = subprocess.CompletedProcess([], 0, stdout="DENIED_EPERM\n",
                                            stderr="secret private path")
        sink = io.StringIO()
        with patch("host_proof.shutil.which", return_value="/usr/bin/docker"):
            with patch("host_proof.verified_seccomp_path", return_value="/tmp/fixture"):
                with patch("host_proof.subprocess.run", return_value=valid) as runner:
                    with contextlib.redirect_stdout(sink):
                        clone3_invalid_argument_precheck(self.image)
        arg = runner.call_args.args[0]
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges=true",
                     "--user=10001:10001", "--entrypoint=/usr/bin/python3"):
            self.assertIn(flag, arg)
        self.assertFalse(any(q.startswith("--mount") or q.startswith("--volume")
                             for q in arg))
        self.assertIn("GUEST_CLONE3_NULL_PROBE=DENIED_EPERM", sink.getvalue())
        self.assertNotIn("secret", sink.getvalue())
        raw = subprocess.CompletedProcess([], 0, stdout="secret hidden token")
        sink = io.StringIO()
        with patch("host_proof.shutil.which", return_value="/usr/bin/docker"):
            with patch("host_proof.verified_seccomp_path", return_value="/tmp/fixture"):
                with patch("host_proof.subprocess.run", return_value=raw):
                    with contextlib.redirect_stdout(sink):
                        clone3_invalid_argument_precheck(self.image)
        self.assertIn("GUEST_CLONE3_NULL_PROBE=UNAVAILABLE", sink.getvalue())
        self.assertNotIn("secret", sink.getvalue())

    def test_clone_newuser_matches_chrome_flag_and_redacts_outputs(self):
        result = subprocess.CompletedProcess([], 0, stdout="ALLOWED\n",
                                             stderr="private user host detail")
        sink = io.StringIO()
        with patch("host_proof.shutil.which", return_value="/usr/bin/docker"), \
             patch("host_proof.verified_seccomp_path", return_value="/tmp/synthetic"), \
             patch("host_proof.subprocess.run", return_value=result) as runner:
            with contextlib.redirect_stdout(sink):
                clone_newuser_precheck(self.image)
        argv = runner.call_args.args[0]
        self.assertIn("--network=none", argv)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--security-opt=no-new-privileges=true", argv)
        self.assertIn("--user=10001:10001", argv)
        self.assertIn("--entrypoint=/usr/bin/python3", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("--network=host", argv)
        self.assertIn("0x10000000 | signal.SIGCHLD", argv[-1])
        self.assertIn("GUEST_CLONE_NEWUSER_PROBE=ALLOWED", sink.getvalue())
        self.assertNotIn("private", sink.getvalue())
        raw = subprocess.CompletedProcess([], 0, stdout="private credentials")
        sink = io.StringIO()
        with patch("host_proof.shutil.which", return_value="/usr/bin/docker"), \
             patch("host_proof.verified_seccomp_path", return_value="/tmp/synthetic"), \
             patch("host_proof.subprocess.run", return_value=raw):
            with contextlib.redirect_stdout(sink):
                clone_newuser_precheck(self.image)
        self.assertIn("GUEST_CLONE_NEWUSER_PROBE=UNAVAILABLE", sink.getvalue())
        self.assertNotIn("credentials", sink.getvalue())

    def test_named_container_and_label_are_fixed(self):
        args = command("/usr/bin/docker", self.image, "172.17.0.1",
                       32001, nonce=self.nonce)
        self.assertEqual(args[:3], ["/usr/bin/docker", "container", "create"])
        self.assertIn("--init", args)
        self.assertIn("--name=" + self.name, args)
        self.assertIn("--label=ldw.proof.nonce=" + self.nonce, args)
        self.assertNotIn("--rm", args)
        for bad in ("bad", "C" * 24, "0" * 25, "", self.nonce + "--network=host"):
            with self.subTest(bad=bad), self.assertRaises(BoundaryError):
                command("/usr/bin/docker", self.image, "172.17.0.1",
                        32001, nonce=bad)

    def test_cleanup_refuses_foreign_container(self):
        with patch("host_proof.inspect_container",
                   return_value=("c" * 64, self.image, "f" * 24)):
            with self.assertRaisesRegex(BoundaryError, "PROOF_CONTAINER_PROVENANCE_MISMATCH"):
                guarded_container_cleanup("/usr/bin/docker", self.name,
                                          self.nonce, self.image)

    def test_cleanup_removes_exact_guest_and_reads_back_absence(self):
        states = [("c" * 64, self.image, self.nonce), None]
        with patch("host_proof.inspect_container", side_effect=states) as inspected:
            with patch("host_proof.subprocess.run",
                       return_value=subprocess.CompletedProcess([], 0)) as runner:
                guarded_container_cleanup("/usr/bin/docker", self.name,
                                          self.nonce, self.image)
        self.assertEqual(inspected.call_count, 2)
        self.assertEqual(runner.call_args.args[0],
                         ["/usr/bin/docker", "container", "rm", "--force", self.name])

    def test_failed_attach_still_invokes_scoped_cleanup(self):
        output = subprocess.CompletedProcess([], 0, stdout="c" * 64)
        def fake_run(args, **kwargs):
            if args[1:3] == ["container", "create"]:
                return output
            if args[1:3] == ["container", "start"]:
                raise subprocess.TimeoutExpired(args, 100)
            raise AssertionError("unexpected command")
        states = [None, ("c" * 64, self.image, self.nonce)]
        with patch("host_proof.secrets.token_hex", return_value=self.nonce):
            with patch("host_proof.inspect_container", side_effect=states):
                with patch("host_proof.subprocess.run", side_effect=fake_run):
                    with patch("host_proof.guarded_container_cleanup") as cleanup:
                        with self.assertRaisesRegex(BoundaryError, "CHROMIUM_GUEST_START_OR_TIMEOUT"):
                            run_bound_guest("/usr/bin/docker", self.image,
                                            "172.17.0.1", 32001, False)
        cleanup.assert_called_once_with("/usr/bin/docker", self.name,
                                        self.nonce, self.image)

    def test_no_start_phase_is_sanitized(self):
        for phase in ("GUEST_BROWSER_LAUNCH_ERROR",
                      "GUEST_BROWSER_LAUNCH_ACTUAL_NO_USABLE_SANDBOX",
                      "GUEST_BROWSER_LAUNCH_ACTUAL_NAMESPACE_DENIED",
                      "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_HOST",
                      "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_LAUNCH_FAILED",
                      "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_INVALID_BOOT_PID",
                      "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE_FORK_FAILED",
                      "GUEST_BROWSER_LAUNCH_ACTUAL_ZYGOTE",
                      "GUEST_BROWSER_LAUNCH_ACTUAL_UNKNOWN",
                      "GUEST_LOCAL_NAVIGATION_ERROR", "GUEST_SERVICE_WORKER_ERROR"):
            with self.assertRaises(BoundaryError) as caught:
                verify_guest({"result": "NO_START", "reason": phase}, 1)
            self.assertEqual(str(caught.exception), "CHROMIUM_NO_START_" + phase)
        with self.assertRaises(BoundaryError) as caught:
            verify_guest({"result": "NO_START", "reason": "secret /home/runner/.env"}, 1)
        self.assertEqual(str(caught.exception), "CHROMIUM_NO_START_UNCLASSIFIED")
        with self.assertRaisesRegex(BoundaryError, "UNCLASSIFIED"):
            verify_guest({"result":"NO_START",
                          "reason":"GUEST_BROWSER_LAUNCH_DIRECT_ZYGOTE"},1)

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
