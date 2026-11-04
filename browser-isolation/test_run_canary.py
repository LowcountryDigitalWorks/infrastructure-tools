"""Static admission negatives. These are NOT a live Docker/packet proof."""
import unittest
from run_canary import BoundaryError, command, validate_guest_result, classify_guest_start_failure


class GuestAdmissionTests(unittest.TestCase):
    image = "sha256:" + "a" * 64

    def test_exact_immutable_host_isolation_flags(self):
        args = command("/usr/bin/docker", self.image, "172.17.0.1", 23456)
        self.assertEqual(args[:2], ["/usr/bin/docker", "run"])
        self.assertIn("--network=none", args)
        self.assertIn("--pull=never", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--read-only", args)
        self.assertIn("--security-opt=no-new-privileges=true", args)
        self.assertIn("--user=65532:65532", args)
        self.assertFalse(any(x.startswith("--pid=") for x in args))
        self.assertEqual(args[-4:], [self.image, "--probe", "172.17.0.1", "23456"])
        self.assertFalse(any(x.startswith("--mount") or x.startswith("--volume") for x in args))
        for unsafe in ("--privileged", "--network=host", "--ipc=host", "--pid=host", "--cap-add"):
            self.assertNotIn(unsafe, args)

    def test_refuses_mutable_or_malformed_images(self):
        for bad in ("ubuntu:latest", "myimage@sha256:" + "a" * 64,
                    "sha256:" + "x" * 64, "sha256:a", ""):
            with self.subTest(bad=bad), self.assertRaises(BoundaryError):
                command("docker", bad, "172.17.0.1", 1000)

    def test_refuses_host_network_and_invalid_ports(self):
        for addr in ("127.0.0.1", "0.0.0.0", "8.8.8.8", "::1", "host.docker.internal"):
            with self.subTest(addr=addr), self.assertRaises(BoundaryError):
                command("docker", self.image, addr, 1000)
        for port in (-1, 0, 65536, False):
            with self.subTest(port=port), self.assertRaises(BoundaryError):
                command("docker", self.image, "172.17.0.1", port)

    def test_guest_result_must_prove_each_vector(self):
        correct = {"guest_fixture": "PASS", "host_gateway": "BLOCKED", "off_guest": "BLOCKED"}
        validate_guest_result(correct, 0)
        for key in correct:
            invalid = dict(correct)
            invalid[key] = "FAIL"
            with self.subTest(key=key), self.assertRaises(BoundaryError) as ctx:
                validate_guest_result(invalid, 1)
            self.assertEqual(str(ctx.exception), "GUEST_" + key.upper() + "_NOT_PROVEN")
        for bad in ("PASS", {}, {**correct, "raw_stdout": "untrusted"}):
            with self.assertRaises(BoundaryError):
                validate_guest_result(bad, 0)
        with self.assertRaises(BoundaryError):
            validate_guest_result(correct, 1)

    def test_guest_error_classification_never_returns_raw_stderr(self):
        diagnostic = "OCI runtime create failed: permission denied /home/runner/private/secret"
        result = classify_guest_start_failure(diagnostic, 125)
        self.assertEqual(result, "GUEST_NO_STRUCTURED_RESULT_EXIT_125_PERMISSION_REFUSED")
        self.assertNotIn("/home/", result)
        self.assertEqual(classify_guest_start_failure("irrelevant", 2),
                         "GUEST_NO_STRUCTURED_RESULT_EXIT_2_UNKNOWN")

    def test_no_model_supplied_docker_options(self):
        with self.assertRaises(TypeError):
            command("docker", self.image, "172.17.0.1", 1234, "--network=host")


if __name__ == "__main__":
    unittest.main()
