"""Real disposable process parent+child cleanup, never Administrator/root."""
import unittest
from process_containment import FixedProcessCanary, ContainmentRefused


class BoundedCanaryTests(unittest.TestCase):
    def test_real_parent_and_child_cleanup(self):
        with FixedProcessCanary() as fixture:
            self.assertEqual(fixture.start()["state"], "RUNNING")
            self.assertIsNotNone(fixture._child_pid)
            self.assertEqual(fixture.stop()["state"], "DRAINED_VERIFIED")
            self.assertIsNotNone(fixture._proc.returncode)
            self.assertEqual(fixture.status()["state"], "DRAINED_VERIFIED")
            with self.assertRaises(ContainmentRefused):
                fixture.start()

    def test_ambiguous_verification_is_quarantined(self):
        with FixedProcessCanary() as fixture:
            fixture.start()
            with self.assertRaises(ContainmentRefused) as caught:
                fixture.stop(simulate_unverifiable=True)
            self.assertEqual(caught.exception.code, "HOST_QUARANTINED")
            self.assertEqual(fixture.status()["state"], "QUARANTINED")
            with self.assertRaises(ContainmentRefused):
                fixture.start()

    def test_expiration_drains_with_real_os_readback(self):
        clock = [100.]
        with FixedProcessCanary(clock=lambda: clock[0], duration_seconds=1) as fixture:
            fixture.start()
            clock[0] += 2
            self.assertEqual(fixture.refresh()["state"], "DRAINED_VERIFIED")

    def test_clock_rollback_fails_closed(self):
        clock = [100.]
        with FixedProcessCanary(clock=lambda: clock[0]) as fixture:
            fixture.start()
            clock[0] -= 1
            with self.assertRaises(ContainmentRefused) as caught:
                fixture.refresh()
            self.assertEqual(caught.exception.code, "CLOCK_UNTRUSTED_HOST_QUARANTINED")
            self.assertEqual(fixture.status()["state"], "QUARANTINED")

    def test_not_unrestricted_shell(self):
        with self.assertRaises(ContainmentRefused):
            FixedProcessCanary(duration_seconds=0)
        with self.assertRaises(TypeError):
            FixedProcessCanary(command="rm -rf /")
        with FixedProcessCanary() as fixture:
            self.assertFalse(fixture.status()["privileged"])
            self.assertFalse(fixture.status()["arbitrary_commands"])
            self.assertFalse(fixture.status()["host_service_installed"])
            with self.assertRaises(ContainmentRefused):
                fixture.stop()


if __name__ == "__main__":
    unittest.main()
