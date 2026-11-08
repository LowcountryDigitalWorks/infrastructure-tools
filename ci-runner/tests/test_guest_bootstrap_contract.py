"""Static fail-closed checks for the pinned CI7 guest download; no network/guest."""
from pathlib import Path
import unittest

BOOTSTRAP = Path(__file__).resolve().parents[1] / "guest" / "bootstrap.sh"
PINNED_URL = (
    "https://github.com/actions/runner/releases/download/v2.338.0/"
    "actions-runner-linux-x64-2.338.0.tar.gz"
)
PINNED_SHA256 = "af4b794c1bc41d73d40535e3fe092a39f9679cd8d965954c2aca25a05ca41d32"


class GuestBootstrapContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = BOOTSTRAP.read_text(encoding="utf-8")
        begin = cls.script.index("if curl ")
        end = cls.script.index("; then", begin)
        cls.fetch = cls.script[begin:end].replace("\\\n", " ")

    def test_exact_pinned_https_download_and_finite_retries(self):
        self.assertIn(PINNED_URL, self.fetch)
        for flag in (
            "--proto '=https'", "--tlsv1.2", "--fail", "--location",
            "--connect-timeout 30", "--max-time 300",
            "--retry 2", "--retry-delay 2", "--retry-max-time 420",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, self.fetch)
        for forbidden in ("--insecure", "--retry-all-errors", "--retry-connrefused",
                          "--location-trusted", "http://", "latest"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.fetch)
        self.assertEqual(self.fetch.count(PINNED_URL), 1)

    def test_checksum_before_extraction_and_no_fallback(self):
        s = self.script
        self.assertIn(PINNED_SHA256, s)
        self.assertIn("sha256sum --check --strict", s)
        fetch_idx = s.index("if curl ")
        hash_idx = s.index("sha256sum --check --strict")
        unpack_idx = s.index('tar -xzf "$archive" -C /opt/actions-runner')
        self.assertLess(fetch_idx, hash_idx)
        self.assertLess(hash_idx, unpack_idx)
        self.assertEqual(s.count("if curl "), 1)

    def test_exhausted_fetch_still_fails_closed_and_scrubs_jit(self):
        s = self.script
        begin = s.index("if curl ")
        end = s.index("printf '%s  %s", begin)
        failure = s[begin:end]
        for classification in (
            "6) phase DOWNLOAD_DNS_FAILED ;;",
            "7) phase DOWNLOAD_CONNECT_FAILED ;;",
            "22) phase DOWNLOAD_HTTP_FAILED ;;",
            "23) phase DOWNLOAD_WRITE_FAILED ;;",
            "35|60) phase DOWNLOAD_TLS_FAILED ;;",
            "*) phase DOWNLOAD_OTHER_FAILED ;;",
        ):
            self.assertIn(classification, failure)
        self.assertLess(failure.index("phase FAILED"), failure.index("rm -f /run/ci7/jit"))
        self.assertLess(failure.index("rm -f /run/ci7/jit"), failure.index("systemctl poweroff"))
        self.assertLess(failure.index("systemctl poweroff"), failure.index("exit 1"))
        self.assertNotIn("continue-on-error", s)


if __name__ == "__main__":
    unittest.main()
