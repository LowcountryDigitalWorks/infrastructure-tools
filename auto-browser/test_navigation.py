"""Real loopback HTTP navigation proof; no external website or owner profile."""
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from controller import BrowserGateError, SyntheticBrowser

HOME = """<!doctype html><html><head><title>LDW Local Site</title></head>
<body><input id="task"><button id="execute" onclick="document.querySelector('#result').textContent=document.querySelector('#task').value.toUpperCase()">Execute</button>
<div id="result">Idle</div><a id="next" href="/done">Continue</a></body></html>"""
DONE = """<!doctype html><html><head><title>LDW Done</title></head>
<body><p id="done">Local navigation complete</p></body></html>"""


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        return

    def do_GET(self):
        if self.path == "/":
            html = HOME.encode()
        elif self.path == "/done":
            html = DONE.encode()
        elif self.path == "/offhost":
            self.send_response(302)
            self.send_header("Location", "https://example.invalid/do-not-load")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


class LoopbackNavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.origin = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=2)

    def test_real_local_navigation_input_click_and_next_page(self):
        with SyntheticBrowser(allowed_port=self.server.server_port) as browser:
            snap = browser.navigate(self.origin + "/")
            self.assertEqual(snap["title"], "LDW Local Site")
            self.assertEqual(snap["url"], self.origin + "/")
            browser.fill("#task", "gm -> ir")
            browser.click("#execute")
            self.assertEqual(browser.text("#result"), "GM -> IR")
            self.assertEqual(len(browser.screenshot_digest()), 64)
            browser.click("#next")
            self.assertEqual(browser.snapshot()["url"], self.origin + "/done")
            self.assertEqual(browser.text("#done"), "Local navigation complete")

    def test_cross_origin_redirect_is_blocked(self):
        with SyntheticBrowser(allowed_port=self.server.server_port) as browser:
            # A valid local entry point must not allow an external redirect.
            # The context route refuses any non-127.0.0.1 URL before network I/O.
            with self.assertRaises(Exception):
                browser.navigate(self.origin + "/offhost")

    def test_other_loopback_service_is_not_approved(self):
        other_port = self.server.server_port + 1 if self.server.server_port < 65535 else 1
        with SyntheticBrowser(allowed_port=self.server.server_port) as browser:
            with self.assertRaises(BrowserGateError):
                browser.navigate("http://127.0.0.1:" + str(other_port) + "/")

    def test_nonlocal_initial_url_is_rejected(self):
        with SyntheticBrowser(allowed_port=self.server.server_port) as browser:
            for url in ("https://example.com", "http://localhost:9090",
                        "http://127.0.0.2:9090", "file:///etc/passwd",
                        "http://127.0.0.1/"):
                with self.assertRaises(BrowserGateError, msg=url):
                    browser.navigate(url)


if __name__ == "__main__":
    unittest.main()
