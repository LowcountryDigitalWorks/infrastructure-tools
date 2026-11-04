import unittest
from controller import BrowserGateError, SyntheticBrowser

PAGE = '''<!doctype html><title>LDW synthetic browser</title>
<label for="task">Task</label><input id="task"><button id="go" onclick="document.querySelector('#result').textContent=document.querySelector('#task').value.toUpperCase()">Run</button><p id="result">Idle</p>'''

class BrowserTests(unittest.TestCase):
    def test_synthetic_page_fill_click_read_screenshot(self):
        with SyntheticBrowser() as browser:
            state = browser.load_fixture(PAGE)
            self.assertEqual(state["title"], "LDW synthetic browser")
            browser.fill("#task", "gm chat relay")
            browser.click("#go")
            self.assertEqual(browser.text("#result"), "GM CHAT RELAY")
            self.assertEqual(len(browser.screenshot_digest()), 64)

    def test_remote_targets_rejected_before_browser_visit(self):
        with SyntheticBrowser() as browser:
            for url in ("https://example.org", "http://localhost:1000", "file:///etc/passwd", "http://127.0.0.1", "http://user:pw@127.0.0.1:8080"):
                with self.assertRaises(BrowserGateError):
                    browser.navigate(url)

    def test_navigation_port_must_be_trusted_not_selected_by_page(self):
        with self.assertRaises(BrowserGateError):
            SyntheticBrowser(allowed_port=0)
        with self.assertRaises(BrowserGateError):
            SyntheticBrowser(allowed_port=True)
        with SyntheticBrowser(allowed_port=18080) as browser:
            for url in (
                "http://127.0.0.1:18081/",
                "http://127.0.0.1:65535/",
                "http://127.0.0.1:bogus/"
            ):
                with self.assertRaises(BrowserGateError):
                    browser.navigate(url)

    def test_page_websocket_is_denied_before_connection(self):
        # WebSockets require an independent route; HTTP interception is not
        # sufficient. This page has no connected browser account.
        with SyntheticBrowser() as browser:
            browser.load_fixture('''<title>Socket fixture</title><script>
            window.connected = false;
            const socket = new WebSocket("ws://127.0.0.1:18080/test");
            socket.addEventListener("open", () => window.connected = true);
            </script>''')
            for _ in range(20):
                if browser.denied_network_counts()["websocket"]:
                    break
                browser._page.wait_for_timeout(50)
            self.assertGreater(browser.denied_network_counts()["websocket"], 0)
            self.assertFalse(browser._page.evaluate("window.connected"))
            self.assertEqual(browser._context.service_workers, [])

    def test_page_external_websocket_denied_by_websocket_route(self):
        with SyntheticBrowser() as browser:
            browser.load_fixture('''<title>External socket fixture</title><script>
            window.connected = false;
            const socket = new WebSocket("wss://example.invalid/test");
            socket.addEventListener("open", () => window.connected = true);
            </script>''')
            for _ in range(20):
                if browser.denied_network_counts()["websocket"]:
                    break
                browser._page.wait_for_timeout(50)
            self.assertGreater(browser.denied_network_counts()["websocket"], 0)
            self.assertFalse(browser._page.evaluate("window.connected"))

    def test_page_external_http_resource_denied_by_http_route(self):
        with SyntheticBrowser() as browser:
            browser.load_fixture('''<title>External image fixture</title>
            <img id="untrusted" src="https://example.invalid/resource.png">''')
            for _ in range(20):
                if browser.denied_network_counts()["http"]:
                    break
                browser._page.wait_for_timeout(50)
            self.assertGreater(browser.denied_network_counts()["http"], 0)
            self.assertEqual(
                browser._page.locator("#untrusted").evaluate(
                    "(element) => element.naturalWidth"), 0)

    def test_oversized_text_and_selector_refused(self):
        with SyntheticBrowser() as browser:
            browser.load_fixture(PAGE)
            with self.assertRaises(BrowserGateError):
                browser.fill("#task", "x" * 1025)
            with self.assertRaises(BrowserGateError):
                browser.click("x" * 161)

if __name__ == "__main__":
    unittest.main()
