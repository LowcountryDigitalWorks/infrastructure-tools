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

    def test_oversized_text_and_selector_refused(self):
        with SyntheticBrowser() as browser:
            browser.load_fixture(PAGE)
            with self.assertRaises(BrowserGateError):
                browser.fill("#task", "x" * 1025)
            with self.assertRaises(BrowserGateError):
                browser.click("x" * 161)

if __name__ == "__main__":
    unittest.main()
