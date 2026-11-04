"""First-party LDW Auto Browser synthetic local click/type/navigation proof.

This is a disposable Chromium/Playwright control adapter, not a deployed Bridge
mutation capability. Only 127.0.0.1 synthetic HTTP pages are accepted here.
"""
from __future__ import annotations

import hashlib
import os
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


class BrowserGateError(ValueError):
    pass


class SyntheticBrowser:
    def __init__(self):
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None

    def __enter__(self):
        self._playwright = sync_playwright().start()
        try:
            # Playwright's isolated nonpersistent browser context, no owner profile.
            browser_kwargs = {"headless": True}
            if os.path.isfile("/usr/bin/chromium"):
                browser_kwargs["executable_path"] = "/usr/bin/chromium"
            self._browser = self._playwright.chromium.launch(**browser_kwargs)
            self._context = self._browser.new_context(accept_downloads=False)
            self._context.route("**/*", lambda route: route.continue_() if self._is_synthetic_url(route.request.url) else route.abort())
            self._page = self._context.new_page()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()
        self._page = self._context = self._browser = self._playwright = None

    @staticmethod
    def _is_synthetic_url(url: str) -> bool:
        try:
            SyntheticBrowser._local_only(url)
            return True
        except (BrowserGateError, ValueError):
            return False

    @staticmethod
    def _local_only(url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password:
            raise BrowserGateError("SYNTHETIC_LOCAL_ONLY")
        if not parsed.port or not 1 <= parsed.port <= 65535:
            raise BrowserGateError("INVALID_LOCAL_PORT")
        if parsed.fragment:
            raise BrowserGateError("NO_FRAGMENT")

    def load_fixture(self, html: str) -> dict:
        """Load a synthetic offline fixture; never loads an owner browser profile."""
        if not isinstance(html, str) or not html or len(html.encode("utf-8")) > 8192:
            raise BrowserGateError("INVALID_FIXTURE")
        self._page.set_content(html, wait_until="domcontentloaded")
        return self.snapshot()

    def navigate(self, url: str) -> dict:
        self._local_only(url)
        self._page.goto(url, wait_until="domcontentloaded", timeout=5000)
        return self.snapshot()

    @staticmethod
    def _selector(value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 160:
            raise BrowserGateError("INVALID_SELECTOR")
        return value

    def fill(self, selector: str, text: str) -> None:
        self._selector(selector)
        if not isinstance(text, str) or len(text.encode("utf-8")) > 1024:
            raise BrowserGateError("INVALID_TEXT")
        self._page.locator(selector).fill(text, timeout=3000)

    def click(self, selector: str) -> None:
        self._selector(selector)
        self._page.locator(selector).click(timeout=3000)

    def text(self, selector: str) -> str:
        self._selector(selector)
        return self._page.locator(selector).inner_text(timeout=3000)[:2048]

    def snapshot(self) -> dict:
        return {"title": self._page.title()[:128], "url": self._page.url}

    def screenshot_digest(self) -> str:
        return hashlib.sha256(self._page.screenshot(type="png", timeout=3000)).hexdigest()
