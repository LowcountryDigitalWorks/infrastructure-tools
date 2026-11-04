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
    def __init__(self, allowed_port: int | None = None):
        # The model must never select this port through a browser tool call.
        # It is fixed by trusted local test-fixture bootstrap only.
        if allowed_port is not None and (
            isinstance(allowed_port, bool) or not isinstance(allowed_port, int)
            or not 1 <= allowed_port <= 65535
        ):
            raise BrowserGateError("INVALID_ALLOWED_PORT")
        self._allowed_port = allowed_port
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._blocked_http = 0
        self._blocked_websocket = 0

    def __enter__(self):
        self._playwright = sync_playwright().start()
        try:
            # Playwright's isolated nonpersistent browser context, no owner profile.
            browser_kwargs = {"headless": True}
            if os.path.isfile("/usr/bin/chromium"):
                browser_kwargs["executable_path"] = "/usr/bin/chromium"
            self._browser = self._playwright.chromium.launch(**browser_kwargs)
            # Service Workers can otherwise bypass HTTP route interception.
            self._context = self._browser.new_context(
                accept_downloads=False, service_workers="block",
            )
            self._context.route("**/*", self._route_http)
            # HTTP interception does NOT cover WebSockets. Block every WS,
            # including local endpoints, before any page is created.
            self._context.route_web_socket("**/*", self._route_websocket)
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

    def _route_http(self, route) -> None:
        if self._is_synthetic_url(route.request.url):
            route.continue_()
        else:
            self._blocked_http += 1
            route.abort()

    def _route_websocket(self, route) -> None:
        # No server connection is made; even localhost WS is prohibited in V0.
        self._blocked_websocket += 1
        route.close(code=1008)

    def denied_network_counts(self) -> dict:
        # Safe diagnostics: never emit attempted URLs or request bodies.
        return {"http": self._blocked_http,
                "websocket": self._blocked_websocket}

    def _is_synthetic_url(self, url: str) -> bool:
        try:
            self._local_only(url)
            return True
        except (BrowserGateError, ValueError):
            return False

    def _local_only(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password:
            raise BrowserGateError("SYNTHETIC_LOCAL_ONLY")
        try:
            port = parsed.port
        except ValueError:
            raise BrowserGateError("INVALID_LOCAL_PORT") from None
        if not port or not 1 <= port <= 65535:
            raise BrowserGateError("INVALID_LOCAL_PORT")
        if self._allowed_port is None or port != self._allowed_port:
            raise BrowserGateError("UNAPPROVED_LOCAL_PORT")
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
