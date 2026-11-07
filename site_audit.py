#!/usr/bin/env python3
"""
site_audit.py — a real-world, non-destructive website audit for a live site.

It checks:
  * HTTP status, redirects, TLS certificate, security headers, cookies
  * Static HTML/JS quality: duplicate IDs, missing labels/alt text, mixed
    content, missing SRI, hard-coded credentials, secrets, Firebase config
  * A real Chromium browser: console errors, page errors, failed requests,
    HTTP 4xx/5xx resources, blank-screen detection, performance metrics
  * Accessibility with axe-core (WCAG rules)
  * Responsive layout: horizontal overflow and small tap targets
  * Same-origin links, assets, manifest, favicon and fragment targets
  * Optional: unauthenticated Firebase/Firestore authorization probe
    (read-only, one masked document per path; never prints field values)
  * Optional: authenticated audit of the Teachers portal using login
    credentials supplied by the operator (--teacher-login). Credentials are
    read from environment variables or a hidden prompt; they are never
    extracted from the site, logged, or written to the report.

It does NOT change data, brute-force credentials, bypass authentication, or
run exploit payloads. The only form it submits is the site's normal login form,
and only when --teacher-login is explicitly requested with your own account.
It is a QA/security-hardening tool, not a replacement for a manual penetration
test.

Quick start:
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt
    python -m playwright install chromium
    python site_audit.py demo-web.com/

Reports are written to ./audit-report/ as report.html, report.json and
report.csv. Exit code is 1 when a finding at/above --fail-on is found.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import html as html_lib
import json
import logging
import os
import re
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from playwright.sync_api import sync_playwright
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    HAS_PLAYWRIGHT = True
except Exception:  # pragma: no cover - optional dependency
    sync_playwright = None
    PlaywrightError = Exception
    PlaywrightTimeout = Exception
    HAS_PLAYWRIGHT = False


VERSION = "1.1.0"
DEFAULT_URL = "demo-web.com/"
DEFAULT_UA = (
    f"SISCD-SiteAudit/{VERSION} "
    "(authorized QA audit; non-destructive; +demo-web.com/)"
)
AXE_URL = "https://cdn.jsdelivr.net/npm/axe-core@4.10.2/axe.min.js"

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {"critical": 30, "high": 12, "medium": 5, "low": 1, "info": 0}
SEV_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}
SEV_COLOR = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#64748b",
}

SENSITIVE_QUERY_KEYS = re.compile(
    r"(?i)^(token|access_token|id_token|refresh_token|key|api_key|apikey|"
    r"auth|authorization|password|passwd|pin|secret|email|session|sid)$"
)

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "critical",
        "Private key material embedded in a public page",
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "critical",
        "AWS access key ID embedded in a public page",
    ),
    (
        "GITHUB_TOKEN",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        "critical",
        "GitHub token embedded in a public page",
    ),
    (
        "STRIPE_LIVE_KEY",
        re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
        "critical",
        "Stripe live secret key embedded in a public page",
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "high",
        "Slack token embedded in a public page",
    ),
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "info",
        "Google/Firebase API key exposed in the page (normal for Firebase web apps)",
    ),
]

SENSITIVE_LOCAL_KEYS = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|credential|auth|apikey|api_key)"
)
SENSITIVE_PIN_KEYS = re.compile(r"(?i)pin")
SAFE_PIN_KEY_EXCEPTIONS = re.compile(
    r"(?i)(lockout|attempt|test|hash|timestamp|updated|count|length)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def redact_url(url: str) -> str:
    """Hide sensitive query-string values before writing them to a report."""
    try:
        parts = urlsplit(url)
        if not parts.query:
            return url
        pairs = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            pairs.append((key, "***" if SENSITIVE_QUERY_KEYS.match(key) else value))
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment)
        )
    except Exception:
        return url


def shorten(text: Any, limit: int = 500) -> str:
    s = str(text if text is not None else "")
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def fmt_bytes(n: int | float | None) -> str:
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def mask_value(value: str) -> str:
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def same_origin(a: str, b: str) -> bool:
    try:
        pa, pb = urlsplit(a), urlsplit(b)
        return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)
    except Exception:
        return False


def is_asset_url(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return bool(
        re.search(
            r"\.(?:png|jpe?g|gif|webp|svg|ico|css|js|mjs|map|woff2?|ttf|otf|"
            r"eot|pdf|zip|mp4|webm|mp3|wav|xml|txt|json)(?:$|\?)",
            path,
        )
    )


def css_escape_selector(value: str) -> str:
    """Small server-side helper only used for readable evidence labels."""
    return re.sub(r"[^a-zA-Z0-9_-]", lambda m: "\\" + m.group(0), value)


@dataclass
class Finding:
    code: str
    severity: str
    category: str
    title: str
    detail: str
    evidence: str = ""
    url: str = ""
    fix: str = ""

    def dedupe_key(self) -> tuple[str, str, str]:
        return (self.code, self.title, self.url)


class Auditor:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.base_url = self._normalize_url(args.url)
        parsed = urlsplit(self.base_url)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.out_dir = Path(args.out).expanduser().resolve()
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir = Path(args.cache_dir).expanduser().resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.findings: list[Finding] = []
        self._finding_keys: set[tuple[str, str, str]] = set()
        self.passed_checks: list[str] = []
        self.warnings: list[str] = []
        self.resources: dict[str, str] = {}
        self.link_results: dict[str, dict[str, Any]] = {}
        self.browser_responses: dict[str, dict[str, Any]] = {}
        self.browser_failures: list[dict[str, str]] = []
        self.console_messages: list[dict[str, str]] = []
        self.page_errors: list[str] = []
        self.dialogs: list[str] = []
        self.browser_metrics: dict[str, Any] = {}
        self.http_metrics: dict[str, Any] = {}
        self.tls_metrics: dict[str, Any] = {}
        self.html_metrics: dict[str, Any] = {}
        self.manifest: dict[str, Any] | None = None
        self.firebase_config: dict[str, str] = {}
        self.firebase_results: list[dict[str, Any]] = []
        self.crawled_pages: list[dict[str, Any]] = []
        self.root_html = ""
        self.root_soup: BeautifulSoup | None = None
        self.root_response: requests.Response | None = None
        self.start_time = time.time()

        self._local = threading.local()
        self.session = self._new_session(include_auth=True)
        self.log = logging.getLogger("site_audit")

    # ------------------------------------------------------------------ setup
    @staticmethod
    def _normalize_url(url: str) -> str:
        url = (url or DEFAULT_URL).strip()
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        if not urlsplit(url).path:
            url += "/"
        return url

    def _headers(self, include_auth: bool = True) -> dict[str, str]:
        headers = {
            "User-Agent": self.args.user_agent or DEFAULT_UA,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
        if include_auth:
            for raw in self.args.header or []:
                if ":" in raw:
                    name, value = raw.split(":", 1)
                    headers[name.strip()] = value.strip()
        return headers

    def _new_session(self, include_auth: bool = True) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=2,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "HEAD"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=12, pool_maxsize=12)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update(self._headers(include_auth))
        if include_auth:
            for raw in self.args.cookie or []:
                if "=" in raw:
                    name, value = raw.split("=", 1)
                    session.cookies.set(name.strip(), value.strip())
        if self.args.proxy:
            session.proxies.update(
                {"http": self.args.proxy, "https": self.args.proxy}
            )
        session.verify = not self.args.insecure
        return session

    def _thread_session(self, include_auth: bool = False) -> requests.Session:
        cache_key = "session_auth" if include_auth else "session"
        session = getattr(self._local, cache_key, None)
        if session is None:
            session = self._new_session(include_auth=include_auth)
            setattr(self._local, cache_key, session)
        return session

    # ------------------------------------------------------------- primitives
    def add(
        self,
        code: str,
        severity: str,
        category: str,
        title: str,
        detail: str,
        evidence: str = "",
        url: str = "",
        fix: str = "",
    ) -> None:
        severity = severity if severity in SEV_ORDER else "info"
        finding = Finding(
            code=code,
            severity=severity,
            category=category,
            title=title,
            detail=shorten(detail, 1800),
            evidence=shorten(evidence, 1800),
            url=redact_url(url or self.base_url),
            fix=shorten(fix, 1200),
        )
        key = finding.dedupe_key()
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        self.findings.append(finding)
        self.log.debug("[%s] %s", severity.upper(), title)

    def passed(self, text: str) -> None:
        if text not in self.passed_checks:
            self.passed_checks.append(text)

    def warn(self, text: str) -> None:
        self.warnings.append(text)
        self.log.warning(text)

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.args.timeout)
        kwargs.setdefault("allow_redirects", True)
        # Never send user-supplied auth headers to a third-party origin.
        if not same_origin(url, self.base_url):
            return self._new_session(include_auth=False).request(method, url, **kwargs)
        return self.session.request(method, url, **kwargs)

    # ================================================================== PHASE 1
    def phase_http(self) -> tuple[requests.Response | None, str, BeautifulSoup | None]:
        self.log.info("1/6  HTTP, TLS, headers, cookies, manifest")
        started = time.perf_counter()
        try:
            response = self._request("GET", self.base_url)
        except Exception as exc:
            self.add(
                "HTTP_UNREACHABLE",
                "critical",
                "Availability",
                "Website is not reachable",
                f"{type(exc).__name__}: {exc}",
                url=self.base_url,
                fix="Check DNS, hosting status, firewall rules and the URL.",
            )
            return None, "", None

        elapsed_ms = round((time.perf_counter() - started) * 1000)
        html_text = response.content.decode(response.encoding or "utf-8", errors="replace")
        self.root_response = response
        self.root_html = html_text
        soup = BeautifulSoup(html_text, "html.parser")
        self.root_soup = soup

        self.http_metrics = {
            "requested_url": self.base_url,
            "final_url": redact_url(response.url),
            "status": response.status_code,
            "reason": response.reason,
            "elapsed_ms": elapsed_ms,
            "body_bytes": len(response.content),
            "content_type": response.headers.get("Content-Type", ""),
            "content_encoding": response.headers.get("Content-Encoding", ""),
            "cache_control": response.headers.get("Cache-Control", ""),
            "redirects": [
                {"status": r.status_code, "url": redact_url(r.url)}
                for r in response.history
            ],
            "headers": {
                k: ("***" if k.lower() in {"set-cookie", "authorization"} else shorten(v, 300))
                for k, v in response.headers.items()
            },
        }

        if response.status_code >= 500:
            self.add(
                "HTTP_5XX",
                "critical",
                "Availability",
                f"Home page returned HTTP {response.status_code}",
                "The server failed to render the main page.",
                evidence=shorten(response.text, 300),
                fix="Check hosting logs and roll back the last deployment.",
            )
        elif response.status_code >= 400:
            self.add(
                "HTTP_4XX",
                "high",
                "Availability",
                f"Home page returned HTTP {response.status_code}",
                "Users may see an error page instead of the application.",
                evidence=shorten(response.text, 300),
                fix="Fix the missing route, permission or server configuration.",
            )
        else:
            self.passed(f"Home page returned HTTP {response.status_code}")

        if urlsplit(response.url).scheme != "https":
            self.add(
                "HTTPS_MISSING",
                "critical",
                "Transport",
                "The final page is served over plain HTTP",
                "Login credentials and student data can be intercepted.",
                url=response.url,
                fix="Redirect all HTTP traffic to HTTPS and enable HSTS.",
            )
        else:
            self.passed("HTTPS is used for the final page")

        self._check_security_headers(response)
        self._check_cookies(response)
        self._check_tls()
        self._check_http_redirect()
        self._check_manifest(soup)
        self._check_simple_paths(soup)
        return response, html_text, soup

    def _check_security_headers(self, response: requests.Response) -> None:
        headers = {k.lower(): v for k, v in response.headers.items()}
        csp = headers.get("content-security-policy", "")
        hsts = headers.get("strict-transport-security", "")
        xfo = headers.get("x-frame-options", "")
        xcto = headers.get("x-content-type-options", "")
        referrer = headers.get("referrer-policy", "")
        permissions = headers.get("permissions-policy") or headers.get("feature-policy")
        coop = headers.get("cross-origin-opener-policy", "")
        content_type = headers.get("content-type", "")
        encoding = headers.get("content-encoding", "")

        if not csp:
            self.add(
                "CSP_MISSING",
                "high",
                "Security headers",
                "Content-Security-Policy header is missing",
                (
                    "The site has no CSP. Because this page contains a very large "
                    "amount of inline JavaScript, any injected script would execute "
                    "with full access to the DOM, Firebase session and local data."
                ),
                evidence="No content-security-policy response header.",
                fix=(
                    "Add a CSP at the host/CDN. Start with a safe minimum such as "
                    "`frame-ancestors 'none'; object-src 'none'; base-uri 'self'` "
                    "and then add script-src using hashes/nonces after testing."
                ),
            )
        else:
            self.passed("Content-Security-Policy header is present")
            if re.search(r"script-src[^;]*'unsafe-inline'", csp, re.I):
                self.add(
                    "CSP_UNSAFE_INLINE",
                    "medium",
                    "Security headers",
                    "CSP allows unsafe-inline scripts",
                    "The CSP does not meaningfully mitigate XSS while unsafe-inline is enabled.",
                    evidence=shorten(csp, 500),
                    fix="Move inline scripts to external files or use nonces/hashes.",
                )
            if "frame-ancestors" not in csp.lower():
                self.add(
                    "CSP_FRAME_ANCESTORS",
                    "medium",
                    "Security headers",
                    "CSP does not restrict framing",
                    "The site can be embedded in another origin (clickjacking).",
                    evidence=shorten(csp, 500),
                    fix="Add `frame-ancestors 'none'` (or your allowed parents) to the CSP.",
                )

        if not hsts:
            self.add(
                "HSTS_MISSING",
                "high",
                "Transport",
                "Strict-Transport-Security header is missing",
                "Browsers are not told to keep using HTTPS after the first visit.",
                fix="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
            )
        else:
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            if not match:
                self.add(
                    "HSTS_INVALID",
                    "medium",
                    "Transport",
                    "HSTS header has no valid max-age",
                    "The HSTS policy may be ignored by browsers.",
                    evidence=shorten(hsts, 300),
                    fix="Use `max-age=31536000` (at least six months).",
                )
            else:
                max_age = int(match.group(1))
                if max_age < 15_552_000:
                    self.add(
                        "HSTS_SHORT",
                        "medium",
                        "Transport",
                        "HSTS max-age is shorter than six months",
                        f"max-age is {max_age} seconds; the recommended minimum is 15552000.",
                        evidence=shorten(hsts, 300),
                        fix="Increase max-age to at least 31536000 seconds.",
                    )
                else:
                    self.passed(f"HSTS is enabled (max-age={max_age})")

        has_frame_ancestors = "frame-ancestors" in csp.lower()
        if not xfo and not has_frame_ancestors:
            self.add(
                "XFO_MISSING",
                "medium",
                "Security headers",
                "Clickjacking protection is missing",
                "Neither X-Frame-Options nor CSP frame-ancestors prevents framing.",
                fix="Add `X-Frame-Options: DENY` and `frame-ancestors 'none'`.",
            )
        elif xfo or has_frame_ancestors:
            self.passed("Clickjacking protection is present")

        if not xcto:
            self.add(
                "XCTO_MISSING",
                "medium",
                "Security headers",
                "X-Content-Type-Options: nosniff is missing",
                "Browsers may MIME-sniff responses and execute content incorrectly.",
                fix="Add `X-Content-Type-Options: nosniff`.",
            )
        elif xcto.strip().lower() != "nosniff":
            self.add(
                "XCTO_INVALID",
                "low",
                "Security headers",
                "X-Content-Type-Options has an unexpected value",
                "The header should be exactly `nosniff`.",
                evidence=shorten(xcto, 200),
                fix="Set `X-Content-Type-Options: nosniff`.",
            )
        else:
            self.passed("X-Content-Type-Options: nosniff is present")

        if not referrer:
            self.add(
                "REFERRER_POLICY_MISSING",
                "low",
                "Security headers",
                "Referrer-Policy header is missing",
                "URLs (which may contain student IDs or tokens) can leak in the Referer header.",
                fix="Add `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
            )
        else:
            self.passed("Referrer-Policy header is present")

        if not permissions:
            self.add(
                "PERMISSIONS_POLICY_MISSING",
                "low",
                "Security headers",
                "Permissions-Policy header is missing",
                "Browser features (camera, microphone, geolocation) are not restricted.",
                fix="Add `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
            )
        else:
            self.passed("Permissions-Policy header is present")

        if not coop:
            self.add(
                "COOP_MISSING",
                "low",
                "Security headers",
                "Cross-Origin-Opener-Policy is missing",
                "Cross-window attacks such as XS-Leaks are not mitigated.",
                fix="Add `Cross-Origin-Opener-Policy: same-origin` after testing popups.",
            )

        allow_origin = headers.get("access-control-allow-origin", "")
        allow_credentials = headers.get("access-control-allow-credentials", "")
        if allow_origin.strip() == "*" and allow_credentials.strip().lower() == "true":
            self.add(
                "CORS_WILDCARD_CREDENTIALS",
                "high",
                "Security headers",
                "CORS allows any origin with credentials",
                "This combination lets malicious sites read authenticated responses.",
                evidence=shorten(
                    f"Access-Control-Allow-Origin: {allow_origin}; "
                    f"Access-Control-Allow-Credentials: {allow_credentials}",
                    300,
                ),
                fix="Return a specific allowlisted origin; never pair `*` with credentials.",
            )

        if "charset=" not in content_type.lower() and "text/html" in content_type.lower():
            self.add(
                "CHARSET_MISSING",
                "low",
                "Content",
                "HTML response does not declare a character set",
                "Some browsers may guess the encoding incorrectly.",
                evidence=shorten(content_type, 200),
                fix="Serve `Content-Type: text/html; charset=utf-8`.",
            )

        body_bytes = len(response.content)
        if body_bytes > 500_000 and not encoding:
            self.add(
                "COMPRESSION_MISSING",
                "medium",
                "Performance",
                "Large HTML response is not compressed",
                f"The page is {fmt_bytes(body_bytes)} and no Content-Encoding was returned.",
                evidence=f"Content-Length/body={body_bytes} bytes; Content-Encoding=''",
                fix="Enable Brotli or gzip compression at the host/CDN.",
            )
        elif encoding:
            self.passed(f"Response compression is enabled ({encoding})")

        cache_control = headers.get("cache-control", "").lower()
        if "no-store" in cache_control and body_bytes > 1_000_000:
            self.add(
                "HTML_NO_STORE_LARGE",
                "medium",
                "Performance",
                "Large HTML is marked no-store and cannot be cached",
                (
                    f"The {fmt_bytes(body_bytes)} HTML document is sent with "
                    "`Cache-Control: no-store`, so every navigation downloads the "
                    "whole document again, even when only a tiny part changed."
                ),
                evidence=f"Cache-Control: {shorten(cache_control, 200)}; HTML bytes={body_bytes}",
                fix=(
                    "Split the inline JavaScript/CSS into versioned static files with "
                    "long cache lifetimes, and cache the small HTML shell. Keep no-store "
                    "only on authenticated API responses if needed."
                ),
            )

        if headers.get("x-powered-by") or headers.get("server"):
            disclosed = headers.get("x-powered-by") or headers.get("server", "")
            self.add(
                "SERVER_DISCLOSURE",
                "info",
                "Security headers",
                "Server technology is disclosed",
                "Version banners help attackers choose exploits.",
                evidence=shorten(disclosed, 200),
                fix="Remove or genericize Server and X-Powered-By headers.",
            )

    def _check_cookies(self, response: requests.Response) -> None:
        try:
            raw_cookies = response.raw.headers.getlist("Set-Cookie")
        except Exception:
            raw_cookies = []
        for raw in raw_cookies:
            parts = [p.strip() for p in raw.split(";")]
            name = parts[0].split("=", 1)[0] if parts else "cookie"
            lower = raw.lower()
            missing = []
            if "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite" not in lower:
                missing.append("SameSite")
            if missing:
                self.add(
                    "COOKIE_FLAGS",
                    "medium",
                    "Security headers",
                    f"Cookie {name} is missing security attributes",
                    "Missing: " + ", ".join(missing),
                    evidence=shorten(re.sub(r"=[^;]+", "=***", raw), 300),
                    fix=(
                        "Set Secure, HttpOnly and SameSite=Lax/Strict on session "
                        "cookies; avoid putting secrets in cookies you do not need."
                    ),
                )
            else:
                self.passed(f"Cookie {name} has Secure/HttpOnly/SameSite")

    def _check_tls(self) -> None:
        if urlsplit(self.base_url).scheme != "https":
            self.add(
                "TLS_NOT_USED",
                "critical",
                "Transport",
                "The audit target does not use HTTPS",
                "All traffic, including login credentials, is unencrypted.",
                fix="Install a valid TLS certificate and redirect HTTP to HTTPS.",
            )
            return
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as tls:
                    cert = tls.getpeercert()
                    not_after = cert.get("notAfter", "")
                    expires_ts = ssl.cert_time_to_seconds(not_after)
                    days = (expires_ts - time.time()) / 86400
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                    self.tls_metrics = {
                        "issuer": issuer.get("organizationName")
                        or issuer.get("commonName", ""),
                        "subject": subject.get("commonName", ""),
                        "expires": not_after,
                        "days_remaining": round(days, 1),
                        "san_count": len(sans),
                        "san_sample": sans[:8],
                    }
            if days < 0:
                self.add(
                    "TLS_EXPIRED",
                    "critical",
                    "Transport",
                    "TLS certificate has expired",
                    f"The certificate expired on {not_after}.",
                    fix="Renew the certificate immediately.",
                )
            elif days < 14:
                self.add(
                    "TLS_EXPIRING",
                    "high",
                    "Transport",
                    "TLS certificate expires very soon",
                    f"Only {days:.1f} days remain (expires {not_after}).",
                    fix="Renew the certificate and verify automatic renewal.",
                )
            elif days < 30:
                self.add(
                    "TLS_EXPIRING",
                    "medium",
                    "Transport",
                    "TLS certificate expires within 30 days",
                    f"{days:.1f} days remain (expires {not_after}).",
                    fix="Renew the certificate and verify automatic renewal.",
                )
            else:
                self.passed(f"TLS certificate is valid for {days:.0f} more days")
        except ssl.SSLError as exc:
            self.add(
                "TLS_ERROR",
                "critical",
                "Transport",
                "TLS certificate validation failed",
                str(exc),
                fix="Install a complete, valid certificate chain for the hostname.",
            )
        except Exception as exc:
            self.warn(f"TLS check could not complete: {type(exc).__name__}: {exc}")

    def _check_http_redirect(self) -> None:
        if urlsplit(self.base_url).scheme != "https":
            return
        http_url = f"http://{urlsplit(self.base_url).netloc}/"
        try:
            # No credentials over plain HTTP: use a clean session for this probe.
            response = self._new_session(include_auth=False).get(
                http_url, timeout=min(self.args.timeout, 15), allow_redirects=False
            )
        except Exception as exc:
            self.warn(f"HTTP-to-HTTPS redirect check failed: {exc}")
            return
        if response.is_redirect or response.status_code in (301, 302, 307, 308):
            location = response.headers.get("Location", "")
            if location.startswith("https://"):
                self.passed("HTTP requests redirect to HTTPS")
                return
        if response.status_code == 200:
            self.add(
                "HTTP_NOT_REDIRECTED",
                "high",
                "Transport",
                "Plain HTTP serves the site without redirecting to HTTPS",
                "Users who type the bare domain can be downgraded to HTTP.",
                evidence=f"HTTP {response.status_code} from {http_url}",
                fix="Configure a 301/308 redirect from http:// to https://.",
            )
        else:
            self.add(
                "HTTP_REDIRECT_UNEXPECTED",
                "low",
                "Transport",
                "HTTP-to-HTTPS redirect is not a permanent redirect",
                f"HTTP returned {response.status_code} instead of 301/308.",
                evidence=f"Location: {response.headers.get('Location', '')}",
                fix="Use a 301 or 308 redirect to the HTTPS URL.",
            )

    def _check_manifest(self, soup: BeautifulSoup) -> None:
        link = soup.find("link", rel=lambda value: value and "manifest" in str(value).lower())
        if not link or not link.get("href"):
            self.add(
                "MANIFEST_MISSING",
                "info",
                "PWA",
                "No web app manifest is declared",
                "The site cannot be installed as a standalone app without a manifest.",
                fix="Add `<link rel=\"manifest\" href=\"/manifest.json\">`.",
            )
            return
        manifest_url = urljoin(self.base_url, link["href"])
        self.resources[manifest_url] = "manifest"
        try:
            response = self._request("GET", manifest_url)
        except Exception as exc:
            self.add(
                "MANIFEST_UNREACHABLE",
                "medium",
                "PWA",
                "Web app manifest could not be fetched",
                f"{type(exc).__name__}: {exc}",
                url=manifest_url,
                fix="Serve manifest.json with HTTP 200 and application/manifest+json.",
            )
            return
        if response.status_code >= 400:
            self.add(
                "MANIFEST_HTTP_ERROR",
                "medium",
                "PWA",
                f"Web app manifest returned HTTP {response.status_code}",
                "The install prompt and PWA metadata will not work.",
                url=manifest_url,
                fix="Fix the manifest path and hosting rewrite.",
            )
            return
        try:
            data = response.json()
        except Exception:
            self.add(
                "MANIFEST_INVALID_JSON",
                "medium",
                "PWA",
                "Web app manifest is not valid JSON",
                "Browsers will ignore a malformed manifest.",
                evidence=shorten(response.text, 300),
                url=manifest_url,
                fix="Validate manifest.json with a JSON parser or Lighthouse.",
            )
            return
        self.manifest = data
        issues: list[str] = []
        for field in ("name", "short_name", "start_url", "display", "icons"):
            if not data.get(field):
                issues.append(f"missing `{field}`")
        if data.get("display") not in ("standalone", "fullscreen", "minimal-ui", "browser"):
            issues.append("display should be standalone/fullscreen/minimal-ui")
        start_url = data.get("start_url")
        if start_url and not same_origin(urljoin(manifest_url, start_url), self.base_url):
            issues.append("start_url points to another origin")
        if issues:
            self.add(
                "MANIFEST_ISSUES",
                "low",
                "PWA",
                "Web app manifest has issues",
                "; ".join(issues),
                evidence=json.dumps(data, ensure_ascii=False)[:600],
                url=manifest_url,
                fix="Fill in the required manifest fields and use a same-origin start_url.",
            )
        icons = data.get("icons") if isinstance(data.get("icons"), list) else []
        declared_sizes: set[str] = set()
        for icon in icons:
            if not isinstance(icon, dict) or not icon.get("src"):
                continue
            icon_url = urljoin(manifest_url, icon["src"])
            self.resources[icon_url] = "image"
            declared_sizes.add(str(icon.get("sizes", "")))
            try:
                icon_response = self._request("GET", icon_url)
            except Exception as exc:
                self.add(
                    "MANIFEST_ICON_UNREACHABLE",
                    "low",
                    "PWA",
                    "Manifest icon could not be fetched",
                    f"{icon_url}: {type(exc).__name__}: {exc}",
                    url=icon_url,
                    fix="Fix the icon path or hosting rewrite.",
                )
                continue
            if icon_response.status_code >= 400:
                self.add(
                    "MANIFEST_ICON_ERROR",
                    "medium",
                    "PWA",
                    f"Manifest icon returned HTTP {icon_response.status_code}",
                    f"Declared size: {icon.get('sizes', '?')}",
                    url=icon_url,
                    fix="Host every icon declared in manifest.json.",
                )
            ctype = icon_response.headers.get("Content-Type", "").lower()
            if not ctype.startswith("image/"):
                self.add(
                    "MANIFEST_ICON_TYPE",
                    "low",
                    "PWA",
                    "Manifest icon has the wrong Content-Type",
                    f"Expected image/*, got {ctype or 'none'}.",
                    url=icon_url,
                    fix="Serve icons as image/png (or the correct image type).",
                )
        if icons and "192x192" not in declared_sizes:
            self.add(
                "MANIFEST_ICON_192",
                "low",
                "PWA",
                "Manifest has no 192x192 icon",
                "Android install prompts prefer a 192x192 icon.",
                url=manifest_url,
                fix="Add a 192x192 PNG icon.",
            )
        if icons and "512x512" not in declared_sizes:
            self.add(
                "MANIFEST_ICON_512",
                "low",
                "PWA",
                "Manifest has no 512x512 icon",
                "A 512x512 icon is required for a richer install experience.",
                url=manifest_url,
                fix="Add a 512x512 PNG icon (and a maskable variant).",
            )
        if not issues and icons:
            self.passed("Web app manifest is valid and its icons are reachable")

    def _check_simple_paths(self, soup: BeautifulSoup) -> None:
        # Favicon / Apple touch icon
        for rel_name, label in (("icon", "favicon"), ("apple-touch-icon", "Apple touch icon")):
            link = soup.find("link", rel=lambda value, rn=rel_name: value and rn in str(value).lower())
            if not link or not link.get("href"):
                self.add(
                    "ICON_MISSING",
                    "info",
                    "PWA",
                    f"{label} is not declared",
                    "Browsers will request /favicon.ico and may show a generic icon.",
                    fix=f"Add a `<link rel=\"{rel_name}\" href=\"...\">` tag.",
                )
                continue
            icon_url = urljoin(self.base_url, link["href"])
            self.resources[icon_url] = "image"
            try:
                response = self._request("GET", icon_url)
                if response.status_code >= 400:
                    self.add(
                        "ICON_HTTP_ERROR",
                        "low",
                        "PWA",
                        f"{label} returned HTTP {response.status_code}",
                        "The icon may appear broken in browser tabs or install prompts.",
                        url=icon_url,
                        fix="Host the icon at the declared path.",
                    )
                elif not response.headers.get("Content-Type", "").lower().startswith("image/"):
                    self.add(
                        "ICON_CONTENT_TYPE",
                        "low",
                        "PWA",
                        f"{label} has the wrong Content-Type",
                        response.headers.get("Content-Type", ""),
                        url=icon_url,
                        fix="Serve the icon with an image/* Content-Type.",
                    )
                else:
                    self.passed(f"{label} is reachable")
            except Exception as exc:
                self.warn(f"{label} check failed: {exc}")

        for path, label in (
            ("/robots.txt", "robots.txt"),
            ("/sitemap.xml", "sitemap.xml"),
            ("/.well-known/security.txt", "security.txt"),
        ):
            url = urljoin(self.origin + "/", path.lstrip("/"))
            try:
                response = self._request("GET", url)
            except Exception as exc:
                self.warn(f"{label} check failed: {exc}")
                continue
            if response.status_code == 404:
                self.add(
                    "OPTIONAL_FILE_MISSING",
                    "info",
                    "Discoverability",
                    f"{label} was not found",
                    (
                        "This is optional. For a private, noindex portal it is not a "
                        "bug, but a security.txt file helps researchers report issues."
                    ),
                    url=url,
                    fix=(
                        "Add a security.txt with a contact address."
                        if label == "security.txt"
                        else "Add the file only if the site should be crawled/indexed."
                    ),
                )
            elif response.status_code >= 400:
                self.add(
                    "OPTIONAL_FILE_ERROR",
                    "low",
                    "Discoverability",
                    f"{label} returned HTTP {response.status_code}",
                    "Crawlers and security researchers may see an error.",
                    url=url,
                    fix="Return a valid file or a clean 404.",
                )
            else:
                self.passed(f"{label} is reachable")

    # ================================================================== PHASE 2
    def phase_static(
        self, html_text: str, soup: BeautifulSoup, page_url: str | None = None
    ) -> None:
        self.log.info("2/6  Static HTML/JavaScript review")
        page_url = page_url or self.base_url
        text = html_text
        size = len(text.encode("utf-8"))
        inline_scripts = soup.find_all("script", src=False)
        inline_js_bytes = sum(len((s.string or s.get_text() or "").encode("utf-8")) for s in inline_scripts)
        inline_css_bytes = sum(
            len((s.string or s.get_text() or "").encode("utf-8"))
            for s in soup.find_all("style")
        )
        self.html_metrics = {
            "bytes": size,
            "inline_js_bytes": inline_js_bytes,
            "inline_css_bytes": inline_css_bytes,
            "scripts": len(soup.find_all("script")),
            "external_scripts": len(soup.find_all("script", src=True)),
            "stylesheets": len(soup.find_all("link", rel=lambda v: v and "stylesheet" in str(v).lower())),
            "images": len(soup.find_all("img")),
            "forms": len(soup.find_all("form")),
            "inputs": len(soup.find_all(["input", "select", "textarea"])),
            "inline_event_handlers": sum(
                1
                for tag in soup.find_all(True)
                for attr in tag.attrs
                if str(attr).lower().startswith("on")
            ),
        }

        # Document basics
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        if not title:
            self.add("TITLE_MISSING", "medium", "Content", "Page has no <title>", "Tabs and search results show the URL instead.", url=page_url, fix="Add a descriptive <title>.")
        else:
            self.passed(f"Page title is set: {shorten(title, 80)}")
        html_tag = soup.find("html")
        if not html_tag or not html_tag.get("lang"):
            self.add("LANG_MISSING", "low", "Accessibility", "The <html> element has no lang attribute", "Screen readers may pronounce the page with the wrong language.", url=page_url, fix='Add lang="en" (or the correct language) to <html>.')
        viewport = soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})
        if not viewport:
            self.add("VIEWPORT_MISSING", "medium", "Mobile", "No viewport meta tag", "Mobile browsers will render a desktop-width page.", url=page_url, fix='Add `<meta name="viewport" content="width=device-width, initial-scale=1">`.')
        elif "width=device-width" not in (viewport.get("content") or "").lower():
            self.add("VIEWPORT_WEAK", "low", "Mobile", "Viewport meta tag does not use width=device-width", "The page may not scale correctly on phones.", evidence=shorten(viewport.get("content"), 200), url=page_url, fix="Use width=device-width, initial-scale=1.")
        charset = soup.find("meta", attrs={"charset": True})
        if not charset:
            self.add("META_CHARSET_MISSING", "low", "Content", "No meta charset declaration", "The browser may guess the encoding before the HTTP header is applied.", url=page_url, fix='Add `<meta charset="utf-8">` as the first head element.')
        description = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
        if not description:
            self.add("META_DESCRIPTION_MISSING", "info", "Content", "No meta description", "Link previews and search snippets may be poor.", url=page_url, fix="Add a concise meta description.")
        robots = soup.find("meta", attrs={"name": re.compile(r"^(robots|googlebot)$", re.I)})
        if robots and "noindex" in (robots.get("content") or "").lower():
            self.passed("Search-engine indexing is disabled (noindex)")
        refresh = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
        if refresh:
            self.add("META_REFRESH", "low", "Content", "Page uses meta refresh", "Meta refresh is bad for accessibility and back-button behavior.", evidence=shorten(refresh.get("content"), 200), url=page_url, fix="Use an HTTP redirect or client-side routing.")
        base_tag = soup.find("base", href=True)
        if base_tag and not same_origin(urljoin(page_url, base_tag["href"]), page_url):
            self.add("BASE_TAG_EXTERNAL", "medium", "Security headers", "Base URL points to another origin", "Relative URLs could be loaded from an attacker-controlled origin.", evidence=shorten(base_tag["href"], 300), url=page_url, fix="Remove the base tag or use a same-origin URL.")

        # Page weight / caching
        if size > 2_000_000:
            self.add("HTML_HUGE", "high", "Performance", "Home page HTML is over 2 MB", f"The HTML document is {fmt_bytes(size)}. Mobile users on slow networks pay this on every visit.", evidence=f"HTML bytes={size}; inline JS={inline_js_bytes}; inline CSS={inline_css_bytes}", url=page_url, fix="Split JavaScript/CSS into versioned static files, enable long-lived caching, and lazy-load non-critical code.")
        elif size > 1_000_000:
            self.add("HTML_LARGE", "medium", "Performance", "Home page HTML is over 1 MB", f"The HTML document is {fmt_bytes(size)}.", evidence=f"HTML bytes={size}; inline JS={inline_js_bytes}; inline CSS={inline_css_bytes}", url=page_url, fix="Move inline code to cacheable static assets and remove unused code.")
        elif size > 500_000:
            self.add("HTML_WEIGHT", "low", "Performance", "Home page HTML is large", f"The HTML document is {fmt_bytes(size)}.", url=page_url, fix="Review bundle size and caching.")
        if inline_js_bytes > 500_000:
            self.add("INLINE_JS_HUGE", "medium", "Performance", "Most JavaScript is inline and uncacheable", f"{fmt_bytes(inline_js_bytes)} of JavaScript is embedded in the HTML document.", evidence=f"inline JS={inline_js_bytes}; external scripts={self.html_metrics['external_scripts']}", url=page_url, fix="Extract JavaScript into hashed .js files served with long cache lifetimes.")
        if inline_css_bytes > 200_000:
            self.add("INLINE_CSS_HUGE", "low", "Performance", "Large inline CSS block", f"{fmt_bytes(inline_css_bytes)} of CSS is embedded in the HTML.", url=page_url, fix="Move CSS to a cacheable stylesheet and purge unused rules.")

        # Duplicate IDs
        id_values = [
            tag["id"]
            for tag in soup.find_all(id=True)
            if tag.get("id") and "${" not in tag["id"] and "{{" not in tag["id"]
        ]
        duplicates = {key: count for key, count in Counter(id_values).items() if count > 1}
        if duplicates:
            evidence = "; ".join(f"#{k} x{v}" for k, v in list(duplicates.items())[:12])
            self.add("DUPLICATE_IDS", "medium", "HTML quality", "Duplicate element IDs", f"{len(duplicates)} ID value(s) are used more than once; labels, anchors and JavaScript lookups may target the wrong node.", evidence=evidence, url=page_url, fix="Make every id unique or use classes/data attributes.")

        # Images
        images = soup.find_all("img")
        missing_alt = [img for img in images if not img.has_attr("alt")]
        empty_src = [img for img in images if not (img.get("src") or "").strip()]
        if missing_alt:
            severity = "medium" if len(missing_alt) > 5 else "low"
            samples = "; ".join(shorten(img.get("src", "inline"), 120) for img in missing_alt[:6])
            self.add("IMG_ALT_MISSING", severity, "Accessibility", "Images without alt text", f"{len(missing_alt)} of {len(images)} images have no alt attribute.", evidence=samples, url=page_url, fix="Add meaningful alt text, or alt=\"\" for decorative images.")
        if empty_src:
            self.add("IMG_EMPTY_SRC", "medium", "HTML quality", "Images with an empty src", f"{len(empty_src)} image tag(s) have no usable source; browsers may request the current page again.", url=page_url, fix="Remove the image or set a valid src.")
        no_dimensions = [img for img in images if not img.get("width") and not img.get("height")]
        if len(no_dimensions) > 20:
            self.add("IMG_NO_DIMENSIONS", "info", "Performance", "Many images have no width/height", f"{len(no_dimensions)} images can cause layout shift (CLS) while loading.", url=page_url, fix="Set intrinsic width and height attributes or CSS aspect-ratio.")

        # Accessible names for controls
        def accessible_name(tag: Any) -> str:
            bits = [
                tag.get_text(" ", strip=True),
                tag.get("aria-label") or "",
                tag.get("title") or "",
                " ".join(img.get("alt", "") for img in tag.find_all("img")),
            ]
            return " ".join(bit for bit in bits if bit).strip()

        empty_controls = []
        for tag in soup.find_all(["a", "button"]):
            if tag.name == "a" and not tag.get("href"):
                continue
            if not accessible_name(tag):
                empty_controls.append(tag)
        if empty_controls:
            samples = "; ".join(
                f"<{tag.name} class={tag.get('class')}>" for tag in empty_controls[:8]
            )
            self.add("CONTROL_NO_NAME", "medium", "Accessibility", "Links or buttons have no accessible name", f"{len(empty_controls)} control(s) cannot be identified by screen readers.", evidence=samples, url=page_url, fix="Add visible text, aria-label, or alt text to icon-only controls.")

        # Static label heuristic (browser axe is more accurate for hidden tabs)
        unlabeled = 0
        for field in soup.find_all(["input", "select", "textarea"]):
            field_type = (field.get("type") or "").lower()
            if field_type in {"hidden", "submit", "button", "reset", "file"}:
                continue
            has_name = bool(
                field.get("aria-label")
                or field.get("aria-labelledby")
                or field.get("title")
                or field.find_parent("label")
            )
            if not has_name and field.get("id"):
                has_name = bool(soup.find("label", attrs={"for": field["id"]}))
            if not has_name:
                unlabeled += 1
        if unlabeled:
            self.add("FORM_LABELS_STATIC", "info", "Accessibility", "Form controls lack explicit labels in static HTML", f"{unlabeled} controls have no <label for>, aria-label or title. Some may be hidden tab panels; the browser axe scan checks the visible ones.", url=page_url, fix="Associate every visible control with a <label for> or aria-label.")

        # Mixed content
        mixed = []
        for tag_name, attr in (
            ("script", "src"),
            ("link", "href"),
            ("img", "src"),
            ("iframe", "src"),
            ("form", "action"),
            ("video", "poster"),
        ):
            for tag in soup.find_all(tag_name):
                value = tag.get(attr)
                if value and str(value).lower().startswith("http://") and urlsplit(page_url).scheme == "https":
                    mixed.append(f"<{tag_name} {attr}={shorten(value, 120)}>")
        if mixed:
            self.add("MIXED_CONTENT", "high", "Security headers", "HTTPS page loads HTTP resources", "Browsers block or warn about mixed content; active content can be tampered with.", evidence="; ".join(mixed[:8]), url=page_url, fix="Load every resource over HTTPS.")

        # target=_blank / iframes / password autocomplete / JS URLs
        unsafe_blank = [
            a for a in soup.find_all("a", target="_blank")
            if "noopener" not in " ".join(a.get("rel") or []).lower()
            and "noreferrer" not in " ".join(a.get("rel") or []).lower()
        ]
        if unsafe_blank:
            self.add("TARGET_BLANK_NOOPENER", "low", "Security headers", "Links open new tabs without noopener", f"{len(unsafe_blank)} link(s) allow the new page to access window.opener.", url=page_url, fix='Add rel="noopener noreferrer" to target="_blank" links.')

        bad_iframes = [
            iframe for iframe in soup.find_all("iframe")
            if not (iframe.get("title") or iframe.get("aria-label"))
        ]
        if bad_iframes:
            self.add("IFRAME_NO_TITLE", "low", "Accessibility", "Iframes have no title", f"{len(bad_iframes)} iframe(s) cannot be described by screen readers.", url=page_url, fix="Add a descriptive title attribute to every iframe.")

        password_fields = soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})
        missing_autocomplete = [p for p in password_fields if not p.get("autocomplete")]
        if missing_autocomplete:
            names = ", ".join(p.get("id") or p.get("name") or "password" for p in missing_autocomplete[:8])
            self.add("PASSWORD_AUTOCOMPLETE", "low", "Accessibility", "Password fields do not declare autocomplete", f"Missing autocomplete on: {names}. Password managers may behave inconsistently.", url=page_url, fix='Use autocomplete="current-password" for login and "new-password" for registration.')

        forms_with_password = [
            form for form in soup.find_all("form")
            if form.find("input", attrs={"type": re.compile(r"^password$", re.I)})
        ]
        for form in forms_with_password:
            method = (form.get("method") or "get").lower()
            if method == "get":
                self.add("PASSWORD_FORM_GET", "critical", "Security headers", "Password form submits with GET", "Credentials would be placed in the URL, browser history and server logs.", url=page_url, fix="Use method=post over HTTPS and prevent default JS submission.")

        js_urls = [a.get("href") for a in soup.find_all("a", href=True) if str(a["href"]).lower().startswith("javascript:")]
        if js_urls:
            self.add("JAVASCRIPT_URLS", "low", "HTML quality", "Links use javascript: URLs", f"{len(js_urls)} link(s) rely on inline JavaScript instead of real routes.", evidence="; ".join(shorten(x, 100) for x in js_urls[:5]), url=page_url, fix="Use buttons for actions and real href values for navigation.")

        # Same-page fragment targets
        static_ids = set(id_values)
        broken_fragments = []
        for anchor in soup.find_all("a", href=True):
            href = str(anchor["href"]).strip()
            if href.startswith("#") and len(href) > 1 and not href.startswith("#!"):
                fragment = href[1:]
                if fragment not in static_ids:
                    broken_fragments.append(href)
        if broken_fragments:
            self.add("BROKEN_FRAGMENT", "low", "Links", "In-page anchors point to missing IDs", f"{len(broken_fragments)} fragment link(s) have no matching element.", evidence="; ".join(broken_fragments[:10]), url=page_url, fix="Fix the fragment or add the missing id.")

        # External scripts without SRI
        no_sri = []
        for tag_name, attr in (("script", "src"), ("link", "href")):
            for tag in soup.find_all(tag_name):
                value = tag.get(attr)
                if not value:
                    continue
                absolute = urljoin(page_url, value)
                if not same_origin(absolute, page_url) and not tag.get("integrity"):
                    no_sri.append(absolute)
        if no_sri:
            self.add("SRI_MISSING", "low", "Supply chain", "Third-party scripts/styles have no Subresource Integrity", f"{len(no_sri)} cross-origin resource(s) are not pinned to a known hash.", evidence="; ".join(shorten(u, 140) for u in no_sri[:6]), url=page_url, fix="Add integrity + crossorigin to third-party assets when the CDN supports CORS.")

        # Dynamic code evaluation
        inline_text = "\n".join((s.string or s.get_text() or "") for s in inline_scripts)
        if re.search(r"\beval\s*\(", inline_text):
            self.add("EVAL_USAGE", "low", "Security headers", "JavaScript uses eval()", "eval() makes a strict Content-Security-Policy difficult and increases XSS impact.", url=page_url, fix="Remove eval(); use JSON.parse or explicit functions.")
        if re.search(r"\bnew\s+Function\s*\(", inline_text):
            self.add("NEW_FUNCTION_USAGE", "low", "Security headers", "JavaScript uses new Function()", "Dynamic code generation requires unsafe-eval in a CSP.", url=page_url, fix="Replace dynamic code generation with static functions.")
        if self.html_metrics["inline_event_handlers"]:
            self.add("INLINE_HANDLERS", "info", "Security headers", "Page uses inline event handlers", f"{self.html_metrics['inline_event_handlers']} onclick/onchange-style attributes make CSP hardening harder.", url=page_url, fix="Move event handlers into external JavaScript and use addEventListener.")

        # Secrets and client-side credential handling
        self._scan_secrets(text, page_url)
        self._scan_credentials(text, soup, page_url)
        self._read_firebase_config(text)

        # Collect resources for the link checker
        self._collect_resources(soup, page_url, text)

    def _scan_secrets(self, text: str, page_url: str) -> None:
        for code, pattern, severity, label in SECRET_PATTERNS:
            matches = pattern.findall(text)
            if not matches:
                continue
            unique = []
            for match in matches:
                value = match if isinstance(match, str) else str(match)
                if value not in unique:
                    unique.append(value)
            sample = unique[0] if unique else ""
            evidence = f"{len(matches)} match(es); sample: {mask_value(sample) if sample else '?'}"
            if code == "GOOGLE_API_KEY":
                detail = (
                    "A Google/Firebase API key is present in the public HTML. This is "
                    "normal for Firebase web apps, but the key must be restricted by "
                    "Firebase Security Rules, API restrictions and App Check."
                )
                fix = (
                    "Do not treat the web API key as a secret. Verify Firestore/Storage "
                    "rules deny unauthenticated access and enable Firebase App Check."
                )
            else:
                detail = label
                fix = "Remove the secret from the client, rotate it immediately, and load it from a server-side secret store."
            self.add(f"SECRET_{code}", severity, "Secrets", label, detail, evidence=evidence, url=page_url, fix=fix)

    def _scan_credentials(self, text: str, soup: BeautifulSoup, page_url: str) -> None:
        default_password = re.search(
            r"(?i)\b(?:DEFAULT|FALLBACK|MASTER|ADMIN|SCHOOL)_PASSWORD\s*=\s*['\"]([^'\"]{3,128})['\"]",
            text,
        )
        if default_password:
            value = default_password.group(1)
            self.add(
                "CLIENT_DEFAULT_PASSWORD",
                "high",
                "Client-side auth",
                "Hard-coded default password in client code",
                "A fallback password is embedded in JavaScript. If it is not changed, anyone who views the source can enter the protected panel.",
                evidence=f"Constant value: {mask_value(value)} (length {len(value)})",
                url=page_url,
                fix="Remove the fallback. Provision a unique password during setup, force a change on first login, and enforce server-side/Firebase Auth.",
            )

        default_pin = re.search(
            r"(?i)\b(?:DEFAULT|FALLBACK|MASTER|ADMIN)_PIN\s*=\s*['\"]([^'\"]{3,128})['\"]",
            text,
        )
        if default_pin:
            self.add(
                "CLIENT_DEFAULT_PIN",
                "high",
                "Client-side auth",
                "Hard-coded default PIN in client code",
                "Anyone can read the fallback PIN from the public bundle.",
                evidence=f"Constant value: {mask_value(default_pin.group(1))}",
                url=page_url,
                fix="Remove the default PIN and require a unique, server-validated credential.",
            )

        storage_pattern = re.compile(
            r"(localStorage|sessionStorage)\.setItem\(\s*([^,]{1,180}?)\s*,\s*([^;]{1,240}?)\)",
            re.S,
        )
        for match in storage_pattern.finditer(text):
            storage = match.group(1)
            key_expr = shorten(match.group(2), 140)
            value_expr = shorten(match.group(3), 180)
            severity = ""
            reason = ""
            if SENSITIVE_LOCAL_KEYS.search(key_expr) and not re.search(
                r"(?i)(lockout|attempt|test|timestamp|updated|count|length)", key_expr
            ):
                severity = "high"
                reason = "a password/token-like key"
            elif SENSITIVE_PIN_KEYS.search(key_expr) and not SAFE_PIN_KEY_EXCEPTIONS.search(key_expr):
                severity = "medium"
                reason = "a PIN-like key"
            if not severity:
                continue
            # Mask literal values in the evidence snippet.
            value_expr = re.sub(
                r"(['\"])(.{3,}?)\1",
                lambda m: m.group(1) + mask_value(m.group(2)) + m.group(1),
                value_expr,
            )
            self.add(
                f"STORAGE_SENSITIVE_{storage.upper()}",
                severity,
                "Client-side auth",
                f"Sensitive credential stored in {storage}",
                f"The code writes {reason} into browser storage. Any script on the origin, or anyone with device access, can read it.",
                evidence=f"{storage}.setItem({key_expr}, {value_expr})",
                url=page_url,
                fix="Do not store passwords or plaintext PINs in Web Storage. Use httpOnly, Secure cookies or Firebase Auth tokens and store only non-reversible hashes when offline verification is required.",
            )

        if re.search(
            r"(?i)password\s*:\s*(?:localStorage\.getItem|getPassword\s*\()",
            text,
        ):
            self.add(
                "PASSWORD_IN_BACKUP",
                "high",
                "Client-side auth",
                "Password is included in exported backup data",
                "A backup/export function reads the account password and includes it in a downloadable JSON file.",
                evidence="password: localStorage.getItem(PASSWORD_KEY)",
                url=page_url,
                fix="Never export passwords or PINs. Encrypt backups or omit credential fields entirely.",
            )

        if re.search(
            r"getElementById\(\s*['\"]loginPassword['\"]\s*\)\.value\s*!==\s*getPassword\s*\(",
            text,
        ):
            self.add(
                "CLIENT_SIDE_PASSWORD_CHECK",
                "high",
                "Client-side auth",
                "Accountant login is enforced only in client-side JavaScript",
                "The password comparison happens in the browser, so it can be bypassed by editing JavaScript or reading local storage. It is not an authentication boundary.",
                evidence="document.getElementById('loginPassword').value !== getPassword()",
                url=page_url,
                fix="Enforce authentication and authorization on the server (Firebase Auth + Security Rules or a backend API). Treat the client-side password only as a local UX lock.",
            )

    def _read_firebase_config(self, text: str) -> None:
        project = re.search(r"projectId\s*:\s*['\"]([^'\"]+)['\"]", text)
        api_key = re.search(r"apiKey\s*:\s*['\"]([^'\"]+)['\"]", text)
        school = re.search(r"FIREBASE_SCHOOL_ID\s*=\s*['\"]([^'\"]+)['\"]", text)
        auth_domain = re.search(r"authDomain\s*:\s*['\"]([^'\"]+)['\"]", text)
        if not project or not api_key:
            return
        self.firebase_config = {
            "projectId": project.group(1),
            "apiKey": api_key.group(1),
            "schoolId": school.group(1) if school else "main",
            "authDomain": auth_domain.group(1) if auth_domain else "",
        }
        self.add(
            "FIREBASE_CONFIG_PUBLIC",
            "info",
            "Firebase",
            "Firebase configuration is present in public HTML",
            "Firebase web apps must expose the project ID and web API key. This is not a secret by itself; protection depends on Security Rules and App Check.",
            evidence=f"projectId={self.firebase_config['projectId']}; authDomain={self.firebase_config['authDomain'] or '?'}",
            url=self.base_url,
            fix="Verify Firestore/Storage Rules with the emulator, restrict the API key to your domains, and enable App Check.",
        )
        if "appCheck" not in text and "app-check" not in text.lower():
            self.add(
                "FIREBASE_APPCHECK_MISSING",
                "low",
                "Firebase",
                "Firebase App Check does not appear to be initialized",
                "Without App Check, scripted clients can call Firebase APIs with the public web key more easily.",
                url=self.base_url,
                fix="Enable App Check (reCAPTCHA Enterprise/App Attest) and enforce it for Firestore and Auth.",
            )

    def _collect_resources(
        self, soup: BeautifulSoup, page_url: str, text: str
    ) -> None:
        def put(raw: Any, kind: str) -> None:
            if not raw:
                return
            value = str(raw).strip()
            if not value or value.startswith(("data:", "blob:", "about:", "#")):
                return
            if value.lower().startswith(("mailto:", "tel:", "javascript:")):
                return
            absolute = urljoin(page_url, value)
            if urlsplit(absolute).scheme not in ("http", "https"):
                return
            absolute = urlunsplit((*urlsplit(absolute)[:4], ""))
            old = self.resources.get(absolute)
            if old is None or (old == "page" and kind != "page"):
                self.resources[absolute] = kind

        for tag in soup.find_all("script", src=True):
            put(tag.get("src"), "js")
        for tag in soup.find_all("link", href=True):
            rel = " ".join(tag.get("rel") or []).lower()
            if "stylesheet" in rel:
                put(tag.get("href"), "css")
            elif "manifest" in rel:
                put(tag.get("href"), "manifest")
            elif any(x in rel for x in ("icon", "apple-touch-icon", "preload", "modulepreload")):
                put(tag.get("href"), "image" if "icon" in rel else "asset")
        for tag in soup.find_all("img"):
            put(tag.get("src"), "image")
            for part in (tag.get("srcset") or "").split(","):
                put(part.strip().split(" ")[0] if part.strip() else "", "image")
        for tag in soup.find_all("source"):
            put(tag.get("src"), "asset")
            put(tag.get("srcset"), "image")
        for tag in soup.find_all("video"):
            put(tag.get("poster"), "image")
        for tag in soup.find_all("iframe", src=True):
            put(tag.get("src"), "page")
        for tag in soup.find_all("form", action=True):
            put(tag.get("action"), "page")
        for tag in soup.find_all("a", href=True):
            href = str(tag["href"]).strip()
            if href and not href.startswith("#"):
                put(href, "page")
        for style_text in [s.get_text() for s in soup.find_all("style")] + [
            tag.get("style", "") for tag in soup.find_all(style=True)
        ]:
            for match in re.finditer(r"url\(\s*['\"]?([^'\")\s]+)", style_text or ""):
                put(match.group(1), "asset")
        # Also catch absolute URLs assigned in inline JS (API endpoints, workers).
        for match in re.finditer(r"https?://[^\s'\"<>)]+", text):
            url = match.group(0).rstrip(".,;")
            if any(ext in url.lower() for ext in (".js", ".css", ".png", ".jpg", ".svg", ".json", ".woff", ".woff2")):
                put(url, "asset")

    # ================================================================== PHASE 3
    def phase_crawl(self) -> None:
        self.log.info("3/6  Crawling same-origin HTML links")
        if not self.root_soup:
            return
        max_pages = max(1, self.args.max_pages)
        if max_pages == 1:
            return
        seen_pages = {self.base_url.rstrip("/")}
        queue: list[tuple[str, BeautifulSoup]] = []
        for anchor in self.root_soup.find_all("a", href=True):
            href = str(anchor["href"]).strip()
            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            absolute = urljoin(self.base_url, href)
            absolute = urlunsplit((*urlsplit(absolute)[:4], ""))
            parsed = urlsplit(absolute)
            if parsed.scheme not in ("http", "https") or parsed.netloc != urlsplit(self.base_url).netloc:
                continue
            if is_asset_url(absolute):
                continue
            key = absolute.rstrip("/")
            if key in seen_pages:
                continue
            seen_pages.add(key)
            queue.append((absolute, self.root_soup))
        while queue and len(self.crawled_pages) < max_pages - 1:
            page_url, _ = queue.pop(0)
            try:
                response = self.session.get(page_url, timeout=self.args.timeout)
            except Exception as exc:
                self.warn(f"Crawl failed for {page_url}: {exc}")
                continue
            content_type = response.headers.get("Content-Type", "").lower()
            record = {
                "url": redact_url(page_url),
                "status": response.status_code,
                "content_type": content_type,
                "bytes": len(response.content),
            }
            self.crawled_pages.append(record)
            if response.status_code >= 400 or "html" not in content_type:
                continue
            page_soup = BeautifulSoup(
                response.content.decode(response.encoding or "utf-8", errors="replace"),
                "html.parser",
            )
            self._collect_resources(
                page_soup,
                page_url,
                response.content.decode(response.encoding or "utf-8", errors="replace"),
            )
            for anchor in page_soup.find_all("a", href=True):
                href = str(anchor["href"]).strip()
                if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue
                absolute = urljoin(page_url, href)
                absolute = urlunsplit((*urlsplit(absolute)[:4], ""))
                parsed = urlsplit(absolute)
                if parsed.scheme not in ("http", "https") or parsed.netloc != urlsplit(self.base_url).netloc:
                    continue
                if is_asset_url(absolute):
                    continue
                key = absolute.rstrip("/")
                if key in seen_pages:
                    continue
                seen_pages.add(key)
                queue.append((absolute, page_soup))
        if self.crawled_pages:
            self.passed(f"Crawled {len(self.crawled_pages)} additional same-origin page(s)")
        else:
            self.passed("No additional same-origin HTML links were found to crawl")

    # ================================================================== PHASE 4
    def phase_browser(self) -> None:
        self.log.info("4/6  Real Chromium browser: console, network, axe, responsive")
        if not HAS_PLAYWRIGHT:
            self.warn(
                "Playwright is not installed. Browser checks were skipped. "
                "Install with: pip install playwright && python -m playwright install chromium"
            )
            return
        try:
            with sync_playwright() as playwright:
                launch_kwargs: dict[str, Any] = {
                    "headless": not self.args.headed,
                    "slow_mo": self.args.slowmo or 0,
                }
                if self.args.proxy:
                    launch_kwargs["proxy"] = {"server": self.args.proxy}
                browser = playwright.chromium.launch(**launch_kwargs)
                context_kwargs: dict[str, Any] = {
                    "viewport": {"width": 1440, "height": 900},
                    "locale": "en-US",
                    "color_scheme": "light",
                    "ignore_https_errors": self.args.insecure,
                }
                if self.args.user_agent:
                    context_kwargs["user_agent"] = self.args.user_agent
                if self.args.storage_state:
                    state_path = Path(self.args.storage_state).expanduser()
                    if not state_path.exists():
                        raise FileNotFoundError(f"Storage state not found: {state_path}")
                    context_kwargs["storage_state"] = str(state_path)
                auth_headers = {}
                for raw in self.args.header or []:
                    if ":" in raw:
                        name, value = raw.split(":", 1)
                        auth_headers[name.strip()] = value.strip()
                context = browser.new_context(**context_kwargs)
                if auth_headers:
                    # Playwright's extra_http_headers would leak Authorization to
                    # every third-party request (Google CDN, WhatsApp, ...). Scope
                    # the headers to the audited origin only.
                    def _scoped_headers(route: Any) -> None:
                        try:
                            if same_origin(route.request.url, self.base_url):
                                merged = dict(route.request.headers)
                                merged.update(auth_headers)
                                route.continue_(headers=merged)
                            else:
                                route.continue_()
                        except Exception:
                            try:
                                route.continue_()
                            except Exception:
                                pass

                    context.route("**/*", _scoped_headers)
                if self.args.cookie:
                    cookies = []
                    for raw in self.args.cookie:
                        if "=" in raw:
                            name, value = raw.split("=", 1)
                            cookies.append(
                                {
                                    "name": name.strip(),
                                    "value": value.strip(),
                                    "url": self.base_url,
                                }
                            )
                    if cookies:
                        context.add_cookies(cookies)
                page = context.new_page()
                page.set_default_timeout(min(self.args.timeout * 1000, 60_000))
                page.set_default_navigation_timeout(min(self.args.timeout * 1000, 60_000))

                def on_console(message: Any) -> None:
                    if message.type not in ("error", "warning"):
                        return
                    location = message.location or {}
                    self.console_messages.append(
                        {
                            "type": message.type,
                            "text": shorten(message.text, 1200),
                            "url": redact_url(location.get("url", "")),
                            "line": str(location.get("lineNumber", "")),
                        }
                    )

                def on_pageerror(error: Any) -> None:
                    self.page_errors.append(shorten(str(error), 1500))

                def on_requestfailed(request: Any) -> None:
                    failure = ""
                    try:
                        failure = request.failure or ""
                    except Exception:
                        pass
                    if "ERR_ABORTED" in failure:
                        return
                    self.browser_failures.append(
                        {
                            "url": redact_url(request.url),
                            "failure": shorten(failure, 300),
                            "type": str(getattr(request, "resource_type", "")),
                        }
                    )

                def on_response(response: Any) -> None:
                    try:
                        if len(self.browser_responses) > 500:
                            return
                        url = response.url
                        existing = self.browser_responses.get(url)
                        item = {
                            "status": response.status,
                            "content_type": response.headers.get("content-type", ""),
                            "method": response.request.method,
                            "resource_type": response.request.resource_type,
                        }
                        if existing is None or response.status >= 400:
                            self.browser_responses[url] = item
                    except Exception:
                        pass

                def on_dialog(dialog: Any) -> None:
                    self.dialogs.append(f"{dialog.type}: {shorten(dialog.message, 300)}")
                    try:
                        dialog.dismiss()
                    except Exception:
                        pass

                page.on("console", on_console)
                page.on("pageerror", on_pageerror)
                page.on("requestfailed", on_requestfailed)
                page.on("response", on_response)
                page.on("dialog", on_dialog)

                goto_response = None
                try:
                    goto_response = page.goto(
                        self.base_url, wait_until="domcontentloaded"
                    )
                    try:
                        page.wait_for_load_state("load", timeout=15_000)
                    except PlaywrightTimeout:
                        pass
                    try:
                        page.wait_for_load_state("networkidle", timeout=8_000)
                    except PlaywrightTimeout:
                        pass
                    page.wait_for_timeout(self.args.wait)
                except Exception as exc:
                    self.add(
                        "BROWSER_NAVIGATION_FAILED",
                        "high",
                        "Browser",
                        "Page failed to load in a real browser",
                        f"{type(exc).__name__}: {exc}",
                        url=self.base_url,
                        fix="Check the JavaScript console, CSP, hosting logs and the main bundle.",
                    )

                if goto_response is not None and goto_response.status >= 400:
                    self.add(
                        "BROWSER_HTTP_ERROR",
                        "high",
                        "Browser",
                        f"Browser received HTTP {goto_response.status} for the main page",
                        "Real users would see an error page.",
                        url=self.base_url,
                        fix="Fix the route or hosting rewrite.",
                    )

                metrics = page.evaluate(BROWSER_METRICS_JS)
                raw_links = metrics.pop("links", [])
                self.browser_metrics["main"] = metrics
                self._analyze_browser_metrics(metrics)

                # Dynamic links discovered in the rendered DOM.
                for link in raw_links:
                    if link.startswith(("http://", "https://")):
                        self.resources.setdefault(link, "page")

                self._screenshot(page, "screenshot-desktop.png")
                self._run_axe(page)
                self._check_responsive(page)

                browser.close()
        except Exception as exc:
            self.warn(f"Browser audit failed: {type(exc).__name__}: {exc}")
            if self.args.headed:
                self.warn(
                    "Headed mode requires a desktop session. Run with --headed locally, "
                    "or remove --headed on a headless server."
                )

    def _analyze_browser_metrics(self, metrics: dict[str, Any]) -> None:
        title = metrics.get("title") or ""
        if not title:
            self.add("BROWSER_TITLE_EMPTY", "medium", "Browser", "Rendered page has no title", "The browser tab is unnamed.", fix="Set document.title after the app boots.")
        if metrics.get("bodyTextLen", 0) < 50:
            self.add("BROWSER_BLANK", "high", "Browser", "Page appears blank after load", f"Only {metrics.get('bodyTextLen', 0)} characters of visible text were rendered.", url=self.base_url, fix="Check for a JavaScript error, failed bundle load, or an empty root element.")
        if metrics.get("hasUndefined"):
            self.add("BROWSER_UNDEFINED_TEXT", "low", "Frontend bugs", "The rendered page contains the word 'undefined'", "A template or data binding is probably missing a value.", url=self.base_url, fix="Guard optional values and provide a fallback UI.")
        if metrics.get("hasNaN"):
            self.add("BROWSER_NAN_TEXT", "low", "Frontend bugs", "The rendered page contains 'NaN'", "A numeric calculation produced Not-a-Number.", url=self.base_url, fix="Validate numeric inputs and guard calculations.")
        if metrics.get("hasObjectObject"):
            self.add("BROWSER_OBJECT_TEXT", "low", "Frontend bugs", "The rendered page contains '[object Object]'", "An object was interpolated into a string instead of a display value.", url=self.base_url, fix="Format objects explicitly before rendering.")
        if metrics.get("dialogsVisible", 0):
            self.passed(f"Modal/dialog rendered ({metrics['dialogsVisible']} visible container(s))")

        # Sensitive browser storage keys (values are never collected).
        for key in metrics.get("localStorageKeys", []):
            if SENSITIVE_LOCAL_KEYS.search(key) and not re.search(
                r"(?i)(lockout|attempt|test|timestamp|updated|count|length)", key
            ):
                self.add(
                    "BROWSER_STORAGE_PASSWORD",
                    "high",
                    "Client-side auth",
                    "Credential-like key found in localStorage",
                    f"localStorage key `{shorten(key, 100)}` suggests a password/token is stored in readable browser storage.",
                    evidence=f"localStorage keys: {', '.join(metrics.get('localStorageKeys', [])[:12])}",
                    url=self.base_url,
                    fix="Store only non-sensitive UI state in Web Storage; use httpOnly cookies or short-lived tokens.",
                )
            elif SENSITIVE_PIN_KEYS.search(key) and not SAFE_PIN_KEY_EXCEPTIONS.search(key):
                self.add(
                    "BROWSER_STORAGE_PIN",
                    "medium",
                    "Client-side auth",
                    "PIN-like key found in localStorage",
                    f"localStorage key `{shorten(key, 100)}` suggests PIN data is stored in readable browser storage.",
                    evidence=f"localStorage keys: {', '.join(metrics.get('localStorageKeys', [])[:12])}",
                    url=self.base_url,
                    fix="Store only a salted hash for offline PIN verification, or keep PINs server-side.",
                )

        # Console errors
        error_messages = [m for m in self.console_messages if m["type"] == "error"]
        grouped = Counter((m["text"], m["url"]) for m in error_messages)
        for (text, url), count in grouped.most_common(10):
            severity = "high" if re.search(
                r"uncaught|typeerror|referenceerror|syntaxerror|firebaseerror|permission|denied|failed to fetch",
                text,
                re.I,
            ) else "medium"
            self.add(
                "CONSOLE_ERROR",
                severity,
                "JavaScript",
                "Browser console error",
                f"{count} occurrence(s).",
                evidence=text,
                url=url or self.base_url,
                fix="Open DevTools, reproduce the error, and fix the failing code or network call.",
            )
        warnings = [m for m in self.console_messages if m["type"] == "warning"]
        if len(warnings) > 20:
            self.add("CONSOLE_WARNINGS", "info", "JavaScript", "Many browser console warnings", f"{len(warnings)} warnings were logged.", url=self.base_url, fix="Review noisy deprecation or Firebase warnings.")

        for error in self.page_errors[:10]:
            self.add(
                "PAGE_ERROR",
                "high",
                "JavaScript",
                "Uncaught JavaScript exception",
                error,
                url=self.base_url,
                fix="Fix the uncaught exception; it can break all interactions on the page.",
            )

        for failure in self.browser_failures[:15]:
            is_self = same_origin(failure["url"], self.base_url)
            self.add(
                "NETWORK_FAILED",
                "high" if is_self else "low",
                "Network",
                "Browser request failed",
                f"{failure['failure']} ({failure['type']})",
                evidence=redact_url(failure["url"]),
                url=failure["url"],
                fix="Check the URL, CORS policy, ad-blocker impact and server availability.",
            )

        for url, item in self.browser_responses.items():
            status = item["status"]
            if status < 400:
                continue
            is_self = same_origin(url, self.base_url)
            if status in (401, 403) and re.search(r"(firestore|identitytoolkit|googleapis|firebase)", url, re.I):
                severity = "low"
                detail = "Authentication/authorization was denied. This can be expected before login, but verify it is intentional."
            elif status >= 500:
                severity = "high" if is_self else "medium"
                detail = "The server returned a 5xx error."
            elif status == 404:
                severity = "high" if is_self else "medium"
                detail = "The resource was not found."
            else:
                severity = "medium" if is_self else "low"
                detail = f"The server returned HTTP {status}."
            self.add(
                "BROWSER_HTTP_RESOURCE",
                severity,
                "Network",
                f"Browser resource returned HTTP {status}",
                detail,
                evidence=f"{item['method']} {redact_url(url)} ({item['resource_type']})",
                url=url,
                fix="Fix the failing endpoint or remove the unused request.",
            )

        if self.console_messages or self.page_errors or self.browser_failures:
            self.passed("Browser console/network events were captured")
        else:
            self.passed("No console errors, page errors or failed requests were observed")

        nav = metrics.get("nav") or {}
        load_ms = nav.get("load") or 0
        if load_ms > 8_000:
            self.add("PERF_LOAD_SLOW", "high", "Performance", "Page load took over 8 seconds", f"loadEventEnd={load_ms:.0f} ms.", url=self.base_url, fix="Reduce bundle size, defer non-critical scripts and enable caching/compression.")
        elif load_ms > 5_000:
            self.add("PERF_LOAD_SLOW", "medium", "Performance", "Page load took over 5 seconds", f"loadEventEnd={load_ms:.0f} ms.", url=self.base_url, fix="Reduce bundle size and split long tasks.")
        summary = metrics.get("resourceSummary") or {}
        transfer = summary.get("transferBytes") or 0
        if transfer > 5_000_000:
            self.add("PERF_TRANSFER_LARGE", "high", "Performance", "Page transfers over 5 MB", f"Resource transfer size: {fmt_bytes(transfer)}.", url=self.base_url, fix="Compress images, split bundles and cache static assets.")
        elif transfer > 3_000_000:
            self.add("PERF_TRANSFER_LARGE", "medium", "Performance", "Page transfers over 3 MB", f"Resource transfer size: {fmt_bytes(transfer)}.", url=self.base_url, fix="Review bundle and image sizes.")
        nodes = metrics.get("nodes") or 0
        if nodes > 5_000:
            self.add("PERF_DOM_LARGE", "medium", "Performance", "Rendered DOM is very large", f"{nodes} elements.", url=self.base_url, fix="Virtualize long lists and remove hidden markup.")
        elif nodes > 3_000:
            self.add("PERF_DOM_LARGE", "low", "Performance", "Rendered DOM is large", f"{nodes} elements.", url=self.base_url, fix="Virtualize long lists where possible.")
        if summary.get("count", 0) > 100:
            self.add("PERF_REQUESTS", "low", "Performance", "Many network requests", f"{summary.get('count')} resources were requested.", url=self.base_url, fix="Bundle assets and remove unused third-party scripts.")

    def _screenshot(self, page: Any, filename: str) -> None:
        try:
            path = self.out_dir / filename
            page.screenshot(path=str(path), full_page=True, animations="disabled")
            self.browser_metrics.setdefault("screenshots", []).append(filename)
        except Exception as exc:
            self.warn(f"Screenshot {filename} failed: {exc}")

    def _run_axe(self, page: Any) -> None:
        if self.args.no_axe:
            return
        axe_path = self.cache_dir / "axe.min.js"
        axe_source = ""
        if axe_path.exists() and axe_path.stat().st_size > 100_000:
            axe_source = axe_path.read_text(encoding="utf-8", errors="replace")
        if not axe_source:
            try:
                response = requests.get(
                    AXE_URL,
                    timeout=30,
                    headers={"User-Agent": self.args.user_agent or DEFAULT_UA},
                    proxies={"http": self.args.proxy, "https": self.args.proxy}
                    if self.args.proxy
                    else None,
                )
                response.raise_for_status()
                axe_source = response.text
                axe_path.write_text(axe_source, encoding="utf-8")
            except Exception as exc:
                self.warn(f"axe-core download failed; accessibility scan skipped: {exc}")
                return
        version_match = re.search(r"axe v([\d.]+)", axe_source)
        self.browser_metrics["axe_version"] = version_match.group(1) if version_match else "unknown"
        try:
            try:
                page.evaluate(axe_source)
            except Exception:
                page.add_script_tag(content=axe_source)
            violations = page.evaluate(
                """
                async () => {
                  const result = await axe.run(document, {resultTypes: ['violations']});
                  return result.violations.map(v => ({
                    id: v.id,
                    impact: v.impact,
                    help: v.help,
                    description: v.description,
                    helpUrl: v.helpUrl,
                    nodes: v.nodes.length,
                    samples: v.nodes.slice(0, 3).map(n => ({
                      target: (n.target || []).join(' '),
                      html: (n.html || '').slice(0, 220),
                      summary: (n.failureSummary || '').slice(0, 300)
                    }))
                  }));
                }
                """
            )
        except Exception as exc:
            self.warn(f"axe-core scan failed: {type(exc).__name__}: {exc}")
            return
        impact_to_severity = {
            "critical": "high",
            "serious": "medium",
            "moderate": "low",
            "minor": "info",
        }
        for violation in violations:
            severity = impact_to_severity.get(violation.get("impact"), "low")
            samples = violation.get("samples") or []
            evidence_lines = []
            for sample in samples:
                evidence_lines.append(
                    f"{sample.get('target')} | {sample.get('summary')}"
                )
            self.add(
                f"AXE_{violation.get('id', 'unknown').upper().replace('-', '_')}",
                severity,
                "Accessibility",
                f"Accessibility: {violation.get('help', violation.get('id', 'violation'))}",
                f"{violation.get('description', '')} Affected nodes: {violation.get('nodes', 0)}.",
                evidence="\n".join(evidence_lines),
                url=self.base_url,
                fix=f"See {violation.get('helpUrl', 'https://dequeuniversity.com/rules/axe/')}",
            )
        if violations:
            self.add(
                "AXE_SUMMARY",
                "info",
                "Accessibility",
                f"axe-core reported {len(violations)} accessibility rule violation(s)",
                "See the individual AXE_* findings for selectors and fixes.",
                url=self.base_url,
                fix="Fix high-impact violations first (ARIA roles, names, contrast, forms).",
            )
        else:
            self.passed(f"axe-core {self.browser_metrics.get('axe_version')} found no accessibility violations")

    def _check_responsive(self, page: Any) -> None:
        viewports = [
            ("desktop", 1440, 900),
            ("tablet", 768, 1024),
            ("mobile", 390, 844),
        ]
        self.browser_metrics["viewports"] = {}
        for name, width, height in viewports:
            try:
                page.set_viewport_size({"width": width, "height": height})
                page.wait_for_timeout(700)
                data = page.evaluate(RESPONSIVE_JS)
                self.browser_metrics["viewports"][name] = data
                if data.get("overflow", 0) > 2:
                    severity = "medium" if name == "mobile" else "low"
                    offenders = data.get("offenders", [])
                    self.add(
                        "RESPONSIVE_OVERFLOW",
                        severity,
                        "Mobile",
                        f"Horizontal overflow at {width}x{height}",
                        f"Content is {data['overflow']}px wider than the viewport.",
                        evidence="; ".join(
                            f"{item.get('selector')} (right={item.get('right')}px, width={item.get('width')}px)"
                            for item in offenders[:6]
                        ),
                        url=self.base_url,
                        fix="Constrain widths, use max-width:100%, and avoid fixed-width tables/cards on small screens.",
                    )
                else:
                    self.passed(f"No horizontal overflow at {width}x{height}")
                if name == "mobile":
                    taps = page.evaluate(TAP_TARGET_JS)
                    self.browser_metrics["tap_targets"] = taps
                    if taps.get("count", 0):
                        self.add(
                            "TAP_TARGET_SMALL",
                            "low",
                            "Mobile",
                            "Some touch targets are smaller than 24x24 px",
                            f"{taps['count']} of {taps.get('checked', 0)} controls are below the WCAG 2.5.8 minimum.",
                            evidence="; ".join(
                                f"{item.get('selector')} ({item.get('width')}x{item.get('height')}px)"
                                for item in taps.get("samples", [])[:6]
                            ),
                            url=self.base_url,
                            fix="Increase padding/min-width/min-height to at least 24x24 CSS pixels.",
                        )
                    self._screenshot(page, "screenshot-mobile.png")
            except Exception as exc:
                self.warn(f"Responsive check at {width}x{height} failed: {exc}")
        try:
            page.set_viewport_size({"width": 1440, "height": 900})
        except Exception:
            pass

    # ================================================================== PHASE 5
    def phase_links(self) -> None:
        self.log.info("5/6  Checking links, assets and manifest resources")
        candidates: dict[str, str] = {}
        for url, kind in self.resources.items():
            if not url or url.startswith(("data:", "blob:", "mailto:", "tel:", "javascript:")):
                continue
            if self.args.no_external and not same_origin(url, self.base_url):
                continue
            if url.rstrip("/") == self.base_url.rstrip("/"):
                continue
            candidates[url] = kind
        # Also check same-origin pages discovered by the crawler.
        for page in self.crawled_pages:
            url = page["url"]
            candidates.setdefault(url, "page")

        max_links = max(1, self.args.max_links)
        if len(candidates) > max_links:
            self.warn(
                f"{len(candidates)} links/assets found; checking the first {max_links}. "
                "Use --max-links to raise the limit."
            )
            candidates = dict(list(candidates.items())[:max_links])

        pending: list[tuple[str, str]] = []
        for url, kind in candidates.items():
            observed = self.browser_responses.get(url)
            if observed:
                self._check_content_type(url, observed.get("content_type", ""), kind)
                self.link_results[url] = {
                    "status": observed.get("status"),
                    "content_type": observed.get("content_type", ""),
                    "source": "browser",
                    "kind": kind,
                }
                continue
            pending.append((url, kind))

        if pending:
            workers = min(max(1, self.args.workers), len(pending), 12)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(self._check_one_link, url, kind): (url, kind)
                    for url, kind in pending
                }
                for future in as_completed(futures):
                    url, kind = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "status": None,
                            "error": f"{type(exc).__name__}: {exc}",
                            "kind": kind,
                        }
                    self.link_results[url] = result
                    self._evaluate_link_result(url, kind, result)

        # Already-observed browser failures are reported in the browser phase.
        for url, result in self.link_results.items():
            if result.get("status") is None and result.get("error"):
                self.add(
                    "LINK_UNREACHABLE",
                    "medium" if same_origin(url, self.base_url) else "low",
                    "Links",
                    "Resource could not be reached",
                    result["error"],
                    evidence=redact_url(url),
                    url=url,
                    fix="Check the URL, DNS, TLS and server availability.",
                )
        broken = sum(
            1
            for result in self.link_results.values()
            if isinstance(result.get("status"), int) and result["status"] >= 400
        )
        if broken:
            self.add(
                "LINK_SUMMARY",
                "info",
                "Links",
                f"{broken} linked resource(s) returned an error",
                "See the individual link findings for exact URLs and status codes.",
                url=self.base_url,
                fix="Fix or remove broken links and assets.",
            )
        else:
            self.passed(f"All {len(self.link_results)} checked links/assets responded successfully")
        self.browser_metrics["links_checked"] = len(self.link_results)

    def _check_one_link(self, url: str, kind: str) -> dict[str, Any]:
        session = self._thread_session()
        headers = {"Accept": "*/*"}
        try:
            response = session.head(
                url,
                timeout=min(self.args.timeout, 20),
                allow_redirects=True,
                headers=headers,
            )
            if response.status_code in (403, 405, 501) or response.status_code >= 400:
                response.close()
                response = session.get(
                    url,
                    timeout=min(self.args.timeout, 20),
                    allow_redirects=True,
                    headers=headers,
                    stream=True,
                )
        except Exception:
            response = session.get(
                url,
                timeout=min(self.args.timeout, 20),
                allow_redirects=True,
                headers=headers,
                stream=True,
            )
        try:
            content_type = response.headers.get("Content-Type", "")
            result = {
                "status": response.status_code,
                "final_url": redact_url(response.url),
                "content_type": content_type,
                "bytes": response.headers.get("Content-Length"),
                "kind": kind,
                "source": "http",
            }
        finally:
            response.close()
        return result

    def _evaluate_link_result(self, url: str, kind: str, result: dict[str, Any]) -> None:
        status = result.get("status")
        if status is None:
            return
        if status >= 500:
            self.add(
                "LINK_5XX",
                "high" if same_origin(url, self.base_url) else "medium",
                "Links",
                f"Linked resource returned HTTP {status}",
                "A server error breaks the link or asset.",
                evidence=redact_url(url),
                url=url,
                fix="Fix the server error or remove the link.",
            )
        elif status == 404:
            self.add(
                "LINK_404",
                "high" if same_origin(url, self.base_url) else "medium",
                "Links",
                "Linked resource returned HTTP 404",
                "The link or asset is missing.",
                evidence=redact_url(url),
                url=url,
                fix="Restore the resource, update the link, or remove it.",
            )
        elif status in (401, 403):
            self.add(
                "LINK_BLOCKED",
                "low",
                "Links",
                f"Linked resource returned HTTP {status}",
                "The resource is protected or blocking automated clients. Verify it manually.",
                evidence=redact_url(url),
                url=url,
                fix="Confirm the resource is intentionally protected and reachable for real users.",
            )
        elif status == 429:
            self.add(
                "LINK_RATE_LIMITED",
                "low",
                "Links",
                "Linked resource returned HTTP 429",
                "The server rate-limited the audit request; this is not necessarily a broken link.",
                evidence=redact_url(url),
                url=url,
                fix="Re-test later or reduce request concurrency.",
            )
        elif status >= 400:
            self.add(
                "LINK_4XX",
                "medium" if same_origin(url, self.base_url) else "low",
                "Links",
                f"Linked resource returned HTTP {status}",
                "The link may be broken or require authentication.",
                evidence=redact_url(url),
                url=url,
                fix="Verify the resource manually and fix the link.",
            )
        self._check_content_type(url, result.get("content_type", ""), kind)

    def _check_content_type(self, url: str, content_type: str, kind: str) -> None:
        ctype = (content_type or "").lower()
        path = urlsplit(url).path.lower()
        expected = ""
        if path.endswith((".js", ".mjs")) or kind == "js":
            expected = "javascript"
        elif path.endswith(".css") or kind == "css":
            expected = "text/css"
        elif path.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico")):
            expected = "image/"
        elif path.endswith(".json") or kind == "manifest":
            expected = "json"
        if not expected or not ctype:
            return
        matches = (
            expected in ctype
            or (expected == "javascript" and ("ecmascript" in ctype or "text/plain" in ctype))
            or (expected == "json" and ("json" in ctype or "manifest" in ctype))
        )
        if matches:
            return
        if kind == "js" and "text/html" in ctype:
            severity = "high"
            detail = "A JavaScript URL is serving the SPA/404 HTML page. The script will fail to execute."
        elif kind == "css" and "text/html" in ctype:
            severity = "medium"
            detail = "A stylesheet URL is serving HTML, so styles will not load."
        else:
            severity = "low"
            detail = f"Expected {expected}, got {ctype or 'no Content-Type'}."
        self.add(
            "CONTENT_TYPE_MISMATCH",
            severity,
            "Content",
            "Resource has the wrong Content-Type",
            detail,
            evidence=redact_url(url),
            url=url,
            fix="Serve the correct Content-Type and ensure unknown routes do not return index.html for assets.",
        )

    # ================================================================== PHASE 6
    def phase_firebase(self) -> None:
        if not self.args.firebase_probe:
            return
        self.log.info("6/6  Optional read-only Firebase/Firestore authorization probe")
        if not self.firebase_config:
            self.add(
                "FIREBASE_PROBE_SKIPPED",
                "info",
                "Firebase",
                "Firebase probe skipped",
                "No Firebase projectId/apiKey pair was found in the HTML.",
                url=self.base_url,
                fix="Pass --firebase-probe only for a site that uses Firebase.",
            )
            return
        project = self.firebase_config["projectId"]
        api_key = self.firebase_config["apiKey"]
        school = self.firebase_config.get("schoolId") or "main"
        candidates = [
            (f"schools/{school}/public/parentMarks", "critical", "student marks / parent portal data"),
            (f"schools/{school}/public/studentPins", "critical", "student PIN registry"),
            (f"schools/{school}/public/teacherDirectory", "high", "teacher directory"),
            (f"schools/{school}/public/parentComm", "high", "parent communications"),
            (f"schools/{school}/app/state", "critical", "main school state"),
            (f"schools/{school}/app/marks", "critical", "class-test marks"),
            ("appUsers", "high", "user/role records (collection)"),
        ]
        session = self._new_session(include_auth=False)
        for path, severity, label in candidates:
            is_collection = path == "appUsers"
            url = (
                f"https://firestore.googleapis.com/v1/projects/{project}"
                f"/databases/(default)/documents/{path}"
            )
            params = {"key": api_key, "mask.fieldPaths": "updatedAt"}
            if is_collection:
                params["pageSize"] = 1
            try:
                response = session.get(
                    url,
                    params=params,
                    timeout=min(self.args.timeout, 20),
                    allow_redirects=True,
                )
            except Exception as exc:
                self.firebase_results.append(
                    {
                        "path": path,
                        "label": label,
                        "status": None,
                        "accessible": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            data: dict[str, Any] = {}
            try:
                data = response.json()
            except Exception:
                pass
            accessible = False
            field_names: list[str] = []
            document_count = 0
            if response.status_code == 200:
                if is_collection:
                    documents = data.get("documents") or []
                    document_count = len(documents)
                    accessible = bool(documents)
                    if documents and isinstance(documents[0], dict):
                        field_names = sorted((documents[0].get("fields") or {}).keys())
                else:
                    accessible = bool(data.get("name"))
                    field_names = sorted((data.get("fields") or {}).keys())
            result = {
                "path": path,
                "label": label,
                "status": response.status_code,
                "accessible": accessible,
                "field_names": field_names[:10],
                "document_count": document_count,
            }
            error = data.get("error") if isinstance(data, dict) else None
            if isinstance(error, dict):
                result["error_status"] = error.get("status")
            self.firebase_results.append(result)
            if accessible:
                self.add(
                    "FIREBASE_PUBLIC_DATA",
                    severity,
                    "Firebase / access control",
                    f"Firestore data is readable without authentication: {label}",
                    (
                        "An unauthenticated Firestore REST request returned HTTP 200 "
                        f"for `{path}`. Only the authorization status and field names "
                        "were inspected; field values were not stored or printed."
                    ),
                    evidence=(
                        f"HTTP 200; path={path}; fields={field_names or '[]'}; "
                        + (
                            f"documents={document_count}"
                            if is_collection
                            else "document=readable"
                        )
                    ),
                    url=url,
                    fix=(
                        "Restrict Firestore Security Rules so this path requires an "
                        "authenticated, authorized user. Do not rely on a client-side "
                        "PIN gate. If parents must read their own child's data, use a "
                        "per-student document with rules that check the authenticated UID "
                        "and custom claims, or serve it through a Cloud Function."
                    ),
                )
            elif response.status_code in (401, 403):
                self.passed(f"Firestore denied unauthenticated access to {path}")
            elif response.status_code == 404:
                self.add(
                    "FIREBASE_DOC_NOT_FOUND",
                    "info",
                    "Firebase",
                    f"Firestore path not found: {path}",
                    "The path may not be used by this deployment.",
                    url=url,
                    fix="No action needed if the path is unused.",
                )
            else:
                self.add(
                    "FIREBASE_PROBE_UNEXPECTED",
                    "low",
                    "Firebase",
                    f"Unexpected Firestore probe response for {path}",
                    f"HTTP {response.status_code}: {shorten(json.dumps(data)[:300], 300)}",
                    url=url,
                    fix="Verify the project ID, API key restrictions and Firestore rules.",
                )
        self.browser_metrics["firebase_probe"] = self.firebase_results

    # ================================================================== REPORT
    def _sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEV_ORDER.get(f.severity, 99), f.category.lower(), f.title.lower()),
        )

    def _score(self) -> tuple[int, str, Counter]:
        counts = Counter(f.severity for f in self.findings)
        penalty = sum(SEV_WEIGHT.get(f.severity, 0) for f in self.findings)
        score = max(0, 100 - penalty)
        if counts.get("critical"):
            score = min(score, 39)
        elif counts.get("high"):
            score = min(score, 69)
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"
        return score, grade, counts

    def _summary(self) -> dict[str, Any]:
        score, grade, counts = self._score()
        return {
            "score": score,
            "grade": grade,
            "counts": {sev: counts.get(sev, 0) for sev in SEVERITIES},
            "total": len(self.findings),
            "duration_seconds": round(time.time() - self.start_time, 1),
        }

    def _public_browser_metrics(self) -> dict[str, Any]:
        # Never keep full rendered link URLs (they can contain phone numbers/tokens).
        metrics = json.loads(json.dumps(self.browser_metrics, default=str))
        main = metrics.get("main")
        if isinstance(main, dict):
            links = main.pop("links", [])
            main["link_count"] = len(links)
        return metrics

    def _write_json(self, summary: dict[str, Any]) -> Path:
        path = self.out_dir / "report.json"
        payload = {
            "tool": {
                "name": "site_audit.py",
                "version": VERSION,
                "mode": "non-destructive QA/security audit",
            },
            "target": self.base_url,
            "started_at": datetime.fromtimestamp(self.start_time, timezone.utc).isoformat(timespec="seconds"),
            "finished_at": utc_now(),
            "summary": summary,
            "http": self.http_metrics,
            "tls": self.tls_metrics,
            "html": self.html_metrics,
            "manifest": self.manifest,
            "browser": self._public_browser_metrics(),
            "firebase": self.firebase_results,
            "crawled_pages": self.crawled_pages,
            "links": {
                "checked": len(self.link_results),
                "results": {redact_url(url): result for url, result in self.link_results.items()},
            },
            "findings": [asdict(f) for f in self._sorted_findings()],
            "passed": self.passed_checks,
            "warnings": self.warnings,
            "scope": (
                "Read-only audit. No forms were submitted and no data was changed. "
                "The optional Firestore probe used masked fields and reports only "
                "authorization status and field names."
            ),
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def _write_csv(self) -> Path:
        path = self.out_dir / "report.csv"
        fields = ["severity", "category", "code", "title", "url", "detail", "evidence", "fix"]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for finding in self._sorted_findings():
                row = asdict(finding)
                writer.writerow({key: row.get(key, "") for key in fields})
        return path

    def _html_badge(self, severity: str) -> str:
        return (
            f'<span class="badge badge-{html_lib.escape(severity)}">'
            f"{html_lib.escape(SEV_LABEL.get(severity, severity.upper()))}</span>"
        )

    def _html_finding(self, finding: Finding) -> str:
        evidence = ""
        if finding.evidence:
            evidence = (
                "<details><summary>Evidence</summary><pre>"
                + html_lib.escape(finding.evidence)
                + "</pre></details>"
            )
        fix = ""
        if finding.fix:
            fix = (
                '<p class="fix"><strong>Fix:</strong> '
                + html_lib.escape(finding.fix)
                + "</p>"
            )
        url = ""
        if finding.url:
            url = (
                '<p class="url"><strong>URL:</strong> <code>'
                + html_lib.escape(finding.url)
                + "</code></p>"
            )
        return f"""
        <article class="finding sev-{html_lib.escape(finding.severity)}" data-severity="{html_lib.escape(finding.severity)}">
          <div class="finding-head">
            {self._html_badge(finding.severity)}
            <span class="category">{html_lib.escape(finding.category)}</span>
            <span class="code">{html_lib.escape(finding.code)}</span>
          </div>
          <h3>{html_lib.escape(finding.title)}</h3>
          <p>{html_lib.escape(finding.detail)}</p>
          {url}
          {fix}
          {evidence}
        </article>
        """

    def _html_metric_table(self, data: dict[str, Any]) -> str:
        if not data:
            return "<p class=\"muted\">No data.</p>"
        rows = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            rows.append(
                "<tr><th>"
                + html_lib.escape(str(key))
                + "</th><td>"
                + html_lib.escape(shorten(value, 800))
                + "</td></tr>"
            )
        return "<table class=\"metrics\">" + "".join(rows) + "</table>"

    def _write_html(self, summary: dict[str, Any]) -> Path:
        path = self.out_dir / "report.html"
        findings = self._sorted_findings()
        counts = summary["counts"]
        cards = "".join(self._html_finding(f) for f in findings)
        if not cards:
            cards = '<p class="muted">No findings were produced.</p>'

        passed = "".join(
            f"<li>✅ {html_lib.escape(item)}</li>" for item in self.passed_checks
        ) or '<li class="muted">No passed checks recorded.</li>'
        warnings = "".join(
            f"<li>⚠️ {html_lib.escape(item)}</li>" for item in self.warnings
        ) or '<li class="muted">No audit warnings.</li>'

        screenshots = self.browser_metrics.get("screenshots", [])
        screenshot_html = "".join(
            f'<figure><img src="{html_lib.escape(name)}" alt="{html_lib.escape(name)}"><figcaption>{html_lib.escape(name)}</figcaption></figure>'
            for name in screenshots
        ) or '<p class="muted">No screenshots captured.</p>'

        firebase_rows = ""
        for item in self.firebase_results:
            status = item.get("status")
            accessible = item.get("accessible")
            verdict = "READABLE WITHOUT AUTH" if accessible else ("protected" if status in (401, 403) else "not found / other")
            css = "bad" if accessible else ("good" if status in (401, 403) else "")
            firebase_rows += (
                "<tr>"
                f"<td><code>{html_lib.escape(item.get('path', ''))}</code></td>"
                f"<td>{html_lib.escape(str(status))}</td>"
                f"<td class=\"{css}\">{html_lib.escape(verdict)}</td>"
                f"<td>{html_lib.escape(', '.join(item.get('field_names', [])))}</td>"
                "</tr>"
            )
        firebase_table = (
            "<table class=\"metrics\"><thead><tr><th>Path</th><th>HTTP</th><th>Verdict</th><th>Field names (values not read)</th></tr></thead><tbody>"
            + firebase_rows
            + "</tbody></table>"
            if firebase_rows
            else '<p class="muted">Firebase probe was not enabled. Re-run with <code>--firebase-probe</code> to check Firestore rules.</p>'
        )

        viewport_rows = ""
        for name, data in (self.browser_metrics.get("viewports") or {}).items():
            viewport_rows += (
                "<tr>"
                f"<td>{html_lib.escape(name)}</td>"
                f"<td>{html_lib.escape(str(data.get('viewport')))}px</td>"
                f"<td>{html_lib.escape(str(data.get('scrollWidth')))}px</td>"
                f"<td class=\"{'bad' if data.get('overflow', 0) > 2 else 'good'}\">{html_lib.escape(str(data.get('overflow')))}px</td>"
                "</tr>"
            )
        viewport_table = (
            "<table class=\"metrics\"><thead><tr><th>Viewport</th><th>Width</th><th>Scroll width</th><th>Overflow</th></tr></thead><tbody>"
            + viewport_rows
            + "</tbody></table>"
            if viewport_rows
            else '<p class="muted">Responsive metrics unavailable.</p>'
        )

        summary_line = (
            f"Critical {counts.get('critical', 0)} · High {counts.get('high', 0)} · "
            f"Medium {counts.get('medium', 0)} · Low {counts.get('low', 0)} · "
            f"Info {counts.get('info', 0)}"
        )

        html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Website audit — {html_lib.escape(self.base_url)}</title>
<style>
:root{{
  --bg:#eef2f7; --card:#ffffff; --ink:#0f172a; --muted:#64748b;
  --border:#dbe3ef; --critical:#b91c1c; --high:#dc2626; --medium:#d97706;
  --low:#2563eb; --info:#64748b; --good:#15803d;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}}
.wrap{{max-width:1120px;margin:0 auto;padding:24px}}
header{{background:linear-gradient(135deg,#0f172a,#1e3a8a);color:#fff;border-radius:16px;padding:28px 30px;box-shadow:0 16px 36px rgba(15,23,42,.20)}}
header h1{{margin:0 0 6px;font-size:26px;letter-spacing:-.02em}}
header p{{margin:4px 0;opacity:.86}}
.score-row{{display:flex;gap:22px;align-items:center;flex-wrap:wrap;margin-top:20px}}
.score{{font-size:52px;font-weight:850;line-height:1}}
.grade{{display:inline-block;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.25);padding:6px 12px;border-radius:999px;font-weight:750}}
.summary-line{{margin-top:8px;font-weight:650}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px;box-shadow:0 3px 10px rgba(15,23,42,.04)}}
.card .n{{font-size:26px;font-weight:850}}
.card .l{{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:750}}
.critical .n{{color:var(--critical)}} .high .n{{color:var(--high)}} .medium .n{{color:var(--medium)}} .low .n{{color:var(--low)}} .info .n{{color:var(--info)}}
h2{{margin:28px 0 12px;font-size:20px}}
.panel{{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px 20px;box-shadow:0 3px 10px rgba(15,23,42,.04);margin-bottom:16px;overflow-x:auto}}
.finding{{overflow-wrap:anywhere}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0 16px}}
.filters button{{border:1px solid var(--border);background:#fff;color:var(--ink);padding:7px 12px;border-radius:999px;font-weight:700;cursor:pointer}}
.filters button.active{{background:#1e3a8a;color:#fff;border-color:#1e3a8a}}
.finding{{background:var(--card);border:1px solid var(--border);border-left:6px solid var(--info);border-radius:12px;padding:16px 18px;margin:12px 0;box-shadow:0 3px 10px rgba(15,23,42,.04)}}
.finding.sev-critical{{border-left-color:var(--critical)}} .finding.sev-high{{border-left-color:var(--high)}}
.finding.sev-medium{{border-left-color:var(--medium)}} .finding.sev-low{{border-left-color:var(--low)}}
.finding.sev-info{{border-left-color:var(--info)}}
.finding-head{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
.finding h3{{margin:8px 0 6px;font-size:17px}}
.finding p{{margin:6px 0;color:#334155}}
.badge{{display:inline-block;padding:3px 8px;border-radius:6px;color:#fff;font-size:11px;font-weight:850;letter-spacing:.06em}}
.badge-critical{{background:var(--critical)}} .badge-high{{background:var(--high)}} .badge-medium{{background:var(--medium)}}
.badge-low{{background:var(--low)}} .badge-info{{background:var(--info)}}
.category,.code{{font-size:12px;color:var(--muted);font-weight:650}}
.code{{margin-left:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
.url code{{background:#f1f5f9;padding:2px 6px;border-radius:4px;overflow-wrap:anywhere}}
.fix{{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:8px 10px}}
details{{margin-top:8px}} summary{{cursor:pointer;color:#1d4ed8;font-weight:700}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;font-size:12.5px}}
table.metrics{{width:100%;border-collapse:collapse;font-size:13.5px}}
table.metrics th,table.metrics td{{text-align:left;border-bottom:1px solid var(--border);padding:8px;vertical-align:top;overflow-wrap:anywhere}}
table.metrics th{{color:#475569;width:30%}}
table.metrics thead th{{background:#f8fafc;color:#1e3a8a;width:auto}}
.good{{color:var(--good);font-weight:750}} .bad{{color:var(--high);font-weight:750}}
ul.checks{{margin:0;padding-left:22px}} ul.checks li{{margin:5px 0}}
.screens{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
figure{{margin:0}} figure img{{width:100%;border:1px solid var(--border);border-radius:10px;background:#fff}}
figcaption{{font-size:12px;color:var(--muted);text-align:center;margin-top:4px}}
.two{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.muted{{color:var(--muted)}}
footer{{color:var(--muted);font-size:12.5px;margin:26px 0 10px;text-align:center}}
@media (max-width:760px){{.two,.screens{{grid-template-columns:1fr}} .code{{margin-left:0}} header{{padding:22px}}}}
@media print{{body{{background:#fff}} .filters{{display:none}} .finding,.panel,header{{box-shadow:none}}}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Website audit report</h1>
  <p><strong>{html_lib.escape(self.base_url)}</strong></p>
  <p>Generated {html_lib.escape(utc_now())} · site_audit.py v{html_lib.escape(VERSION)} · {html_lib.escape(str(summary['duration_seconds']))}s</p>
  <div class="score-row">
    <div><div class="score">{summary['score']}<span style="font-size:20px;opacity:.6">/100</span></div><div class="summary-line">{html_lib.escape(summary_line)}</div></div>
    <div class="grade">Grade {html_lib.escape(summary['grade'])}</div>
  </div>
</header>

<div class="grid">
  <div class="card critical"><div class="n">{counts.get('critical',0)}</div><div class="l">Critical</div></div>
  <div class="card high"><div class="n">{counts.get('high',0)}</div><div class="l">High</div></div>
  <div class="card medium"><div class="n">{counts.get('medium',0)}</div><div class="l">Medium</div></div>
  <div class="card low"><div class="n">{counts.get('low',0)}</div><div class="l">Low</div></div>
  <div class="card info"><div class="n">{counts.get('info',0)}</div><div class="l">Info</div></div>
</div>

<div class="panel">
  <h2>Scope and safety</h2>
  <p>This was a read-only audit: no forms were submitted and no data was changed. The optional Firestore probe used masked fields (<code>mask.fieldPaths=updatedAt</code>) and reports only whether a path is readable and its field names. It never prints document values. Run it only against sites you own or are authorized to test.</p>
</div>

<h2>Findings</h2>
<div class="filters" id="filters">
  <button class="active" data-filter="all">All ({len(findings)})</button>
  <button data-filter="critical">Critical ({counts.get('critical',0)})</button>
  <button data-filter="high">High ({counts.get('high',0)})</button>
  <button data-filter="medium">Medium ({counts.get('medium',0)})</button>
  <button data-filter="low">Low ({counts.get('low',0)})</button>
  <button data-filter="info">Info ({counts.get('info',0)})</button>
</div>
<div id="findings">{cards}</div>

<h2>Browser evidence</h2>
<div class="panel">
  <div class="screens">{screenshot_html}</div>
  <h3>Rendered page metrics</h3>
  {self._html_metric_table(self.browser_metrics.get('main', {}))}
  <h3>Responsive layout</h3>
  {viewport_table}
  <h3>Touch targets</h3>
  {self._html_metric_table(self.browser_metrics.get('tap_targets', {}))}
</div>

<h2>Firebase / Firestore authorization probe</h2>
<div class="panel">
  <p class="muted">Read-only, unauthenticated probe. Only status and field names are recorded; values are never stored.</p>
  {firebase_table}
</div>

<div class="two">
  <div class="panel">
    <h2>Passed checks</h2>
    <ul class="checks">{passed}</ul>
  </div>
  <div class="panel">
    <h2>Audit warnings</h2>
    <ul class="checks">{warnings}</ul>
  </div>
</div>

<footer>
  Non-destructive QA/security audit. Not a replacement for a manual penetration test.
  Findings are evidence-based but should be manually confirmed before remediation.
</footer>
</div>
<script>
(function(){{
  var buttons = document.querySelectorAll('#filters button');
  var findings = document.querySelectorAll('#findings .finding');
  buttons.forEach(function(btn){{
    btn.addEventListener('click', function(){{
      buttons.forEach(function(b){{ b.classList.remove('active'); }});
      btn.classList.add('active');
      var f = btn.getAttribute('data-filter');
      findings.forEach(function(card){{
        card.style.display = (f === 'all' || card.getAttribute('data-severity') === f) ? '' : 'none';
      }});
    }});
  }});
}})();
</script>
</body>
</html>
"""
        path.write_text(html_doc, encoding="utf-8")
        return path

    def phase_report(self) -> int:
        summary = self._summary()
        json_path = self._write_json(summary)
        csv_path = self._write_csv()
        html_path = self._write_html(summary)
        counts = summary["counts"]
        icon = {"critical": "✖", "high": "▲", "medium": "●", "low": "◆", "info": "ℹ"}
        print()
        print("=" * 78)
        print(f"  Website audit — {self.base_url}")
        print("=" * 78)
        print(f"  Score: {summary['score']}/100 (grade {summary['grade']})")
        print(
            "  Findings: "
            + " | ".join(
                f"{SEV_LABEL[sev].title()} {counts.get(sev, 0)}" for sev in SEVERITIES
            )
        )
        print(f"  Duration: {summary['duration_seconds']}s")
        print()
        top = [f for f in self._sorted_findings() if f.severity != "info"][:8]
        if top:
            print("  Top findings:")
            for finding in top:
                print(f"    {icon.get(finding.severity, '•')} [{SEV_LABEL[finding.severity]}] {finding.title}")
            print()
        else:
            print("  No actionable findings. 🎉")
            print()
        print(f"  HTML report: {html_path}")
        print(f"  JSON report: {json_path}")
        print(f"  CSV report:  {csv_path}")
        print("=" * 78)
        if self.args.fail_on == "none":
            return 0
        threshold = SEV_ORDER.get(self.args.fail_on, SEV_ORDER["high"])
        if any(SEV_ORDER.get(f.severity, 99) <= threshold for f in self.findings):
            return 1
        return 0

    # ===================================================================== RUN
    def run(self) -> int:
        self.log.info("Auditing %s", self.base_url)
        response, html_text, soup = self.phase_http()
        if response is not None and soup is not None:
            self.phase_static(html_text, soup)
            self.phase_crawl()
            if self.args.no_browser:
                self.passed("Browser checks disabled by --no-browser")
            else:
                self.phase_browser()
            self.phase_links()
            self.phase_firebase()
        else:
            self.warn("Static, browser and link checks skipped because the home page was unreachable.")
        return self.phase_report()


BROWSER_METRICS_JS = r"""
() => {
  const isVisible = (el) => {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width > 1 && r.height > 1;
  };
  const text = document.body ? document.body.innerText : '';
  const nav = (performance.getEntriesByType('navigation') || [])[0] || null;
  const resources = performance.getEntriesByType('resource') || [];
  const byType = {};
  let transfer = 0;
  for (const r of resources) {
    transfer += r.transferSize || 0;
    const t = r.initiatorType || 'other';
    byType[t] = (byType[t] || 0) + 1;
  }
  const ls = [];
  const ss = [];
  try { for (let i = 0; i < localStorage.length; i++) ls.push(localStorage.key(i)); } catch (e) {}
  try { for (let i = 0; i < sessionStorage.length; i++) ss.push(sessionStorage.key(i)); } catch (e) {}
  const dialogs = [...document.querySelectorAll('[role="dialog"], .modal-overlay, .modal-box')].filter(isVisible);
  const headings = [...document.querySelectorAll('h1,h2,h3')].filter(isVisible).slice(0, 10)
    .map(e => (e.innerText || '').trim().slice(0, 100)).filter(Boolean);
  const buttons = [...document.querySelectorAll('button')].filter(isVisible).slice(0, 15)
    .map(e => (e.innerText || e.getAttribute('aria-label') || e.getAttribute('title') || '').trim().slice(0, 60))
    .filter(Boolean);
  const links = [...document.querySelectorAll('a[href]')].filter(isVisible).slice(0, 40)
    .map(a => a.href).filter(h => /^https?:/i.test(h));
  const robotsMeta = document.querySelector('meta[name="robots"]');
  const viewportMeta = document.querySelector('meta[name="viewport"]');
  return {
    title: document.title || '',
    url: location.origin + location.pathname,
    readyState: document.readyState,
    bodyTextLen: (text || '').trim().length,
    nodes: document.getElementsByTagName('*').length,
    scripts: document.scripts.length,
    stylesheets: document.styleSheets.length,
    images: document.images.length,
    forms: document.forms.length,
    inputs: document.querySelectorAll('input,select,textarea').length,
    buttonsCount: document.querySelectorAll('button').length,
    linksCount: document.querySelectorAll('a[href]').length,
    dialogsVisible: dialogs.length,
    headings: headings,
    buttons: buttons,
    links: links,
    localStorageKeys: ls,
    sessionStorageKeys: ss,
    hasUndefined: /\bundefined\b/.test(text || ''),
    hasNaN: /\bNaN\b/.test(text || ''),
    hasObjectObject: (text || '').includes('[object Object]'),
    scrollWidth: document.documentElement.scrollWidth,
    innerWidth: window.innerWidth,
    scrollHeight: document.documentElement.scrollHeight,
    innerHeight: window.innerHeight,
    lang: document.documentElement.lang || '',
    metaRobots: robotsMeta ? (robotsMeta.content || '') : '',
    viewportMeta: viewportMeta ? (viewportMeta.content || '') : '',
    nav: nav ? {
      ttfb: Math.round(nav.responseStart || 0),
      domContentLoaded: Math.round(nav.domContentLoadedEventEnd || 0),
      load: Math.round(nav.loadEventEnd || 0),
      duration: Math.round(nav.duration || 0),
      transferSize: nav.transferSize || 0,
      encodedBodySize: nav.encodedBodySize || 0
    } : null,
    resourceSummary: {
      count: resources.length,
      transferBytes: transfer,
      byType: byType
    },
    jsHeap: (performance.memory && performance.memory.usedJSHeapSize) || null
  };
}
"""

RESPONSIVE_JS = r"""
() => {
  const vw = window.innerWidth;
  const esc = (s) => (window.CSS && CSS.escape) ? CSS.escape(String(s)) : String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  const isVisible = (el) => {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width > 1 && r.height > 1;
  };
  const cssPath = (el) => {
    if (el.id) return '#' + esc(el.id);
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && parts.length < 4) {
      let sel = node.tagName.toLowerCase();
      if (node.classList && node.classList.length) {
        sel += '.' + [...node.classList].slice(0, 2).map(esc).join('.');
      }
      const parent = node.parentElement;
      if (parent) {
        const siblings = [...parent.children].filter(s => s.tagName === node.tagName);
        if (siblings.length > 1) sel += ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')';
      }
      parts.unshift(sel);
      node = node.parentElement;
    }
    return parts.join(' > ');
  };
  const skip = new Set(['html', 'body', 'head', 'title', 'meta', 'link', 'style', 'script']);
  const offenders = [];
  for (const el of document.querySelectorAll('body *')) {
    const tag = el.tagName.toLowerCase();
    if (skip.has(tag) || !isVisible(el)) continue;
    const r = el.getBoundingClientRect();
    if (r.right > vw + 2 || r.left < -2) {
      offenders.push({
        selector: cssPath(el),
        tag: tag,
        left: Math.round(r.left),
        right: Math.round(r.right),
        width: Math.round(r.width)
      });
      if (offenders.length >= 12) break;
    }
  }
  return {
    viewport: vw,
    scrollWidth: document.documentElement.scrollWidth,
    overflow: Math.max(0, document.documentElement.scrollWidth - vw),
    offenders: offenders
  };
}
"""

TAP_TARGET_JS = r"""
() => {
  const esc = (s) => (window.CSS && CSS.escape) ? CSS.escape(String(s)) : String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  const isVisible = (el) => {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width > 1 && r.height > 1;
  };
  const cssPath = (el) => {
    if (el.id) return '#' + esc(el.id);
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && parts.length < 4) {
      let sel = node.tagName.toLowerCase();
      if (node.classList && node.classList.length) {
        sel += '.' + [...node.classList].slice(0, 2).map(esc).join('.');
      }
      const parent = node.parentElement;
      if (parent) {
        const siblings = [...parent.children].filter(s => s.tagName === node.tagName);
        if (siblings.length > 1) sel += ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')';
      }
      parts.unshift(sel);
      node = node.parentElement;
    }
    return parts.join(' > ');
  };
  const nodes = [...document.querySelectorAll('button, input:not([type="hidden"]), select, textarea, [role="button"]')]
    .filter(el => isVisible(el) && !el.disabled);
  const samples = [];
  let checked = 0;
  for (const el of nodes) {
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (['checkbox', 'radio', 'range'].includes(type)) continue;
    checked++;
    const r = el.getBoundingClientRect();
    if (r.width < 24 || r.height < 24) {
      samples.push({
        selector: cssPath(el),
        tag: el.tagName.toLowerCase(),
        width: Math.round(r.width),
        height: Math.round(r.height)
      });
    }
  }
  return {checked: checked, count: samples.length, samples: samples.slice(0, 10)};
}
"""


def save_auth_state(args: argparse.Namespace) -> int:
    if not HAS_PLAYWRIGHT:
        print("Playwright is required: pip install playwright && python -m playwright install chromium")
        return 2
    if not sys.stdin.isatty():
        print("--save-auth needs an interactive terminal so you can log in manually.")
        return 2
    target = args.url or DEFAULT_URL
    try:
        with sync_playwright() as playwright:
            launch_kwargs: dict[str, Any] = {"headless": False}
            if args.proxy:
                launch_kwargs["proxy"] = {"server": args.proxy}
            browser = playwright.chromium.launch(**launch_kwargs)
            context_kwargs: dict[str, Any] = {}
            if args.insecure:
                context_kwargs["ignore_https_errors"] = True
            context = browser.new_context(**context_kwargs)
            page = context.new_page()
            page.goto(target, wait_until="domcontentloaded", timeout=args.timeout * 1000)
            print()
            print("A Chromium window is open. Log in with your own account.")
            print("Do not enter credentials into a site you do not trust.")
            print("When the authenticated page is fully loaded, press Enter here.")
            input()
            state_path = Path(args.save_auth).expanduser().resolve()
            state_path.parent.mkdir(parents=True, exist_ok=True)
            context.storage_state(path=str(state_path))
            print(f"Saved authenticated browser state to: {state_path}")
            browser.close()
        return 0
    except Exception as exc:
        print(f"Could not save auth state: {type(exc).__name__}: {exc}")
        print("On a headless server, run this command on a desktop machine with a display.")
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="site_audit.py",
        description=(
            "Real-world, non-destructive website audit: HTTP/TLS/headers, static "
            "code review, Chromium console/network checks, axe accessibility, "
            "responsive layout, link checking and optional Firebase rules probe."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python site_audit.py demo-web.com/\n"
            "  python site_audit.py demo-web.com/ --headed --firebase-probe\n"
            "  python site_audit.py demo-web.com/ --no-browser --fail-on none\n"
            "  python site_audit.py demo-web.com/ --save-auth auth.json\n"
            "  python site_audit.py demo-web.com/ --storage-state auth.json\n"
        ),
    )
    parser.add_argument("url", nargs="?", default=DEFAULT_URL, help=f"Target URL (default: {DEFAULT_URL})")
    parser.add_argument("--out", default="audit-report", help="Report directory (default: audit-report)")
    parser.add_argument("--cache-dir", default=".audit-cache", help="Cache directory for axe-core (default: .audit-cache)")
    parser.add_argument("--timeout", type=int, default=20, help="Per-request timeout in seconds (default: 20)")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent link checks (default: 8)")
    parser.add_argument("--max-links", type=int, default=80, help="Maximum links/assets to check (default: 80)")
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum same-origin pages to crawl (default: 10)")
    parser.add_argument("--no-browser", action="store_true", help="Skip Playwright browser checks")
    parser.add_argument("--headed", action="store_true", help="Show the Chromium window while testing")
    parser.add_argument("--slowmo", type=int, default=0, help="Slow Playwright actions by N ms (debugging)")
    parser.add_argument("--wait", type=int, default=3000, help="Extra wait after page load in ms (default: 3000)")
    parser.add_argument("--storage-state", metavar="PATH", help="Playwright storage state JSON for authenticated testing")
    parser.add_argument("--save-auth", metavar="PATH", help="Open a browser, let the user log in, then save storage state")
    parser.add_argument("--cookie", action="append", metavar="NAME=VALUE", help="Cookie for authenticated testing (repeatable)")
    parser.add_argument("--header", action="append", metavar="NAME: VALUE", help="Extra HTTP header (repeatable)")
    parser.add_argument("--proxy", help="HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--insecure", action="store_true", help="Ignore TLS certificate errors (staging only)")
    parser.add_argument("--user-agent", help="Override the User-Agent")
    parser.add_argument("--no-axe", action="store_true", help="Skip the axe-core accessibility scan")
    parser.add_argument("--no-external", action="store_true", help="Do not check external links/assets")
    parser.add_argument("--firebase-probe", action="store_true", help="Run the opt-in read-only Firestore authorization probe")
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITIES) + ["none"],
        default="high",
        help="Exit 1 if a finding at/above this severity exists (default: high; use none to always exit 0)",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )
    if args.insecure:
        try:
            requests.packages.urllib3.disable_warnings()
        except Exception:
            pass
    if args.save_auth:
        return save_auth_state(args)
    auditor = Auditor(args)
    try:
        return auditor.run()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return 130
    except Exception as exc:
        logging.exception("Audit failed: %s", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())





