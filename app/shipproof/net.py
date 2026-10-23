"""HTTP client with SSRF protection, hard size caps and a time budget.

Rules we never break:
  * only http/https
  * never touch a non-public IP (loopback, RFC1918, link-local, metadata IPs)
  * re-check every redirect hop
  * cap body size and total time
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import config


class BlockedTarget(Exception):
    """The URL points somewhere we refuse to scan."""


@dataclass
class FetchResult:
    url: str = ""
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    header_list: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    error: str = ""
    cert_error: bool = False
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status >= 200 and self.status < 400 and not self.error

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def header_all(self, name: str) -> list[str]:
        return [v for (k, v) in self.header_list if k.lower() == name.lower()]


class Budget:
    """Wall-clock budget shared by every request in one scan."""

    def __init__(self, seconds: float) -> None:
        self._end = time.monotonic() + max(1.0, seconds)

    def left(self) -> float:
        return max(0.0, self._end - time.monotonic())

    def expired(self) -> bool:
        return self.left() <= 0.75

    def timeout(self, preferred: float | None = None) -> float:
        return max(1.0, min(preferred or config.HTTP_TIMEOUT, self.left()))


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise BlockedTarget("empty URL")
    if len(raw) > 2048:
        raise BlockedTarget("URL too long")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw):
        raw = "https://" + raw
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise BlockedTarget("only http and https URLs can be scanned")
    host = parts.hostname or ""
    if not host or "." not in host and host != "localhost":
        raise BlockedTarget("URL needs a public domain name")
    # strip userinfo, fragments and normalise the path
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc, parts.path or "/", parts.query, "")
    )


def check_public_host(host: str) -> None:
    """Resolve a hostname and refuse anything that is not a public IP."""
    if not host:
        raise BlockedTarget("missing hostname")
    if config.ALLOW_PRIVATE:
        return
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise BlockedTarget("hostname could not be resolved") from exc
    if not infos:
        raise BlockedTarget("hostname could not be resolved")
    for info in infos:
        raw_ip = str(info[4][0]).split("%")[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            raise BlockedTarget("unparseable resolved address")
        if not ip.is_global:
            raise BlockedTarget("target is not a public internet address")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_repeats = 2

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        target = urllib.parse.urljoin(req.full_url, newurl)
        parts = urllib.parse.urlsplit(target)
        if parts.scheme not in ("http", "https"):
            raise BlockedTarget("redirect to a non-http(s) scheme")
        check_public_host(parts.hostname or "")
        return super().redirect_request(req, fp, code, msg, headers, target)


def _read_limited(resp, limit: int) -> bytes:  # noqa: ANN001
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        try:
            chunk = resp.read(min(65536, limit - total))
        except (socket.timeout, TimeoutError):
            break
        except Exception:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def safe_fetch(
    url: str,
    *,
    budget: Budget | None = None,
    max_bytes: int | None = None,
    timeout: float | None = None,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
) -> FetchResult:
    """GET a URL with SSRF + size + time protection. Never raises for network errors."""
    started = time.monotonic()
    result = FetchResult(url=url)
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise BlockedTarget("only http and https URLs can be scanned")
        check_public_host(parts.hostname or "")
    except BlockedTarget as exc:
        result.error = f"blocked: {exc}"
        return result

    limit = max_bytes or config.MAX_BYTES_PER_URL
    effective_timeout = budget.timeout(timeout) if budget else (timeout or config.HTTP_TIMEOUT)
    headers = {
        "User-Agent": config.USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)

    request = urllib.request.Request(url, method=method, headers=headers)
    opener = urllib.request.build_opener(_SafeRedirectHandler())
    try:
        with opener.open(request, timeout=effective_timeout) as resp:
            body = _read_limited(resp, limit)
            result.status = int(getattr(resp, "status", resp.getcode()) or 0)
            result.url = resp.geturl()
            result.header_list = list(resp.headers.items())
            result.headers = {k.lower(): v for k, v in resp.headers.items()}
            result.body = body
    except urllib.error.HTTPError as exc:
        # The server answered — that is data, not a failure.
        try:
            body = _read_limited(exc, limit)
        except Exception:
            body = b""
        result.status = int(exc.code)
        result.url = getattr(exc, "url", url) or url
        try:
            result.header_list = list(exc.headers.items())
            result.headers = {k.lower(): v for k, v in exc.headers.items()}
        except Exception:
            pass
        result.body = body
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        text = str(reason)
        if "CERTIFICATE_VERIFY_FAILED" in text.upper() or isinstance(
            reason, __import__("ssl").SSLCertVerificationError
        ):
            result.cert_error = True
            result.error = "certificate could not be verified"
        elif "Name or service not known" in text or "getaddrinfo" in text:
            result.error = "domain does not resolve"
        else:
            result.error = text[:200]
    except (socket.timeout, TimeoutError):
        result.error = "timed out"
    except BlockedTarget as exc:
        result.error = f"blocked: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        result.error = f"{type(exc).__name__}: {exc}"[:200]
    result.elapsed_ms = int((time.monotonic() - started) * 1000)
    return result


def origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def join(base: str, path: str) -> str:
    return urllib.parse.urljoin(base if base.endswith("/") else base + "/", path)


def same_origin(a: str, b: str) -> bool:
    return origin(a).lower() == origin(b).lower()
