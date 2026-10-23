"""Health monitoring: periodic TCP ping + traffic stats helpers."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

try:
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]

try:
    from aiohttp_socks import ProxyConnector
except ImportError:  # pragma: no cover
    ProxyConnector = None  # type: ignore[assignment]

SPEED_DOWN_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
SPEED_UP_URL = "https://speed.cloudflare.com/__up"
SPEED_UP_BYTES = 4_000_000
SPEED_TIMEOUT = 20.0

# Default target for HTTP-mode pings: any 204-returning URL is fine and the
# body is never read, so it costs a couple of bytes per probe.
DEFAULT_PING_URL = "https://www.gstatic.com/generate_204"


def _connector_for(proxy_url: Optional[str]):
    """Return an aiohttp connector. SOCKS5 proxy if given, else default."""
    if not proxy_url:
        return None
    if ProxyConnector is None:
        return None
    try:
        return ProxyConnector.from_url(proxy_url)
    except Exception:
        return None


async def tcp_ping(host: str, port: int, timeout: float = 5.0) -> Optional[int]:
    """Open a TCP connection and return latency in ms, or None on failure."""
    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        fut = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(fut, timeout=timeout)
        latency_ms = int((loop.time() - start) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        return latency_ms
    except (OSError, asyncio.TimeoutError):
        return None


async def tls_handshake(host: str, port: int, sni: str, timeout: float = 5.0) -> bool:
    """True if a TLS handshake with `sni` completes.

    A bare TCP connect proves nothing about a TLS/REALITY node: some hosts accept
    the connection and then never answer the ClientHello (seen on the whole
    81.163.23.111 family — 14 ms TCP, dead tunnel), so the panel used to show a
    green ping for servers that cannot carry a single byte.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        fut = asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or host)
        _, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        return True
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
        return False


async def tcp_ping_samples(
    host: str,
    port: int,
    count: int = 4,
    timeout: float = 3.0,
    gap: float = 0.15,
) -> list[int]:
    samples: list[int] = []
    for i in range(count):
        ms = await tcp_ping(host, port, timeout=timeout)
        if ms is not None:
            samples.append(ms)
        if i < count - 1:
            await asyncio.sleep(gap)
    return samples


def compute_jitter(samples: list[int]) -> int:
    if len(samples) < 2:
        return 0
    diffs = [abs(samples[i] - samples[i - 1]) for i in range(1, len(samples))]
    return int(round(sum(diffs) / len(diffs)))


async def http_ping(
    url: str, proxy_url: Optional[str] = None, timeout: float = 3.0
) -> Optional[int]:
    """Measure time-to-response-headers of a GET request, in milliseconds.

    With `proxy_url` the request travels through the local SOCKS proxy, so the
    number reflects the real tunnel (DNS + handshake + request) rather than the
    bare TCP reachability of the server's address.
    """
    if aiohttp is None:
        return None
    timeout_cfg = aiohttp.ClientTimeout(total=timeout, sock_connect=timeout)
    connector = _connector_for(proxy_url)
    loop = asyncio.get_running_loop()
    try:
        async with aiohttp.ClientSession(
            timeout=timeout_cfg, connector=connector
        ) as session:
            start = loop.time()
            async with session.get(url, allow_redirects=False) as resp:
                elapsed = loop.time() - start
                resp.release()
        return int(round(elapsed * 1000))
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
        return None


async def http_ping_samples(
    url: str,
    proxy_url: Optional[str] = None,
    count: int = 4,
    timeout: float = 3.0,
    gap: float = 0.15,
) -> list[int]:
    samples: list[int] = []
    total = max(1, int(count))
    for i in range(total):
        ms = await http_ping(url, proxy_url=proxy_url, timeout=timeout)
        if ms is not None:
            samples.append(ms)
        if i < total - 1:
            await asyncio.sleep(gap)
    return samples


async def ping_many(
    endpoints: list[tuple[str, str, int]],
    *,
    count: int = 1,
    timeout: float = 3.0,
    concurrency: int = 16,
    on_result: Optional[Callable[[str, int], None]] = None,
    tls_sni: Optional[dict[str, str]] = None,
) -> dict[str, int]:
    """TCP-ping many (id, host, port) endpoints concurrently.

    Returns {server_id: latency_ms}, with -1 for any endpoint that never
    answered. `on_result` is called as each endpoint finishes so a UI can
    stream progress instead of waiting for the slowest one. Endpoints whose
    host failed to resolve (empty host) are reported as -1 right away.

    `tls_sni` maps server_id → SNI for TLS/REALITY nodes: those additionally
    have to complete a TLS handshake, otherwise the endpoint is reported as
    dead even though TCP answered.
    """
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    results: dict[str, int] = {}
    tls_sni = tls_sni or {}

    def report(server_id: str, ms: int) -> None:
        results[server_id] = ms
        if on_result is not None:
            try:
                on_result(server_id, ms)
            except Exception:
                pass

    async def one(server_id: str, host: str, port: int) -> None:
        async with sem:
            samples = await tcp_ping_samples(
                host, port, count=max(1, int(count)), timeout=timeout, gap=0.1
            )
            sni = tls_sni.get(server_id)
            if samples and sni:
                if not await tls_handshake(host, port, sni, timeout=max(timeout, 3.0)):
                    samples = []
        report(server_id, int(round(sum(samples) / len(samples))) if samples else -1)

    pending = [e for e in endpoints if e[1]]
    if pending:
        await asyncio.gather(*(one(sid, host, port) for sid, host, port in pending))
    for sid, host, _ in endpoints:
        if not host:
            report(sid, -1)
    return results


async def measure_download_mbps(
    url: str = SPEED_DOWN_URL,
    timeout: float = SPEED_TIMEOUT,
    proxy_url: Optional[str] = None,
) -> Optional[float]:
    """Fetch URL and return throughput in Mbps (megabits/second).

    If `proxy_url` is given (e.g. "socks5://127.0.0.1:11081"), traffic is
    routed through that SOCKS proxy so the measurement reflects the tunnel.
    """
    if aiohttp is None:
        return None
    timeout_cfg = aiohttp.ClientTimeout(total=timeout, sock_connect=5.0)
    loop = asyncio.get_running_loop()
    connector = _connector_for(proxy_url)
    try:
        async with aiohttp.ClientSession(
            timeout=timeout_cfg, connector=connector
        ) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return None
                start = loop.time()
                total = 0
                async for chunk in resp.content.iter_chunked(65536):
                    total += len(chunk)
                elapsed = max(loop.time() - start, 1e-6)
        if total <= 0:
            return None
        return round((total * 8.0) / elapsed / 1_000_000.0, 1)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return None


async def measure_upload_mbps(
    url: str = SPEED_UP_URL,
    size_bytes: int = SPEED_UP_BYTES,
    timeout: float = SPEED_TIMEOUT,
    proxy_url: Optional[str] = None,
) -> Optional[float]:
    if aiohttp is None:
        return None
    payload = b"\0" * size_bytes
    timeout_cfg = aiohttp.ClientTimeout(total=timeout, sock_connect=5.0)
    loop = asyncio.get_running_loop()
    connector = _connector_for(proxy_url)
    try:
        async with aiohttp.ClientSession(
            timeout=timeout_cfg, connector=connector
        ) as session:
            start = loop.time()
            async with session.post(url, data=payload) as resp:
                # Read body to ensure full round-trip
                await resp.read()
                if resp.status >= 400:
                    return None
            elapsed = max(loop.time() - start, 1e-6)
        return round((size_bytes * 8.0) / elapsed / 1_000_000.0, 1)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return None


async def resolve_host(host: str) -> Optional[str]:
    loop = asyncio.get_running_loop()
    try:
        info = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in info:
            return sockaddr[0]
    except (socket.gaierror, OSError):
        return None
    return None


def read_resolv_conf_nameservers(path: str = "/etc/resolv.conf") -> list[str]:
    out: list[str] = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        out.append(parts[1])
    except OSError:
        pass
    return out


def check_dns_leak(running: bool, proxy_mode: str, mode: str) -> dict:
    """Best-effort DNS leak check.

    'leaking' is True when the proxy is up but system DNS is going to a
    nameserver that won't be routed through the proxy.

    Heuristic:
      - TUN mode → all UDP/53 hits sing-box → NOT leaking (regardless of resolv.conf).
      - System+global → only HTTP/SOCKS goes through proxy; DNS to /etc/resolv.conf
        servers goes direct over the system → leaking.
      - System+rules → same as global from a DNS-leak standpoint → leaking.
      - Proxy not running → not running, "leaking" reported as N/A (false).
    """
    nameservers = read_resolv_conf_nameservers()
    if not running:
        return {"leaking": False, "dns_servers": nameservers, "reason": "proxy not running"}
    if proxy_mode == "tun":
        return {"leaking": False, "dns_servers": nameservers, "reason": "TUN intercepts all DNS"}
    leaking = any(not (ns.startswith("127.") or ns == "::1") for ns in nameservers)
    return {
        "leaking": bool(leaking),
        "dns_servers": nameservers,
        "reason": (
            "system DNS bypasses the SOCKS proxy in system-proxy mode"
            if leaking
            else "all configured nameservers are local"
        ),
    }


@dataclass
class HealthState:
    latency_ms: int = -1
    jitter_ms: int = -1
    down_mbps: float = -1.0
    up_mbps: float = -1.0
    speed_taken_at: float = 0.0  # epoch seconds; 0 = never
    last_check: float = 0.0  # epoch seconds; 0 = never
    consecutive_failures: int = 0
    status: str = "ok"  # ok | degraded | failed

    def to_dict(self) -> dict:
        if self.last_check:
            last_iso = datetime.fromtimestamp(self.last_check, tz=timezone.utc).isoformat()
        else:
            last_iso = ""
        if self.speed_taken_at:
            speed_iso = datetime.fromtimestamp(
                self.speed_taken_at, tz=timezone.utc
            ).isoformat()
        else:
            speed_iso = ""
        return {
            "latency_ms": int(self.latency_ms),
            "jitter_ms": int(self.jitter_ms),
            "down_mbps": float(self.down_mbps),
            "up_mbps": float(self.up_mbps),
            "speed_taken_at": speed_iso,
            "last_check": last_iso,
            "consecutive_failures": int(self.consecutive_failures),
            "status": self.status,
        }


class HealthMonitor:
    """Periodic probe of the active tunnel.

    Two probe methods:
      * "tcp"  — TCP connect to the remote server's address:port.
      * "http" — HTTP(S) GET to `url`, optionally through the local SOCKS
                 proxy, so the number reflects the tunnel end-to-end.

    - One probe every `interval` seconds (default 30).
    - 1 failure → degraded; 3 consecutive → failed + on_failed callback fires once.
    - First successful probe after failure resets status to ok.
    """

    FAIL_THRESHOLD = 3

    def __init__(
        self,
        host: str,
        port: int,
        interval: float = 30.0,
        timeout: float = 5.0,
        on_failed: Optional[Callable[[], Awaitable[None]]] = None,
        method: str = "tcp",
        url: str = "",
        proxy_url: Optional[str] = None,
        count: int = 4,
    ) -> None:
        self.host = host
        self.port = port
        self.interval = interval
        self.timeout = timeout
        self.method = method
        self.url = url or DEFAULT_PING_URL
        self.proxy_url = proxy_url
        self.count = max(1, int(count))
        self._on_failed = on_failed
        self._task: Optional[asyncio.Task] = None
        self.state = HealthState()
        self._failed_emitted = False
        self._speed_task: Optional[asyncio.Task] = None

    def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._failed_emitted = False
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def check_now(self) -> int:
        if self.method == "http":
            samples = await http_ping_samples(
                self.url,
                proxy_url=self.proxy_url,
                count=self.count,
                timeout=self.timeout,
                gap=0.1,
            )
        else:
            samples = await tcp_ping_samples(
                self.host, self.port, count=self.count, timeout=self.timeout, gap=0.1
            )
        self.state.last_check = time.time()
        if not samples:
            self.state.latency_ms = -1
            self.state.jitter_ms = -1
            self.state.consecutive_failures += 1
            if self.state.consecutive_failures >= self.FAIL_THRESHOLD:
                self.state.status = "failed"
                if not self._failed_emitted and self._on_failed:
                    self._failed_emitted = True
                    try:
                        await self._on_failed()
                    except Exception:
                        pass
            else:
                self.state.status = "degraded"
            return -1
        latency = int(round(sum(samples) / len(samples)))
        self.state.latency_ms = latency
        self.state.jitter_ms = compute_jitter(samples)
        self.state.consecutive_failures = 0
        self.state.status = "ok"
        self._failed_emitted = False
        return latency

    async def run_speed_test(self, proxy_url: Optional[str] = None) -> dict:
        """Measure download + upload throughput. Updates state in-place.

        When `proxy_url` is provided, traffic is routed through that proxy.
        """
        down = await measure_download_mbps(proxy_url=proxy_url)
        up = await measure_upload_mbps(proxy_url=proxy_url)
        self.state.down_mbps = down if down is not None else -1.0
        self.state.up_mbps = up if up is not None else -1.0
        self.state.speed_taken_at = time.time()
        return {
            "down_mbps": self.state.down_mbps,
            "up_mbps": self.state.up_mbps,
            "ping_ms": int(self.state.latency_ms),
            "jitter_ms": int(self.state.jitter_ms),
        }

    async def _loop(self) -> None:
        try:
            # First check immediately so GetHealth has real data quickly.
            await self.check_now()
            while True:
                await asyncio.sleep(self.interval)
                await self.check_now()
        except asyncio.CancelledError:
            return


class TunnelMonitor:
    """End-to-end probe of the live tunnel through the local SOCKS port.

    TCP (and even TLS) reachability of the node's address proves nothing about
    the tunnel itself: a node whose transport is misconfigured (e.g. gRPC
    expected while the config speaks plain TCP) completes the handshake and
    then answers with binary garbage — browsers die with
    SSL_ERROR_RX_UNKNOWN_RECORD_TYPE while every ping stays green.

    The only honest check is the request a browser would make, so this monitor
    drives an HTTP GET through the mux port the system proxy points at.
    """

    FAIL_THRESHOLD = 2

    def __init__(
        self,
        proxy_url: str,
        url: str = DEFAULT_PING_URL,
        interval: float = 25.0,
        timeout: float = 8.0,
        on_failed: Optional[Callable[[], Awaitable[None]]] = None,
        fail_threshold: Optional[int] = None,
    ) -> None:
        self.proxy_url = proxy_url
        self.url = url or DEFAULT_PING_URL
        self.interval = max(5.0, float(interval))
        self.timeout = max(1.0, float(timeout))
        self.fail_threshold = max(1, int(fail_threshold or self.FAIL_THRESHOLD))
        self._on_failed = on_failed
        self._task: Optional[asyncio.Task] = None
        self._failed_emitted = False
        self.latency_ms = -1
        self.consecutive_failures = 0
        self.last_check = 0.0

    async def check_now(self) -> Optional[int]:
        ms = await http_ping(self.url, proxy_url=self.proxy_url, timeout=self.timeout)
        self.last_check = time.time()
        if ms is None:
            self.consecutive_failures += 1
            if (
                self.consecutive_failures >= self.fail_threshold
                and not self._failed_emitted
                and self._on_failed is not None
            ):
                self._failed_emitted = True
                try:
                    await self._on_failed()
                except Exception:
                    pass
            return None
        self.latency_ms = int(ms)
        self.consecutive_failures = 0
        self._failed_emitted = False
        return int(ms)

    def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._failed_emitted = False
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _loop(self) -> None:
        try:
            # Let a freshly started tunnel settle, then probe.
            await asyncio.sleep(1.5)
            await self.check_now()
            while True:
                await asyncio.sleep(self.interval)
                await self.check_now()
        except asyncio.CancelledError:
            return
