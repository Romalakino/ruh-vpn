"""Fail-open guard for the GNOME system proxy.

The proxy lives in dconf, so it outlives a crash, a SIGKILL, an OOM kill or a
reboot. If the tunnel dies while the mode is still "manual", every GNOME app
keeps dialing 127.0.0.1:<dead port> and the machine looks offline even though
the link is perfectly fine ("the cable died" reports).

A fresh backend owns the control port, so at that point nothing can be serving
our proxy: reset it. Only a loopback host on one of *our* ports is touched — a
corporate proxy or another local tool is left alone.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import select
import shutil
import signal
import sys
from collections.abc import Iterable

PROXY_SCHEMA = "org.gnome.system.proxy"
LOOPBACK = ("127.0.0.1", "localhost", "::1")
TARGETS = (
    "org.gnome.system.proxy.http",
    "org.gnome.system.proxy.https",
    "org.gnome.system.proxy.socks",
    "org.gnome.system.proxy.ftp",
)


async def _run(*args: str) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except OSError as exc:
        return 1, str(exc)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=2.0)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        await proc.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        return 1, "gsettings timed out"
    return proc.returncode or 0, out.decode("utf-8", errors="replace")


def _unquote(value: str) -> str:
    return value.strip().strip("'").strip('"').strip()


async def _get(schema: str, key: str) -> str | None:
    rc, out = await _run("gsettings", "get", schema, key)
    return _unquote(out) if rc == 0 else None


async def reset_stale_proxy(ports: Iterable[int]) -> bool:
    """Disable the system proxy when it points at one of our loopback ports.

    Empty ports or mixed/unknown proxy ownership are a no-op. Returns True
    only when the mode was successfully switched back to "none".
    """
    own = set(ports)
    if not own or shutil.which("gsettings") is None:
        return False
    if await _get(PROXY_SCHEMA, "mode") != "manual":
        return False

    matched = False
    for schema in TARGETS:
        host = await _get(schema, "host")
        if host == "":
            continue
        if host not in LOOPBACK:
            return False
        try:
            port = int(await _get(schema, "port"))
        except (TypeError, ValueError):
            return False
        if port not in own:
            return False
        matched = True
    if not matched:
        return False
    rc, _ = await _run("gsettings", "set", PROXY_SCHEMA, "mode", "none")
    return rc == 0


def wait_for_backend(fd: int) -> bool:
    """Return True on a missed heartbeat, False on normal EOF."""
    while select.select([fd], [], [], 5.0)[0]:
        if not os.read(fd, 4096):
            return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("ports", nargs="+", type=int)
    args = parser.parse_args()
    parent_fd = None
    if args.watch:
        if os.getppid() > 1:
            try:
                parent_fd = os.pidfd_open(os.getppid())
            except OSError:
                pass
        timed_out = wait_for_backend(sys.stdin.fileno())
    # shortcut: system proxy only; add privileged cleanup before covering TUN/nft.
    asyncio.run(reset_stale_proxy(args.ports))
    if args.watch and timed_out and parent_fd is not None:
        try:
            # A frozen parent cannot handle SIGTERM; pidfd avoids PID-reuse races.
            signal.pidfd_send_signal(parent_fd, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if parent_fd is not None:
        os.close(parent_fd)
