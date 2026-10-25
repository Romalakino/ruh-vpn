import asyncio
import os
from types import SimpleNamespace

import pytest

from backend.service import proxy_guard


def _fake(monkeypatch, mode="'manual'\n", host="'127.0.0.1'\n", port="11081\n", overrides=None):
    calls = []
    overrides = overrides or {}

    async def run(*args):
        calls.append(args)
        if args in overrides:
            return overrides[args]
        if args[:3] == ("gsettings", "get", proxy_guard.PROXY_SCHEMA) and args[3] == "mode":
            return 0, mode
        if args[1] == "get" and args[3] == "host":
            return 0, host
        if args[1] == "get" and args[3] == "port":
            return 0, port
        return 0, ""

    monkeypatch.setattr(proxy_guard, "_run", run)
    monkeypatch.setattr(proxy_guard.shutil, "which", lambda name: "/usr/bin/gsettings")
    return calls


def test_resets_our_dead_port(monkeypatch):
    calls = _fake(monkeypatch)
    assert asyncio.run(proxy_guard.reset_stale_proxy({11080, 11081})) is True
    assert ("gsettings", "set", proxy_guard.PROXY_SCHEMA, "mode", "none") in calls


def test_leaves_foreign_port_alone(monkeypatch):
    calls = _fake(monkeypatch, port="8080\n")
    assert asyncio.run(proxy_guard.reset_stale_proxy({11081})) is False
    assert not [c for c in calls if c[1] == "set"]


def test_leaves_corporate_proxy_alone(monkeypatch):
    calls = _fake(monkeypatch, host="'10.0.0.1'\n")
    assert asyncio.run(proxy_guard.reset_stale_proxy({11081})) is False
    assert not [c for c in calls if c[1] == "set"]


def test_noop_when_proxy_is_off(monkeypatch):
    calls = _fake(monkeypatch, mode="'none'\n")
    assert asyncio.run(proxy_guard.reset_stale_proxy({11081})) is False
    assert len(calls) == 1  # only the mode read


@pytest.mark.parametrize("host", proxy_guard.LOOPBACK)
def test_accepts_all_loopback_hosts_and_custom_ports(monkeypatch, host):
    _fake(monkeypatch, host=repr(host), port="12081")
    assert asyncio.run(proxy_guard.reset_stale_proxy({12081}))


def test_empty_owned_ports_never_mean_wildcard(monkeypatch):
    calls = _fake(monkeypatch)
    assert not asyncio.run(proxy_guard.reset_stale_proxy(set()))
    assert not calls


def test_missing_gsettings_is_noop(monkeypatch):
    calls = _fake(monkeypatch)
    monkeypatch.setattr(proxy_guard.shutil, "which", lambda name: None)
    assert not asyncio.run(proxy_guard.reset_stale_proxy({11081}))
    assert not calls


@pytest.mark.parametrize("host,port", [("'10.0.0.1'", "11081"), ("'127.0.0.1'", "8080")])
def test_mixed_proxy_ownership_is_untouched(monkeypatch, host, port):
    calls = _fake(monkeypatch, overrides={
        ("gsettings", "get", proxy_guard.TARGETS[1], "host"): (0, host),
        ("gsettings", "get", proxy_guard.TARGETS[1], "port"): (0, port),
    })
    assert not asyncio.run(proxy_guard.reset_stale_proxy({11081}))
    assert not [c for c in calls if c[1] == "set"]


@pytest.mark.parametrize("result", [(0, "not-a-port"), (1, "read failed")])
def test_unknown_port_is_untouched(monkeypatch, result):
    calls = _fake(monkeypatch, overrides={
        ("gsettings", "get", proxy_guard.TARGETS[0], "port"): result,
    })
    assert not asyncio.run(proxy_guard.reset_stale_proxy({11081}))
    assert not [c for c in calls if c[1] == "set"]


def test_failed_reset_does_not_report_success(monkeypatch):
    _fake(monkeypatch, overrides={
        ("gsettings", "set", proxy_guard.PROXY_SCHEMA, "mode", "none"): (1, "write failed"),
    })
    assert not asyncio.run(proxy_guard.reset_stale_proxy({11081}))


@pytest.mark.parametrize("error", [asyncio.TimeoutError, asyncio.CancelledError])
def test_failed_subprocess_is_reaped_and_cancellation_propagates(monkeypatch, error):
    calls = []
    proc = SimpleNamespace(returncode=None)

    async def communicate():
        raise error()

    async def wait():
        calls.append("wait")

    def kill():
        calls.append("kill")
        proc.returncode = -9

    proc.communicate, proc.wait, proc.kill = communicate, wait, kill

    async def spawn(*args, **kwargs):
        return proc

    monkeypatch.setattr(proxy_guard.asyncio, "create_subprocess_exec", spawn)
    if error is asyncio.CancelledError:
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(proxy_guard._run("gsettings"))
    else:
        assert asyncio.run(proxy_guard._run("gsettings"))[0] == 1
    assert calls == ["kill", "wait"]


def test_watchdog_exits_immediately_when_backend_pipe_closes():
    reader, writer = os.pipe()
    os.close(writer)
    try:
        assert proxy_guard.wait_for_backend(reader) is False
    finally:
        os.close(reader)


def test_watchdog_exits_on_missed_heartbeat(monkeypatch):
    calls = []

    def select(readers, writers, errors, timeout):
        calls.append((readers, timeout))
        return [], [], []

    monkeypatch.setattr(proxy_guard.select, "select", select)
    assert proxy_guard.wait_for_backend(42) is True
    assert calls == [([42], 5.0)]
