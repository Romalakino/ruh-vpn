import asyncio
from types import SimpleNamespace

import pytest

from backend.service import vpn_service


def _service(monkeypatch, fail_at=None):
    service = vpn_service.VpnService.__new__(vpn_service.VpnService)
    service._log = lambda *args: None
    calls = []

    async def run(cmd):
        calls.append(cmd)
        return 1 if len(calls) == fail_at else 0

    service._run = run
    monkeypatch.setattr(vpn_service.shutil, "which", lambda name: "/usr/bin/gsettings")
    return service, calls


def test_manual_proxy_is_enabled_only_after_configuration(monkeypatch):
    service, calls = _service(monkeypatch)
    assert asyncio.run(service._set_system_proxy(11081))
    assert calls[0] == ["gsettings", "set", "org.gnome.system.proxy", "mode", "none"]
    assert calls[-1] == ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"]


def test_configuration_failure_never_enables_proxy(monkeypatch):
    service, calls = _service(monkeypatch, fail_at=3)
    assert not asyncio.run(service._set_system_proxy(11081))
    assert not any(cmd[-2:] == ["mode", "manual"] for cmd in calls)


def test_shutdown_resets_proxy_before_a_monitor_can_fail():
    service = vpn_service.VpnService.__new__(vpn_service.VpnService)
    service.state = SimpleNamespace(lock=asyncio.Lock())
    calls = []

    async def reset(**kwargs):
        calls.append("reset")

    async def stop():
        calls.append("stop")
        raise RuntimeError("broken monitor")

    service._unset_system_proxy = reset
    service._tunnel = SimpleNamespace(stop=stop)
    with pytest.raises(RuntimeError, match="broken monitor"):
        asyncio.run(service.shutdown())
    assert calls == ["reset", "stop"]


def test_queued_start_cannot_restart_proxy_during_shutdown():
    service = vpn_service.VpnService.__new__(vpn_service.VpnService)
    service._shutting_down = True
    assert not asyncio.run(service._start_locked("server", "rules", "system"))
