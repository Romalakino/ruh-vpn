import asyncio
from types import SimpleNamespace

import pytest

from backend import app
from backend.models.server import Settings


def _entrypoint(monkeypatch, bootstrap_error=None, bind_error=None):
    events = []

    async def bootstrap():
        events.append("bootstrap")
        if bootstrap_error:
            raise bootstrap_error

    async def shutdown():
        events.append("shutdown")

    service = SimpleNamespace(state=SimpleNamespace(settings=Settings()), bootstrap=bootstrap, shutdown=shutdown)

    async def stop():
        events.append("close-socket")

    control = SimpleNamespace(
        mark_ready=lambda: events.append("ready"),
        mark_stopping=lambda: events.append("stopping"),
        stop=stop,
    )

    async def serve(*args, **kwargs):
        events.append("bind")
        if bind_error:
            raise bind_error
        return control

    async def reset(ports):
        events.append("reset")
        assert ports == {11080, 11081, 11082}
        return True

    async def settings():
        return Settings()

    async def spawn_guard(*args, **kwargs):
        events.append("guard")
        assert kwargs["start_new_session"]

        async def wait():
            return 0

        guard = SimpleNamespace(returncode=None, wait=wait)
        guard.stdin = SimpleNamespace(close=lambda: None)
        return guard

    async def heartbeat(guard):
        return

    monkeypatch.setattr(app, "VpnService", lambda: service)
    monkeypatch.setattr(app, "serve", serve)
    monkeypatch.setattr(app, "reset_stale_proxy", reset)
    monkeypatch.setattr(app, "load_settings", settings)
    monkeypatch.setattr(app.asyncio, "create_subprocess_exec", spawn_guard)
    monkeypatch.setattr(app, "_guard_heartbeat", heartbeat)
    monkeypatch.setattr(app, "_install_stdio_guards", lambda: None)
    monkeypatch.setattr(app, "_write_pidfile", lambda port: events.append("pidfile"))
    monkeypatch.setattr(app, "_remove_pidfile", lambda: None)
    monkeypatch.setattr(app, "_remove_tokenfile", lambda token: None)
    return events


def test_bind_loser_never_resets_or_tears_down_existing_proxy(monkeypatch):
    events = _entrypoint(monkeypatch, bind_error=OSError("port in use"))
    assert asyncio.run(app.main()) == 3
    assert events == ["bind"]


def test_bootstrap_failure_resets_proxy_and_cleans_up_before_releasing_socket(monkeypatch):
    events = _entrypoint(monkeypatch, bootstrap_error=RuntimeError("broken settings"))
    with pytest.raises(RuntimeError, match="broken settings"):
        asyncio.run(app.main())
    assert events == ["bind", "pidfile", "reset", "guard", "bootstrap", "stopping", "reset", "shutdown", "close-socket"]


def test_guard_failure_stops_unprotected_backend(monkeypatch):
    events = _entrypoint(monkeypatch)
    with pytest.raises(RuntimeError, match="fail-open guard exited"):
        asyncio.run(app.main())
    assert events == ["bind", "pidfile", "reset", "guard", "bootstrap", "ready", "stopping", "reset", "shutdown", "close-socket"]
