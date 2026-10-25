import asyncio
import json
import os
from types import SimpleNamespace

from backend.http.control import ControlServer


def _control(token: str = "right-token", token_file=None) -> ControlServer:
    state = SimpleNamespace(
        status_listeners=[], server_list_listeners=[], log_listeners=[],
        ping_listeners=[], notice_listeners=[]
    )
    service = SimpleNamespace(state=state, add_traffic_listener=lambda cb: None)
    return ControlServer(service, token=token, token_file=token_file)


def _request(header: str | None):
    headers = {} if header is None else {"Authorization": header}
    return SimpleNamespace(headers=headers)


def test_missing_header_rejected():
    assert not _control()._authorized(_request(None))


def test_wrong_token_rejected():
    assert not _control()._authorized(_request("Bearer wrong"))


def test_wrong_scheme_rejected():
    assert not _control()._authorized(_request("Basic right-token"))


def test_correct_token_accepted():
    assert _control()._authorized(_request("Bearer right-token"))


def test_empty_configured_token_rejects_everything():
    # A backend that somehow starts without a token must fail closed.
    assert not _control(token="")._authorized(_request("Bearer "))


def test_token_file_written_0600(tmp_path):
    path = tmp_path / "control.token"
    _control(token="secret", token_file=path)._publish_token()
    assert path.read_text().strip() == "secret"
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_rpc_rejected_during_bootstrap():
    response = asyncio.run(_control()._handle_rpc(_request("Bearer right-token")))
    assert response.status == 503
    assert json.loads(response.body) == {"error": "backend is not ready"}


def test_health_distinguishes_bound_ready_and_stopping():
    control = _control()
    assert not json.loads(asyncio.run(control._handle_health(None)).body)["ready"]
    control.mark_ready()
    assert json.loads(asyncio.run(control._handle_health(None)).body)["ready"]
    control.mark_stopping()
    assert not json.loads(asyncio.run(control._handle_health(None)).body)["ready"]
