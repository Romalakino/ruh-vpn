import asyncio
import signal
from pathlib import Path

import pytest

from backend.identity import TAG
from backend.singbox import process_manager as pm


def _singbox(name="rules", binary="/usr/bin/sing-box"):
    return [binary, "run", "-c", str(pm.SINGBOX_CONFIG_DIR / pm.CONFIG_NAMES[name])]


@pytest.mark.parametrize("name", pm.CONFIG_NAMES)
def test_exact_instance_configs_are_owned(name):
    assert pm._owned_command(_singbox(name))


def test_private_tun_binary_is_owned():
    assert pm._owned_command(_singbox("tun", "/private/bin/sing-box-tun"))


def test_shell_mentions_and_other_data_directories_are_not_owned():
    assert not pm._owned_command(["bash", "-c", " ".join(_singbox())])
    assert not pm._owned_command(["python3", "-c", " ".join(_singbox())])
    assert not pm._owned_command(["/usr/bin/sing-box", "run", "-c", "/other/ruh-vpn-rules.json"])
    assert not pm._owned_command([])


def test_ssh_requires_our_tag_and_known_hosts_file():
    owned = ["ssh", "-N", "-o", f"SetEnv={TAG}=1", "-o", f"UserKnownHostsFile={pm.KNOWN_HOSTS_FILE}"]
    assert pm._owned_command(owned)
    assert not pm._owned_command(owned[:-2])
    assert not pm._owned_command(owned[:-1] + ["UserKnownHostsFile=/other/known_hosts"])


def _proc(root: Path, pid: int, args: list[str]) -> Path:
    path = root / str(pid) / "cmdline"
    path.parent.mkdir(parents=True)
    path.write_bytes(("\0".join(args) + "\0").encode())
    return path


def test_cleanup_signals_only_our_orphans(monkeypatch, tmp_path):
    owned = _proc(tmp_path, 123456, _singbox())
    _proc(tmp_path, 123457, ["bash", "-c", " ".join(_singbox())])
    _proc(tmp_path, 123458, ["sing-box", "run", "-c", "/other/ruh-vpn-rules.json"])
    signals = []

    def kill(pid, sig):
        signals.append((pid, sig))
        owned.write_bytes(b"")

    monkeypatch.setattr(pm, "PROC_ROOT", tmp_path)
    monkeypatch.setattr(pm.os, "kill", kill)
    asyncio.run(pm.ProcessManager().pkill_zombies())
    assert signals == [(123456, signal.SIGTERM)]


def test_changed_pid_is_not_force_killed(monkeypatch, tmp_path):
    owned = _proc(tmp_path, 123456, _singbox())
    signals = []

    async def sleep(seconds):
        owned.write_bytes(b"unrelated\0process\0")

    monkeypatch.setattr(pm, "PROC_ROOT", tmp_path)
    monkeypatch.setattr(pm.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    monkeypatch.setattr(pm.asyncio, "sleep", sleep)
    asyncio.run(pm.ProcessManager().pkill_zombies())
    assert signals == [(123456, signal.SIGTERM)]
