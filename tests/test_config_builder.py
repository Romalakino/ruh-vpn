import json
import shutil
import subprocess

import pytest

from backend.models.server import VlessServer
from backend.routing.rules import PRESETS
from backend.singbox import config_builder

ALL = list(PRESETS.keys())

VLESS = VlessServer(
    name="test",
    address="example.com",
    port=443,
    uuid="8a41ee79-4b8f-4c8a-b64c-6cb43df77e30",
    security="reality",
    sni="example.com",
    fp="chrome",
    pbk="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",  # any 32-byte key
    sid="ab",
)


def test_rules_config_includes_presets():
    cfg = config_builder.build_rules_config(active_presets=ALL)
    tags = {rs["tag"] for rs in cfg["route"]["rule_set"]}
    expected = {rs["tag"] for p in PRESETS.values() for rs in p["rule_sets"]}
    assert expected <= tags
    proxy_rules = [r for r in cfg["route"]["rules"] if r.get("outbound") == "proxy" and "rule_set" in r]
    assert len(proxy_rules) == len(ALL)


def test_rules_config_dns_proxies_unmatched_domains_and_keeps_roblox_direct():
    cfg = config_builder.build_rules_config(active_presets=ALL)
    assert cfg["dns"]["final"] == "proxy-dns"
    assert cfg["route"]["final"] == "proxy"
    assert cfg["dns"]["rules"][0] == config_builder.roblox_dns_rule()
    resolver = next(s for s in cfg["dns"]["servers"] if s["tag"] == config_builder.ROBLOX_DNS_TAG)
    assert resolver["server"] == "9.9.9.9"
    assert "detour" not in resolver


def test_transport_config_resolves_prefer_ipv4():
    # The transport is the only config resolving the (usually domain) server
    # address locally; without prefer_ipv4 sing-box may dial an AAAA record
    # on an IPv4-only network (issue #327).
    cfg = config_builder.build_transport_config(VLESS)
    assert cfg["dns"]["strategy"] == "prefer_ipv4"
    assert cfg["route"]["default_domain_resolver"] == "local"


@pytest.mark.skipif(shutil.which("sing-box") is None, reason="sing-box not installed")
@pytest.mark.parametrize("presets", [[], ALL])
def test_sing_box_accepts_generated_configs(tmp_path, presets):
    for name, cfg in {
        "transport": config_builder.build_transport_config(VLESS),
        "rules": config_builder.build_rules_config(active_presets=presets),
        "global": config_builder.build_global_config(),
        "tun": config_builder.build_tun_config(
            upstream_socks_port=11081,
            route_exclude_addresses=["203.0.113.1/32"],
        ),
    }.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(cfg))
        proc = subprocess.run(
            ["sing-box", "check", "-c", str(path)],
            capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0, f"{name}: {proc.stderr}"
