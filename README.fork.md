# Ruh VPN — local fork

This is a **local fork** of the community plugin `umedbazarov/ruh-vpn`
(v0.1.1), loaded by Noctalia as a `path` source named `vlad-dev`
(source location: `~/dev/noctalia-plugins`, plugin id `vlad-dev/ruh-vpn`).

Why a fork: path-source plugins are read **in place** (no materialization), so
edits survive everything and there is no "re-apply the patch" step. The
community plugin stays installed but disabled as a fallback.

Local changes on top of upstream:
* subscription `x-hwid` + device headers (Remnawave needs them)
* ping settings (`ping_method`, `ping_url`, `ping_timeout_ms`, `ping_count`,
  `ping_concurrency`, `health_interval`, `auto_failover`)
* "Ping all" + "Fastest" connect (RPC `PingAll` / `FastestServer` /
  `ConnectFastest`, events `PingUpdate` / `Notice`)
* per-row latency badges, sort-by-ping, ping progress line
* widget right-click = connect to fastest
* panel width 640, name truncation, no GeoIP flags
* `translations/ru.json`

Details: `~/.config/opencode/skills/niri-noctalia/references/ruh-vpn-patches.md`
