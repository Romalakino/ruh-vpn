--!nonstrict
-- widget.luau — bar tile. Reads shared state published by service.luau.

local PANEL = "vlad-dev/ruh-vpn:vpn_panel"

-- Same command channel the panel uses: the headless service watches state
-- "cmd" and turns each new nonce into an RPC call. "w" keeps widget nonces
-- from colliding with the panel's.
local nonce = 0
local function send(method, args)
  nonce = nonce + 1
  noctalia.state.set("cmd", {
    method = method, args = args or {},
    nonce = "w" .. tostring(nonce) .. ":" .. tostring(os.time()),
  })
end

local function activeName(status)
  if not status.running then return "VPN" end
  for _, sv in ipairs(noctalia.state.get("servers") or {}) do
    if sv.id == status.activeServerId then return sv.name or "VPN" end
  end
  return "VPN"
end

local function fmtBytes(n)
  n = tonumber(n) or 0
  if n < 1024 then return string.format("%dB", n) end
  local u = { "K", "M", "G", "T" }
  local i = 0
  repeat n = n / 1024; i = i + 1 until n < 1024 or i >= #u
  return string.format(n < 10 and "%.1f%s" or "%.0f%s", n, u[i])
end

function update()
  local s = noctalia.state.get("status") or {}
  local h = noctalia.state.get("health") or {}
  local running = s.running == true

  barWidget.setGlyph(running and "lock" or "lock-open")
  barWidget.setColor(running and "primary" or "on_surface_variant")

  local label = activeName(s)
  if noctalia.getConfig("show_ping") and running and h.latency_ms and h.latency_ms > 0 then
    label = label .. " · " .. tostring(h.latency_ms) .. "ms"
  end
  if noctalia.getConfig("show_traffic") and running then
    local t = noctalia.state.get("traffic") or {}
    label = label .. "  ↓" .. fmtBytes(t.bytes_received) .. " ↑" .. fmtBytes(t.bytes_sent)
  end
  barWidget.setText(label)
  barWidget.setTooltip(running and ("Connected — " .. activeName(s) .. "\nRight-click: fastest")
                              or "VPN off\nRight-click: connect to the fastest server")
end

function onClick()
  noctalia.togglePanel(PANEL)
end

-- Right-click: connect to the fastest server, same as the panel's ⚡ button.
function onRightClick()
  local s = noctalia.state.get("status") or {}
  send("ConnectFastest", { s.mode or "rules", s.proxyMode or "system" })
  noctalia.notify("Ruh VPN", noctalia.tr("panel.connecting"))
end

noctalia.setUpdateInterval(2000)
