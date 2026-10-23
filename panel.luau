--!nonstrict
-- panel.luau — main VPN UI. Multi-view single panel:
--   view = "main" | "editor" | "rules" | "logs"
-- Value-driven: every render reads current state; controls report changes
-- through named global callbacks. ui.input is uncontrolled (value seeds once,
-- edits flow through onChange into the module-level `form` table).

local MAX_ROWS  = 64          -- clickable server rows (pool below is generated)
local MAX_PRE   = 8           -- preset toggles
local MAX_RULE  = 64          -- custom rule rows
local MAX_SUB   = 32          -- subscription rows
local nonce     = 0

local view      = "main"
local slotIds   = {}          -- server row slot -> id
local presetKeys = {}         -- preset slot -> key
local ruleIds   = {}          -- rule slot -> id
local sortByPing = false      -- servers list ordered by last mass ping

-- editor form
local form      = {}
local formProto = "ssh"
local editingId = nil
local formRev   = 0           -- bumps to reset ui.input identity on open

-- add-rule form
local ruleForm  = { pattern = "", type = "force-proxy" }
local ruleRev   = 0

-- subscriptions
local subUrls   = {}          -- sub slot -> url
local subForm   = { url = "", name = "" }
local subRev    = 0

local resetArmed = false      -- "Reset all servers" waits for a second click

local PROTOS = { "ssh", "vless", "vmess", "shadowsocks", "socks5" }
local TRANSPORTS = { "tcp", "ws", "grpc", "http" }
local SECURITIES = { "none", "tls", "reality" }
local RULE_TYPES = { "force-proxy", "direct", "block" }

-- ── design tokens ───────────────────────────────────────────────
-- The fixed olive/chartreuse palette gives the plugin its own visual identity.
local T = {
  bg         = "#1b1c17",
  -- Glass: card surfaces are theme roles carrying an alpha suffix (a plain hex
  -- cannot hold alpha here), so the blurred panel backdrop shows through them.
  -- `cardBase` is the opaque hex twin of `card`, used where a colour still has
  -- to be flattened against a solid base (protocol pills, hero halo).
  card       = "surface_variant/0.45",
  cardBase   = "#26271f",
  cardHi     = "surface_variant/0.65",
  cardActive = "surface_variant/0.80",
  border     = "on_surface/0.22",
  borderSoft = "on_surface/0.15",
  accent     = "#cfe04e",
  accentText = "#1b1c17",
  text       = "#e8e7df",
  textDim    = "#a3a497",
  muted      = "#7d7e71",
  success    = "#9bd17a",
  danger     = "#d68a7a",
  pingGood   = "#9bd17a",
  pingMid    = "#e0c84e",
  pingBad    = "#d68a7a",
}

-- Colour props take a role token or a plain hex. Flatten alpha against the
-- backdrop because alpha suffixes are only legal on theme roles.
local function mix(fg, bg, a)
  local function ch(h, i) return tonumber(h:sub(i, i + 1), 16) end
  local r = ch(bg, 2) + (ch(fg, 2) - ch(bg, 2)) * a
  local g = ch(bg, 4) + (ch(fg, 4) - ch(bg, 4)) * a
  local b = ch(bg, 6) + (ch(fg, 6) - ch(bg, 6)) * a
  return string.format("#%02x%02x%02x", math.floor(r + 0.5), math.floor(g + 0.5), math.floor(b + 0.5))
end

-- Protocol pill colours, alpha pre-flattened.
local PROTO_TAG = {
  SSH    = { fg = "#9ab7d1", a = 0.12 },
  VLESS  = { fg = "#cfe04e", a = 0.14 },
  VMess  = { fg = "#c18cd9", a = 0.14 },
  SS     = { fg = "#d99967", a = 0.14 },
  SOCKS5 = { fg = "#d99967", a = 0.14 },
}

local PROTO_LABEL = {
  ssh = "SSH", vless = "VLESS", vmess = "VMess",
  shadowsocks = "SS", socks5 = "SOCKS5",
}

-- ── command channel ─────────────────────────────────────────────
local function send(method, args)
  nonce = nonce + 1
  noctalia.state.set("cmd", {
    method = method, args = args or {},
    nonce = tostring(nonce) .. ":" .. tostring(os.time()),
  })
end

-- ── helpers ─────────────────────────────────────────────────────
local function indexOf(list, val, dflt)
  for i, v in ipairs(list) do if v == val then return i - 1 end end
  return dflt or 0
end

local function pingColor(ms)
  ms = tonumber(ms)
  if not ms or ms < 0 then return T.muted end
  if ms < 60 then return T.pingGood end
  if ms < 150 then return T.pingMid end
  return T.pingBad
end

-- Uppercase protocol pill.
local function protoTag(proto)
  local label = PROTO_LABEL[(proto or ""):lower()]
  if not label then return nil end
  local tag = PROTO_TAG[label]
  return ui.row({ fill = mix(tag.fg, T.cardBase, tag.a), radius = 4, paddingH = 6, align = "center" }, {
    ui.label({ text = label:upper(), color = tag.fg, fontSize = 10, fontWeight = "bold" }),
  })
end

-- Coloured latency dot and milliseconds. A negative value means the last
-- probe got no answer, which is worth showing as "—" rather than "-1ms".
local function pingBadge(ms)
  ms = tonumber(ms)
  local ok = ms and ms >= 0
  return ui.row({ gap = 5, align = "center" }, {
    ui.box({ width = 6, height = 6, radius = 3, fill = pingColor(ms) }),
    ui.label({ text = ok and (tostring(ms) .. "ms") or "—", color = T.textDim, fontSize = 11 }),
  })
end

-- Hard clamp for controls that have no maxLines/maxWidth prop (ui.button).
local function ellipsize(text, limit)
  text = tostring(text or "")
  local n = utf8.len(text)
  if n and n > limit then
    local cut = utf8.offset(text, limit)
    if cut then return text:sub(1, cut - 1) .. "…" end
  end
  return text
end

-- ISO-3166 alpha-2 to regional indicator pair.
local function flagFor(country)
  if type(country) ~= "string" or #country ~= 2 then return nil end
  local cc, out = country:upper(), ""
  for i = 1, 2 do
    local b = cc:byte(i)
    if b < 65 or b > 90 then return nil end
    out = out .. utf8.char(0x1F1E6 + b - 65)
  end
  return out
end

local function activeName(servers, id)
  for _, s in ipairs(servers) do if s.id == id then return s.name or s.id end end
  return nil
end

local function num(v, dflt) return tonumber(v) or dflt end

-- Leaving the view disarms the reset confirm; it must never survive a round trip.
local function navigate(v) view = v; resetArmed = false; render() end   -- render is assigned below

-- ── declared forward ────────────────────────────────────────────
render = nil

-- ================================================================
-- MAIN VIEW
-- ================================================================
-- Server row: status, flag, name, protocol, endpoint, latency and actions.
-- Row and column nodes do not accept onClick, so the name button and status
-- dot are the click targets.
local function serverRows(servers, status, running, health, pings)
  local rows = {}
  slotIds = {}
  local byId = (pings and pings.byId) or {}

  -- Sort a *copy*: the state table must not be reordered in place.
  local list = servers
  if sortByPing then
    list = {}
    for i, s in ipairs(servers) do list[i] = s end
    table.sort(list, function(a, b)
      local ma, mb = tonumber(byId[a.id]), tonumber(byId[b.id])
      local na = (ma and ma >= 0) and ma or math.huge
      local nb = (mb and mb >= 0) and mb or math.huge
      if na ~= nb then return na < nb end
      return tostring(a.name or "") < tostring(b.name or "")
    end)
  end

  for i, s in ipairs(list) do
    local slot = i - 1
    if slot >= MAX_ROWS then break end
    slotIds[slot] = s.id
    local isSelected = s.id == status.activeServerId
    local isActive   = isSelected and running

    local dot = (isActive and T.success) or (isSelected and mix(T.accent, T.bg, 0.7)) or T.border
    -- Keep idle rows transparent instead of painting over the panel.
    local fill = (isActive and T.cardActive) or (isSelected and mix(T.accent, T.bg, 0.05)) or nil
    local edge = (isActive and T.border) or (isSelected and mix(T.accent, T.bg, 0.4)) or nil

    local pick = "onServer" .. tostring(slot)
    -- The name lives in a ui.button, which has no width/clamp prop: a long
    -- subscription name widens the row until the protocol pill rides over the
    -- edit/delete icons. Truncate it so every row fits the fixed panel width,
    -- and let flexGrow take the slack so the pill sits in the same column.
    local name = ellipsize(s.name or s.id or noctalia.tr("panel.fallback-server-name"), 34)
    local title = { ui.button({ text = name, variant = "ghost", contentAlign = "start",
                                onClick = pick, flexGrow = 1 }) }
    local tag = protoTag(s.protocol)
    if tag then title[#title + 1] = tag end

    local cells = { ui.box({ width = 7, height = 7, radius = 4, fill = dot, onClick = pick }) }
    local flag = flagFor(s.country)
    if flag then cells[#cells + 1] = ui.label({ text = flag, fontSize = 16 }) end
    cells[#cells + 1] = ui.column({ gap = 2, flexGrow = 1 }, {
      ui.row({ gap = 6, align = "center" }, title),
      -- Indent to clear the name button's own inner padding so the endpoint
      -- lines up under the name rather than under the button's edge.
      ui.row({ paddingH = 15 }, {
        ui.label({ text = s.host or s.address or "", color = T.muted, fontSize = 11, maxLines = 1 }),
      }),
    })
    -- Latency badge: prefer the mass-ping result for any server, fall back to
    -- the live health probe for the connected one.
    local ms = tonumber(byId[s.id])
    if ms == nil and isActive then ms = tonumber(health.latency_ms) end
    if ms ~= nil then
      cells[#cells + 1] = pingBadge(ms)
    end
    cells[#cells + 1] = ui.button({ glyph = "pencil", glyphSize = 13, variant = "ghost",
                                    onClick = "onEdit" .. tostring(slot) })
    cells[#cells + 1] = ui.button({ glyph = "trash", glyphSize = 13, variant = "ghost",
                                    onClick = "onDel" .. tostring(slot) })

    rows[#rows + 1] = ui.row({ gap = 10, align = "center", fill = fill, radius = 10,
                               border = edge, borderWidth = edge and 1 or nil,
                               paddingH = 12, paddingV = 10 }, cells)
  end
  if #rows == 0 then
    rows[1] = ui.row({ paddingH = 12, paddingV = 10 }, {
      ui.label({ text = noctalia.tr("panel.no-servers"), color = T.muted }),
    })
  end
  return rows
end

local function hero(status, backend, running)
  if not backend.ready then return "shield-off", T.muted end
  local level = status.statusLevel
  if running and (level == "error" or level == "failed") then return "alert-triangle", T.danger end
  if running and level == "degraded" then return "alert-circle", T.pingMid end
  if running then return "shield-check", T.success end
  return "shield-off", T.muted
end

local function mainView()
  local status  = noctalia.state.get("status") or {}
  local servers = noctalia.state.get("servers") or {}
  local health  = noctalia.state.get("health") or {}
  local backend = noctalia.state.get("backend") or {}
  local sp      = noctalia.state.get("speedtest") or {}
  local pings   = noctalia.state.get("pings") or {}
  local running = status.running == true

  local down = (sp.down_mbps and sp.down_mbps > 0) and sp.down_mbps or health.down_mbps
  local up   = (sp.up_mbps and sp.up_mbps > 0) and sp.up_mbps or health.up_mbps
  -- A finished test reports its own latency; prefer it over the background probe.
  local ping = (sp.ping_ms and sp.ping_ms > 0) and sp.ping_ms or health.latency_ms

  local heroGlyph, heroColor = hero(status, backend, running)

  local heroTitle
  if not backend.ready then
    heroTitle = noctalia.tr("panel.starting")
  elseif running then
    heroTitle = noctalia.tr("panel.connected")
  else
    heroTitle = noctalia.tr("panel.disconnected")
  end

  -- Active server subtitle.
  local heroSub = running and activeName(servers, status.activeServerId) or nil

  -- Telemetry line.
  local line2
  if not backend.ready then
    line2 = backend.error and ("backend: " .. backend.error) or ""
  elseif running and ping and ping > 0 then
    line2 = tostring(ping) .. " ms"
    if down and down > 0 then
      line2 = line2 .. "   ↓" .. string.format("%.1f", down)
              .. " ↑" .. string.format("%.1f", up or 0) .. " Mbps"
    end
  else
    line2 = ""
  end

  local heroHead = {
    ui.box({ width = 7, height = 7, radius = 4, fill = heroColor }),
    ui.label({ text = heroTitle, color = T.text, fontSize = 15, fontWeight = "semibold" }),
  }
  if heroSub then
    heroHead[#heroHead + 1] = ui.label({ text = "· " .. heroSub, color = T.muted,
                                         fontSize = 14, maxLines = 1, flexGrow = 1 })
  end

  local heroBody = { ui.row({ gap = 8, align = "center" }, heroHead) }
  if line2 ~= "" then
    heroBody[#heroBody + 1] = ui.label({ text = line2, color = T.textDim, fontSize = 12, maxLines = 1 })
  end

  -- Mass-ping progress / summary, shown only once a sweep has run or started.
  local pingDone = 0
  for _ in pairs(pings.byId or {}) do pingDone = pingDone + 1 end
  local pingLine = nil
  if pings.running then
    pingLine = ui.label({ text = noctalia.tr("panel.pinging") .. " " .. tostring(pingDone)
      .. " / " .. tostring(pings.total or 0), fontSize = 11, color = T.muted })
  elseif (pings.total or 0) > 0 then
    local best = tonumber(pings.best)
    pingLine = ui.label({ text = tostring(pings.alive or 0) .. "/" .. tostring(pings.total)
      .. " " .. noctalia.tr("panel.alive") .. "  ·  " .. noctalia.tr("panel.best") .. " "
      .. ((best and best >= 0) and (tostring(best) .. " ms") or "—"),
      fontSize = 11, color = T.muted })
  end

  -- No width here: the column fills the panel declared in plugin.toml, so the
  -- content uses the whole window instead of sitting in a 380px strip.
  return ui.column({ gap = 0, flexGrow = 1 }, {
    -- ── header ──────────────────────────────────────────────────
    ui.row({ gap = 8, align = "center", paddingH = 16, paddingV = 14 }, {
      ui.label({ text = noctalia.tr("title"), color = T.text, fontSize = 16,
                 fontWeight = "semibold", flexGrow = 1 }),
      ui.toggle({ checked = running, onChange = "onMaster" }),
      ui.button({ glyph = "cloud-download", glyphSize = 15, variant = "ghost", onClick = "onOpenSubs" }),
      ui.button({ glyph = "file-text", glyphSize = 15, variant = "ghost", onClick = "onOpenLogs" }),
      ui.button({ glyph = "settings", glyphSize = 15, variant = "ghost", onClick = "onOpenRules" }),
      ui.button({ glyph = "x", glyphSize = 15, variant = "ghost", onClick = "onClosePanel" }),
    }),
    ui.separator({}),

    ui.column({ gap = 14, paddingH = 16, paddingV = 14, flexGrow = 1 }, {
      -- ── status hero card ──────────────────────────────────────
      ui.row({ gap = 14, align = "center", fill = T.card, radius = 14,
               border = T.borderSoft, borderWidth = 1, paddingH = 16, paddingV = 14 }, {
        ui.row({ fill = mix(heroColor, T.cardBase, 0.14), radius = 12,
                 border = mix(heroColor, T.cardBase, 0.28), borderWidth = 1,
                 paddingH = 10, paddingV = 10, align = "center" }, {
          ui.glyph({ name = heroGlyph, size = 22, color = heroColor }),
        }),
        ui.column({ gap = 3, flexGrow = 1 }, heroBody),
        -- Single test button, in the hero's right corner: it drives both
        -- numbers shown to its left (latency and throughput).
        ui.button({ text = noctalia.tr("action.run-test"), glyph = "gauge", glyphSize = 14,
                    variant = "outline", onClick = "onRunTest", enabled = backend.ready == true }),
      }),

      -- ── mode chips ────────────────────────────────────────────
      ui.row({ gap = 10 }, {
        ui.column({ gap = 4, flexGrow = 1 }, {
          ui.label({ text = noctalia.tr("panel.routing"), fontSize = 11, color = T.muted }),
          ui.select({ selectedIndex = (status.mode == "global") and 1 or 0,
                      options = { "rules", "global" }, onChange = "onMode", flexGrow = 1 }),
        }),
        ui.column({ gap = 4, flexGrow = 1 }, {
          ui.label({ text = noctalia.tr("panel.via"), fontSize = 11, color = T.muted }),
          ui.select({ selectedIndex = (status.proxyMode == "tun") and 1 or 0,
                      options = { "system", "tun" }, onChange = "onVia", flexGrow = 1 }),
        }),
      }),

      -- ── servers ───────────────────────────────────────────────
      ui.row({ gap = 6, align = "center" }, {
        ui.label({ text = noctalia.tr("panel.servers") .. " (" .. tostring(#servers) .. ")",
                   fontSize = 12, color = T.muted, flexGrow = 1 }),
        ui.button({ text = noctalia.tr("action.fastest"), glyph = "bolt", glyphSize = 14,
                    variant = "outline", onClick = "onFastest",
                    enabled = backend.ready == true and #servers > 0 }),
        ui.button({ glyph = "activity", glyphSize = 14, variant = "ghost", onClick = "onPingAll",
                    enabled = backend.ready == true and #servers > 0 }),
        ui.button({ glyph = "arrow-down-up", glyphSize = 14, variant = "ghost",
                    onClick = "onSortPing" }),
        ui.button({ glyph = "clipboard", glyphSize = 14, variant = "ghost", onClick = "onImportClip" }),
        ui.button({ text = noctalia.tr("action.add"), glyph = "plus", glyphSize = 14,
                    variant = "primary", onClick = "onAddServer" }),
      }),
      pingLine,
      -- flexGrow, not a fixed height: the list takes whatever vertical space
      -- is left so the panel has no dead area at the bottom.
      ui.scroll({ flexGrow = 1, gap = 4 }, { ui.column({ gap = 4 }, serverRows(servers, status, running, health, pings)) }),
    }),
  })
end

-- ================================================================
-- EDITOR VIEW
-- ================================================================
local function field(key, labelKey, placeholder)
  return ui.column({ gap = 2 }, {
    ui.label({ text = noctalia.tr(labelKey), fontSize = 11, color = T.muted }),
    ui.input({ key = "fld-" .. key .. "-" .. formRev, value = tostring(form[key] or ""),
               placeholder = placeholder or "", onChange = "onFld_" .. key, flexGrow = 1 }),
  })
end

local function protoFields()
  local p = formProto
  -- GetServers strips secrets, so an edited server's password/uuid arrive
  -- empty; the backend keeps the stored value when they stay empty on save.
  local keep = editingId and noctalia.tr("editor.keep") or nil
  local f = {}
  if p == "ssh" then
    f = { field("host", "editor.host", "1.2.3.4"), field("port", "editor.port", "22"),
          field("user", "editor.user", "root"), field("password", "editor.password", keep),
          field("keyFile", "editor.keyfile", "~/.ssh/id_ed25519") }
  elseif p == "vless" then
    f = { field("address", "editor.address"), field("port", "editor.port"),
          field("uuid", "editor.uuid", keep),
          ui.column({ gap = 2 }, { ui.label({ text = noctalia.tr("editor.transport"), fontSize = 11, color = T.muted }),
            ui.select({ selectedIndex = indexOf(TRANSPORTS, form.transport, 0), options = TRANSPORTS, onChange = "onFldTransport", flexGrow = 1 }) }),
          ui.column({ gap = 2 }, { ui.label({ text = noctalia.tr("editor.security"), fontSize = 11, color = T.muted }),
            ui.select({ selectedIndex = indexOf(SECURITIES, form.security, 0), options = SECURITIES, onChange = "onFldSecurity", flexGrow = 1 }) }),
          field("sni", "editor.sni"), field("flow", "editor.flow"),
          field("pbk", "editor.pbk"), field("sid", "editor.sid"), field("fp", "editor.fp"),
          field("path", "editor.path"), field("host", "editor.wshost") }
  elseif p == "vmess" then
    f = { field("address", "editor.address"), field("port", "editor.port"),
          field("uuid", "editor.uuid", keep), field("alterId", "editor.alterid", "0"),
          ui.column({ gap = 2 }, { ui.label({ text = noctalia.tr("editor.transport"), fontSize = 11, color = T.muted }),
            ui.select({ selectedIndex = indexOf(TRANSPORTS, form.transport, 0), options = TRANSPORTS, onChange = "onFldTransport", flexGrow = 1 }) }),
          field("sni", "editor.sni"), field("path", "editor.path"), field("host", "editor.wshost") }
  elseif p == "shadowsocks" then
    f = { field("address", "editor.address"), field("port", "editor.port"),
          field("method", "editor.method", "aes-256-gcm"), field("password", "editor.password", keep) }
  elseif p == "socks5" then
    f = { field("host", "editor.host"), field("port", "editor.port"),
          field("username", "editor.user"), field("password", "editor.password", keep) }
  end
  return f
end

local function editorView()
  local children = {
    ui.column({ gap = 2 }, {
      ui.label({ text = noctalia.tr("editor.protocol"), fontSize = 11, color = T.muted }),
      ui.select({ selectedIndex = indexOf(PROTOS, formProto, 0), options = PROTOS,
                  onChange = "onFldProto", flexGrow = 1, enabled = editingId == nil }),
    }),
    field("name", "editor.name", "my server"),
    -- The flag in the server row comes from here. Nothing in the backend ever
    -- derives a country (the models have no such field; they just accept extra
    -- keys), so without this input flagFor() had no data and the flag could
    -- never render.
    field("country", "editor.country", "fi"),
  }
  for _, f in ipairs(protoFields()) do children[#children + 1] = f end
  children[#children + 1] = ui.separator({})
  children[#children + 1] = ui.row({ gap = 8 }, {
    ui.button({ text = noctalia.tr("action.save"), glyph = "check", variant = "primary", onClick = "onSave" }),
    ui.spacer({}),
    editingId and ui.button({ text = noctalia.tr("action.delete"), glyph = "trash", glyphSize = 13,
                              variant = "outline", onClick = "onDelete" }) or ui.spacer({}),
  })
  -- Header outside the scroll, scroll on flexGrow: a fixed scroll height
  -- overflowed the panel instead of clipping, leaving Save unreachable.
  return ui.column({ gap = 10, padding = 16, flexGrow = 1 }, {
    ui.row({ gap = 8, align = "center" }, {
      ui.button({ glyph = "chevron-left", variant = "ghost", onClick = "onBack" }),
      ui.label({ text = editingId and noctalia.tr("editor.edit") or noctalia.tr("editor.new"),
                 fontWeight = "bold", fontSize = 15, flexGrow = 1 }),
    }),
    ui.scroll({ flexGrow = 1 }, { ui.column({ gap = 10 }, children) }),
  })
end

-- ================================================================
-- RULES VIEW
-- ================================================================
local function rulesView()
  local presets = noctalia.state.get("presets") or {}
  local rules   = noctalia.state.get("rules") or {}
  local kill    = noctalia.state.get("killswitch") or {}
  local dns     = noctalia.state.get("dnsleak")

  local dnsText, dnsColor
  if dns == nil then
    dnsText, dnsColor = noctalia.tr("rules.dns-hint"), T.muted
  elseif dns.leaking then
    dnsText, dnsColor = noctalia.tr("rules.dns-leak") .. " — " .. (dns.reason or ""), T.danger
  else
    dnsText, dnsColor = noctalia.tr("rules.dns-ok") .. " — " .. (dns.reason or ""), T.success
  end

  local presetRows = {}
  presetKeys = {}
  for i, p in ipairs(presets) do
    local slot = i - 1
    if slot >= MAX_PRE then break end
    presetKeys[slot] = p.key
    presetRows[#presetRows + 1] = ui.row({ gap = 8, align = "center" }, {
      ui.label({ text = (p.flag or "") .. " " .. (p.name or p.key), flexGrow = 1 }),
      ui.toggle({ checked = p.enabled == true, onChange = "onPreset" .. tostring(slot) }),
    })
  end

  local ruleRows = {}
  ruleIds = {}
  for i, r in ipairs(rules) do
    local slot = i - 1
    if slot >= MAX_RULE then break end
    ruleIds[slot] = r.id
    ruleRows[#ruleRows + 1] = ui.row({ gap = 6, align = "center" }, {
      ui.glyph({ name = r.type == "block" and "ban" or (r.type == "direct" and "arrow-right" or "shield"),
                 color = r.type == "block" and T.danger or T.muted }),
      ui.column({ gap = 0, flexGrow = 1 }, {
        ui.label({ text = r.pattern or "", fontSize = 13 }),
        ui.label({ text = r.type or "", fontSize = 10, color = T.muted }),
      }),
      ui.button({ glyph = "x", variant = "ghost", onClick = "onRuleDel" .. tostring(slot) }),
    })
  end
  if #ruleRows == 0 then
    ruleRows[1] = ui.row({ paddingH = 6, paddingV = 6 }, {
      ui.label({ text = noctalia.tr("rules.none"), color = T.muted }),
    })
  end

  -- Header outside the scroll, scroll on flexGrow (same fix as editorView):
  -- a fixed scroll height overflowed the panel instead of clipping.
  return ui.column({ gap = 12, padding = 16, flexGrow = 1 }, {
    ui.row({ gap = 8, align = "center" }, {
      ui.button({ glyph = "chevron-left", variant = "ghost", onClick = "onBack" }),
      ui.label({ text = noctalia.tr("rules.title"), fontWeight = "bold", fontSize = 15, flexGrow = 1 }),
    }),

    ui.scroll({ flexGrow = 1 }, { ui.column({ gap = 12 }, {
    ui.row({ gap = 8, align = "center" }, {
      ui.glyph({ name = "shield-x", color = kill.enabled and T.danger or T.muted }),
      ui.column({ gap = 0, flexGrow = 1 }, {
        ui.label({ text = noctalia.tr("rules.killswitch") }),
        ui.label({ text = noctalia.tr("rules.killswitch-desc"), fontSize = 10, color = T.muted }),
      }),
      ui.toggle({ checked = kill.enabled == true, onChange = "onKill" }),
    }),

    ui.row({ gap = 8, align = "center" }, {
      ui.glyph({ name = "world-search", color = dnsColor }),
      ui.label({ text = dnsText, fontSize = 11, color = dnsColor, flexGrow = 1 }),
      ui.button({ text = noctalia.tr("rules.dns-check"), variant = "outline", onClick = "onDnsCheck" }),
    }),

    ui.separator({}),
    ui.label({ text = noctalia.tr("rules.presets"), fontSize = 12, color = T.muted }),
    ui.column({ gap = 6 }, presetRows),

    ui.separator({}),
    ui.label({ text = noctalia.tr("rules.custom"), fontSize = 12, color = T.muted }),
    ui.row({ gap = 6, align = "center" }, {
      ui.input({ key = "rule-pat-" .. ruleRev, value = ruleForm.pattern, placeholder = "*.example.com | 10.0.0.0/8",
                 onChange = "onRulePattern", flexGrow = 1 }),
      ui.select({ selectedIndex = indexOf(RULE_TYPES, ruleForm.type, 0), options = RULE_TYPES, onChange = "onRuleType" }),
      ui.button({ glyph = "plus", variant = "primary", onClick = "onRuleAdd" }),
    }),
    ui.column({ gap = 6 }, ruleRows),

    -- Two-step reset because there is no undo or backend bulk-clear command.
    ui.separator({}),
    ui.row({ gap = 8, align = "center" }, {
      ui.glyph({ name = "trash", size = 15, color = resetArmed and T.danger or T.muted }),
      ui.column({ gap = 0, flexGrow = 1 }, {
        ui.label({ text = noctalia.tr("rules.reset-servers"), color = resetArmed and T.danger or T.text }),
        ui.label({ text = noctalia.tr("rules.reset-servers-desc"), fontSize = 10, color = T.muted }),
      }),
      ui.button({ text = resetArmed and noctalia.tr("action.confirm") or noctalia.tr("action.reset"),
                  variant = "outline", onClick = "onResetServers" }),
    }),
    }) }),
  })
end

-- ================================================================
-- LOGS VIEW
-- ================================================================
local function logsView()
  local logs = noctalia.state.get("logs") or {}
  local rows = {}
  local startI = math.max(1, #logs - 150)
  for i = startI, #logs do
    local e = logs[i]
    local lvl = (e and e.level) or "info"
    rows[#rows + 1] = ui.label({
      text = (e and e.message) or "",
      fontSize = 11,
      color = (lvl == "error" and T.danger) or (lvl == "warn" and T.pingMid) or T.muted,
    })
  end
  if #rows == 0 then rows[1] = ui.label({ text = noctalia.tr("logs.empty"), color = T.muted }) end
  return ui.column({ gap = 10, padding = 16, flexGrow = 1 }, {
    ui.row({ gap = 8, align = "center" }, {
      ui.button({ glyph = "chevron-left", variant = "ghost", onClick = "onBack" }),
      ui.label({ text = noctalia.tr("logs.title"), fontWeight = "bold", fontSize = 15, flexGrow = 1 }),
    }),
    ui.scroll({ flexGrow = 1, stickToBottom = true }, { ui.column({ gap = 3 }, rows) }),
  })
end

-- ================================================================
-- SUBSCRIPTIONS VIEW
-- ================================================================
local function subsView()
  local subs = noctalia.state.get("subscriptions") or {}
  local rows = {}
  subUrls = {}
  for i, sub in ipairs(subs) do
    local slot = i - 1
    if slot >= MAX_SUB then break end
    subUrls[slot] = sub.url
    rows[#rows + 1] = ui.row({ gap = 6, align = "center" }, {
      ui.column({ gap = 0, flexGrow = 1 }, {
        ui.label({ text = (sub.name and sub.name ~= "") and sub.name or (sub.url or ""), fontSize = 13 }),
        ui.label({ text = sub.url or "", fontSize = 10, color = T.muted }),
      }),
      ui.button({ glyph = "refresh", variant = "ghost", onClick = "onSubUpd" .. tostring(slot) }),
      ui.button({ glyph = "x", variant = "ghost", onClick = "onSubDel" .. tostring(slot) }),
    })
  end
  if #rows == 0 then
    rows[1] = ui.row({ paddingH = 6, paddingV = 6 }, {
      ui.label({ text = noctalia.tr("subs.none"), color = T.muted }),
    })
  end

  return ui.column({ gap = 12, padding = 16, flexGrow = 1 }, {
    ui.row({ gap = 8, align = "center" }, {
      ui.button({ glyph = "chevron-left", variant = "ghost", onClick = "onBack" }),
      ui.label({ text = noctalia.tr("subs.title"), fontWeight = "bold", fontSize = 15, flexGrow = 1 }),
    }),
    ui.column({ gap = 6 }, {
      ui.input({ key = "sub-url-" .. subRev, value = subForm.url, placeholder = "https://…/sub",
                 onChange = "onSubUrl", flexGrow = 1 }),
      ui.row({ gap = 6, align = "center" }, {
        ui.input({ key = "sub-name-" .. subRev, value = subForm.name, placeholder = noctalia.tr("subs.name"),
                   onChange = "onSubName", flexGrow = 1 }),
        ui.button({ text = noctalia.tr("action.add"), glyph = "plus", variant = "primary", onClick = "onSubAdd" }),
      }),
    }),
    ui.separator({}),
    ui.scroll({ flexGrow = 1 }, { ui.column({ gap = 8 }, rows) }),
  })
end

-- ── dispatch ────────────────────────────────────────────────────
render = function()
  local tree
  if view == "editor" then tree = editorView()
  elseif view == "rules" then tree = rulesView()
  elseif view == "logs" then tree = logsView()
  elseif view == "subs" then tree = subsView()
  else tree = mainView() end
  panel.render(tree)
end

-- ── lifecycle ───────────────────────────────────────────────────
function onOpen()
  for _, k in ipairs({ "status", "servers", "health", "backend", "presets", "rules",
                       "killswitch", "logs", "subscriptions", "speedtest", "dnsleak",
                       "pings" }) do
    noctalia.state.watch(k, function(_) render() end)
  end
  render()
end
function onClose() end

-- ── main handlers ───────────────────────────────────────────────
function onToggle()
  local s = noctalia.state.get("status") or {}
  if s.running then send("StopProxy", {})
  elseif s.activeServerId and s.activeServerId ~= "" then
    send("StartProxy", { s.activeServerId, s.mode or "rules", s.proxyMode or "system" })
  else noctalia.notifyError("VPN", noctalia.tr("error.no-server")) end
end
-- The toggle reports the desired value; onToggle derives the action from state.
function onMaster(_) onToggle() end
function onClosePanel() panel.close() end

function onMode(_, label) send("SetMode", { label }) end
function onVia(_, label)
  if label == "tun" then noctalia.notify("VPN", noctalia.tr("notice.tun")) end
  send("SetProxyMode", { label })
end
-- RunSpeedTest reports latency and throughput in one command.
function onRunTest()
  local s = noctalia.state.get("status") or {}
  if not s.activeServerId or s.activeServerId == "" then
    noctalia.notifyError("VPN", noctalia.tr("error.no-server"))
    return
  end
  send("RunSpeedTest", {})
end
function onOpenRules() navigate("rules") end
function onOpenLogs() navigate("logs") end
function onOpenSubs() navigate("subs") end
function onBack() navigate("main") end

-- ── mass ping / fastest ─────────────────────────────────────────
function onFastest()
  local s = noctalia.state.get("status") or {}
  send("ConnectFastest", { s.mode or "rules", s.proxyMode or "system" })
end
function onPingAll() send("PingAll", {}) end
function onSortPing() sortByPing = not sortByPing; render() end

function onImportClip()
  local txt = noctalia.clipboardText()
  if txt and txt ~= "" then send("ParseShareLink", { txt })
  else noctalia.notifyError("VPN", noctalia.tr("error.clipboard")) end
end
function onDnsCheck() send("CheckDnsLeak", {}) end

-- ── editor open/save ────────────────────────────────────────────
local function openEditor(server)
  form = {}
  formRev = formRev + 1
  if server then
    editingId = server.id
    formProto = server.protocol or "ssh"
    for k, v in pairs(server) do form[k] = v end
  else
    editingId = nil
    formProto = "ssh"
    form.port = "22"
  end
  navigate("editor")
end

function onAddServer() openEditor(nil) end

function onSave()
  local p = { protocol = formProto, name = form.name or "" }
  -- Persisted via the models' extra="allow"; only the UI reads it.
  local cc = (form.country or ""):lower():gsub("%s", "")
  if #cc == 2 then p.country = cc end
  if editingId then p.id = editingId end
  if formProto == "ssh" then
    p.host = form.host; p.port = num(form.port, 22); p.user = form.user
    if form.password and form.password ~= "" then p.password = form.password end
    if form.keyFile and form.keyFile ~= "" then p.keyFile = form.keyFile end
  elseif formProto == "vless" then
    p.address = form.address; p.port = num(form.port, 443); p.uuid = form.uuid
    p.transport = form.transport or "tcp"; p.security = form.security or "none"
    for _, k in ipairs({ "sni", "flow", "pbk", "sid", "fp", "path", "host", "serviceName" }) do
      if form[k] and form[k] ~= "" then p[k] = form[k] end
    end
  elseif formProto == "vmess" then
    p.address = form.address; p.port = num(form.port, 443); p.uuid = form.uuid
    p.alterId = num(form.alterId, 0); p.transport = form.transport or "tcp"
    for _, k in ipairs({ "sni", "path", "host" }) do
      if form[k] and form[k] ~= "" then p[k] = form[k] end
    end
  elseif formProto == "shadowsocks" then
    p.address = form.address; p.port = num(form.port, 8388)
    p.method = form.method; p.password = form.password
  elseif formProto == "socks5" then
    p.host = form.host; p.port = num(form.port, 1080)
    if form.username and form.username ~= "" then p.username = form.username end
    if form.password and form.password ~= "" then p.password = form.password end
  end
  send(editingId and "UpdateServer" or "AddServer", { p })
  navigate("main")
end

function onDelete()
  if editingId then send("RemoveServer", { editingId }) end
  editingId = nil
  navigate("main")
end

-- editor field handlers (uncontrolled inputs → accumulate in form)
function onFld_name(v)       form.name = v end
function onFld_country(v)    form.country = v end
function onFld_host(v)       form.host = v end
function onFld_address(v)    form.address = v end
function onFld_port(v)       form.port = v end
function onFld_user(v)       form.user = v end
function onFld_password(v)   form.password = v end
function onFld_keyFile(v)    form.keyFile = v end
function onFld_uuid(v)       form.uuid = v end
function onFld_method(v)     form.method = v end
function onFld_sni(v)        form.sni = v end
function onFld_flow(v)       form.flow = v end
function onFld_fp(v)         form.fp = v end
function onFld_pbk(v)        form.pbk = v end
function onFld_sid(v)        form.sid = v end
function onFld_path(v)       form.path = v end
function onFld_serviceName(v) form.serviceName = v end
function onFld_username(v)   form.username = v end
function onFld_alterId(v)    form.alterId = v end
function onFldTransport(_, label) form.transport = label end
function onFldSecurity(_, label)  form.security = label end
function onFldProto(_, label)     formProto = label; formRev = formRev + 1; render() end

-- ── rules handlers ──────────────────────────────────────────────
function onKill(value) send("SetKillSwitch", { value == "true" }) end

-- Arms on the first click, fires on the second. Every state.set is delivered in
-- order (verified — the host queues them rather than collapsing to the last),
-- so fanning out one RemoveServer per id is safe.
function onResetServers()
  if not resetArmed then
    resetArmed = true
    render()
    return
  end
  resetArmed = false
  for _, s in ipairs(noctalia.state.get("servers") or {}) do
    send("RemoveServer", { s.id })
  end
  render()
end
function onRulePattern(v) ruleForm.pattern = v end
function onRuleType(_, label) ruleForm.type = label end
function onRuleAdd()
  if not ruleForm.pattern or ruleForm.pattern == "" then return end
  send("AddRoutingRule", { { pattern = ruleForm.pattern, type = ruleForm.type, enabled = true } })
  ruleForm.pattern = ""
  ruleRev = ruleRev + 1
  render()
end

local function onPresetAt(slot, value)
  local key = presetKeys[slot]; if key then send("TogglePreset", { key, value == "true" }) end
end
local function onRuleDelAt(slot)
  local id = ruleIds[slot]; if id then send("RemoveRoutingRule", { id }) end
end

-- ── subscription handlers ───────────────────────────────────────
function onSubUrl(v) subForm.url = v end
function onSubName(v) subForm.name = v end
function onSubAdd()
  if not subForm.url or subForm.url == "" then return end
  send("AddSubscription", { subForm.url, subForm.name or "" })
  subForm.url = ""; subForm.name = ""; subRev = subRev + 1; render()
end
local function onSubUpdAt(slot) local u = subUrls[slot]; if u then send("UpdateSubscription", { u }) end end
local function onSubDelAt(slot) local u = subUrls[slot]; if u then send("RemoveSubscription", { u }) end end

-- ── server row handlers ─────────────────────────────────────────
local function onServerAt(slot)
  local id = slotIds[slot]; if not id then return end
  local s = noctalia.state.get("status") or {}
  if s.running then send("SwitchServer", { id })
  else send("StartProxy", { id, s.mode or "rules", s.proxyMode or "system" }) end
end
local function onEditAt(slot)
  local id = slotIds[slot]; if not id then return end
  for _, sv in ipairs(noctalia.state.get("servers") or {}) do
    if sv.id == id then openEditor(sv); return end
  end
end
local function onDelAt(slot)
  local id = slotIds[slot]; if id then send("RemoveServer", { id }) end
end

-- ── fixed handler pools (host resolves onClick by global name) ───
-- One global per slot: the host looks callbacks up by name, and a global
-- written through _G is invisible to it, so these stay plain declarations.

function onServer0() onServerAt(0) end  function onServer1() onServerAt(1) end  function onServer2() onServerAt(2) end  function onServer3() onServerAt(3) end
function onServer4() onServerAt(4) end  function onServer5() onServerAt(5) end  function onServer6() onServerAt(6) end  function onServer7() onServerAt(7) end
function onServer8() onServerAt(8) end  function onServer9() onServerAt(9) end  function onServer10() onServerAt(10) end  function onServer11() onServerAt(11) end
function onServer12() onServerAt(12) end  function onServer13() onServerAt(13) end  function onServer14() onServerAt(14) end  function onServer15() onServerAt(15) end
function onServer16() onServerAt(16) end  function onServer17() onServerAt(17) end  function onServer18() onServerAt(18) end  function onServer19() onServerAt(19) end
function onServer20() onServerAt(20) end  function onServer21() onServerAt(21) end  function onServer22() onServerAt(22) end  function onServer23() onServerAt(23) end
function onServer24() onServerAt(24) end  function onServer25() onServerAt(25) end  function onServer26() onServerAt(26) end  function onServer27() onServerAt(27) end
function onServer28() onServerAt(28) end  function onServer29() onServerAt(29) end  function onServer30() onServerAt(30) end  function onServer31() onServerAt(31) end
function onServer32() onServerAt(32) end  function onServer33() onServerAt(33) end  function onServer34() onServerAt(34) end  function onServer35() onServerAt(35) end
function onServer36() onServerAt(36) end  function onServer37() onServerAt(37) end  function onServer38() onServerAt(38) end  function onServer39() onServerAt(39) end
function onServer40() onServerAt(40) end  function onServer41() onServerAt(41) end  function onServer42() onServerAt(42) end  function onServer43() onServerAt(43) end
function onServer44() onServerAt(44) end  function onServer45() onServerAt(45) end  function onServer46() onServerAt(46) end  function onServer47() onServerAt(47) end
function onServer48() onServerAt(48) end  function onServer49() onServerAt(49) end  function onServer50() onServerAt(50) end  function onServer51() onServerAt(51) end
function onServer52() onServerAt(52) end  function onServer53() onServerAt(53) end  function onServer54() onServerAt(54) end  function onServer55() onServerAt(55) end
function onServer56() onServerAt(56) end  function onServer57() onServerAt(57) end  function onServer58() onServerAt(58) end  function onServer59() onServerAt(59) end
function onServer60() onServerAt(60) end  function onServer61() onServerAt(61) end  function onServer62() onServerAt(62) end  function onServer63() onServerAt(63) end

function onEdit0() onEditAt(0) end  function onEdit1() onEditAt(1) end  function onEdit2() onEditAt(2) end  function onEdit3() onEditAt(3) end
function onEdit4() onEditAt(4) end  function onEdit5() onEditAt(5) end  function onEdit6() onEditAt(6) end  function onEdit7() onEditAt(7) end
function onEdit8() onEditAt(8) end  function onEdit9() onEditAt(9) end  function onEdit10() onEditAt(10) end  function onEdit11() onEditAt(11) end
function onEdit12() onEditAt(12) end  function onEdit13() onEditAt(13) end  function onEdit14() onEditAt(14) end  function onEdit15() onEditAt(15) end
function onEdit16() onEditAt(16) end  function onEdit17() onEditAt(17) end  function onEdit18() onEditAt(18) end  function onEdit19() onEditAt(19) end
function onEdit20() onEditAt(20) end  function onEdit21() onEditAt(21) end  function onEdit22() onEditAt(22) end  function onEdit23() onEditAt(23) end
function onEdit24() onEditAt(24) end  function onEdit25() onEditAt(25) end  function onEdit26() onEditAt(26) end  function onEdit27() onEditAt(27) end
function onEdit28() onEditAt(28) end  function onEdit29() onEditAt(29) end  function onEdit30() onEditAt(30) end  function onEdit31() onEditAt(31) end
function onEdit32() onEditAt(32) end  function onEdit33() onEditAt(33) end  function onEdit34() onEditAt(34) end  function onEdit35() onEditAt(35) end
function onEdit36() onEditAt(36) end  function onEdit37() onEditAt(37) end  function onEdit38() onEditAt(38) end  function onEdit39() onEditAt(39) end
function onEdit40() onEditAt(40) end  function onEdit41() onEditAt(41) end  function onEdit42() onEditAt(42) end  function onEdit43() onEditAt(43) end
function onEdit44() onEditAt(44) end  function onEdit45() onEditAt(45) end  function onEdit46() onEditAt(46) end  function onEdit47() onEditAt(47) end
function onEdit48() onEditAt(48) end  function onEdit49() onEditAt(49) end  function onEdit50() onEditAt(50) end  function onEdit51() onEditAt(51) end
function onEdit52() onEditAt(52) end  function onEdit53() onEditAt(53) end  function onEdit54() onEditAt(54) end  function onEdit55() onEditAt(55) end
function onEdit56() onEditAt(56) end  function onEdit57() onEditAt(57) end  function onEdit58() onEditAt(58) end  function onEdit59() onEditAt(59) end
function onEdit60() onEditAt(60) end  function onEdit61() onEditAt(61) end  function onEdit62() onEditAt(62) end  function onEdit63() onEditAt(63) end

function onDel0() onDelAt(0) end  function onDel1() onDelAt(1) end  function onDel2() onDelAt(2) end  function onDel3() onDelAt(3) end
function onDel4() onDelAt(4) end  function onDel5() onDelAt(5) end  function onDel6() onDelAt(6) end  function onDel7() onDelAt(7) end
function onDel8() onDelAt(8) end  function onDel9() onDelAt(9) end  function onDel10() onDelAt(10) end  function onDel11() onDelAt(11) end
function onDel12() onDelAt(12) end  function onDel13() onDelAt(13) end  function onDel14() onDelAt(14) end  function onDel15() onDelAt(15) end
function onDel16() onDelAt(16) end  function onDel17() onDelAt(17) end  function onDel18() onDelAt(18) end  function onDel19() onDelAt(19) end
function onDel20() onDelAt(20) end  function onDel21() onDelAt(21) end  function onDel22() onDelAt(22) end  function onDel23() onDelAt(23) end
function onDel24() onDelAt(24) end  function onDel25() onDelAt(25) end  function onDel26() onDelAt(26) end  function onDel27() onDelAt(27) end
function onDel28() onDelAt(28) end  function onDel29() onDelAt(29) end  function onDel30() onDelAt(30) end  function onDel31() onDelAt(31) end
function onDel32() onDelAt(32) end  function onDel33() onDelAt(33) end  function onDel34() onDelAt(34) end  function onDel35() onDelAt(35) end
function onDel36() onDelAt(36) end  function onDel37() onDelAt(37) end  function onDel38() onDelAt(38) end  function onDel39() onDelAt(39) end
function onDel40() onDelAt(40) end  function onDel41() onDelAt(41) end  function onDel42() onDelAt(42) end  function onDel43() onDelAt(43) end
function onDel44() onDelAt(44) end  function onDel45() onDelAt(45) end  function onDel46() onDelAt(46) end  function onDel47() onDelAt(47) end
function onDel48() onDelAt(48) end  function onDel49() onDelAt(49) end  function onDel50() onDelAt(50) end  function onDel51() onDelAt(51) end
function onDel52() onDelAt(52) end  function onDel53() onDelAt(53) end  function onDel54() onDelAt(54) end  function onDel55() onDelAt(55) end
function onDel56() onDelAt(56) end  function onDel57() onDelAt(57) end  function onDel58() onDelAt(58) end  function onDel59() onDelAt(59) end
function onDel60() onDelAt(60) end  function onDel61() onDelAt(61) end  function onDel62() onDelAt(62) end  function onDel63() onDelAt(63) end

function onPreset0(v) onPresetAt(0, v) end  function onPreset1(v) onPresetAt(1, v) end  function onPreset2(v) onPresetAt(2, v) end  function onPreset3(v) onPresetAt(3, v) end
function onPreset4(v) onPresetAt(4, v) end  function onPreset5(v) onPresetAt(5, v) end  function onPreset6(v) onPresetAt(6, v) end  function onPreset7(v) onPresetAt(7, v) end

function onRuleDel0() onRuleDelAt(0) end  function onRuleDel1() onRuleDelAt(1) end  function onRuleDel2() onRuleDelAt(2) end  function onRuleDel3() onRuleDelAt(3) end
function onRuleDel4() onRuleDelAt(4) end  function onRuleDel5() onRuleDelAt(5) end  function onRuleDel6() onRuleDelAt(6) end  function onRuleDel7() onRuleDelAt(7) end
function onRuleDel8() onRuleDelAt(8) end  function onRuleDel9() onRuleDelAt(9) end  function onRuleDel10() onRuleDelAt(10) end  function onRuleDel11() onRuleDelAt(11) end
function onRuleDel12() onRuleDelAt(12) end  function onRuleDel13() onRuleDelAt(13) end  function onRuleDel14() onRuleDelAt(14) end  function onRuleDel15() onRuleDelAt(15) end
function onRuleDel16() onRuleDelAt(16) end  function onRuleDel17() onRuleDelAt(17) end  function onRuleDel18() onRuleDelAt(18) end  function onRuleDel19() onRuleDelAt(19) end
function onRuleDel20() onRuleDelAt(20) end  function onRuleDel21() onRuleDelAt(21) end  function onRuleDel22() onRuleDelAt(22) end  function onRuleDel23() onRuleDelAt(23) end
function onRuleDel24() onRuleDelAt(24) end  function onRuleDel25() onRuleDelAt(25) end  function onRuleDel26() onRuleDelAt(26) end  function onRuleDel27() onRuleDelAt(27) end
function onRuleDel28() onRuleDelAt(28) end  function onRuleDel29() onRuleDelAt(29) end  function onRuleDel30() onRuleDelAt(30) end  function onRuleDel31() onRuleDelAt(31) end
function onRuleDel32() onRuleDelAt(32) end  function onRuleDel33() onRuleDelAt(33) end  function onRuleDel34() onRuleDelAt(34) end  function onRuleDel35() onRuleDelAt(35) end
function onRuleDel36() onRuleDelAt(36) end  function onRuleDel37() onRuleDelAt(37) end  function onRuleDel38() onRuleDelAt(38) end  function onRuleDel39() onRuleDelAt(39) end
function onRuleDel40() onRuleDelAt(40) end  function onRuleDel41() onRuleDelAt(41) end  function onRuleDel42() onRuleDelAt(42) end  function onRuleDel43() onRuleDelAt(43) end
function onRuleDel44() onRuleDelAt(44) end  function onRuleDel45() onRuleDelAt(45) end  function onRuleDel46() onRuleDelAt(46) end  function onRuleDel47() onRuleDelAt(47) end
function onRuleDel48() onRuleDelAt(48) end  function onRuleDel49() onRuleDelAt(49) end  function onRuleDel50() onRuleDelAt(50) end  function onRuleDel51() onRuleDelAt(51) end
function onRuleDel52() onRuleDelAt(52) end  function onRuleDel53() onRuleDelAt(53) end  function onRuleDel54() onRuleDelAt(54) end  function onRuleDel55() onRuleDelAt(55) end
function onRuleDel56() onRuleDelAt(56) end  function onRuleDel57() onRuleDelAt(57) end  function onRuleDel58() onRuleDelAt(58) end  function onRuleDel59() onRuleDelAt(59) end
function onRuleDel60() onRuleDelAt(60) end  function onRuleDel61() onRuleDelAt(61) end  function onRuleDel62() onRuleDelAt(62) end  function onRuleDel63() onRuleDelAt(63) end

function onSubUpd0() onSubUpdAt(0) end  function onSubUpd1() onSubUpdAt(1) end  function onSubUpd2() onSubUpdAt(2) end  function onSubUpd3() onSubUpdAt(3) end
function onSubUpd4() onSubUpdAt(4) end  function onSubUpd5() onSubUpdAt(5) end  function onSubUpd6() onSubUpdAt(6) end  function onSubUpd7() onSubUpdAt(7) end
function onSubUpd8() onSubUpdAt(8) end  function onSubUpd9() onSubUpdAt(9) end  function onSubUpd10() onSubUpdAt(10) end  function onSubUpd11() onSubUpdAt(11) end
function onSubUpd12() onSubUpdAt(12) end  function onSubUpd13() onSubUpdAt(13) end  function onSubUpd14() onSubUpdAt(14) end  function onSubUpd15() onSubUpdAt(15) end
function onSubUpd16() onSubUpdAt(16) end  function onSubUpd17() onSubUpdAt(17) end  function onSubUpd18() onSubUpdAt(18) end  function onSubUpd19() onSubUpdAt(19) end
function onSubUpd20() onSubUpdAt(20) end  function onSubUpd21() onSubUpdAt(21) end  function onSubUpd22() onSubUpdAt(22) end  function onSubUpd23() onSubUpdAt(23) end
function onSubUpd24() onSubUpdAt(24) end  function onSubUpd25() onSubUpdAt(25) end  function onSubUpd26() onSubUpdAt(26) end  function onSubUpd27() onSubUpdAt(27) end
function onSubUpd28() onSubUpdAt(28) end  function onSubUpd29() onSubUpdAt(29) end  function onSubUpd30() onSubUpdAt(30) end  function onSubUpd31() onSubUpdAt(31) end

function onSubDel0() onSubDelAt(0) end  function onSubDel1() onSubDelAt(1) end  function onSubDel2() onSubDelAt(2) end  function onSubDel3() onSubDelAt(3) end
function onSubDel4() onSubDelAt(4) end  function onSubDel5() onSubDelAt(5) end  function onSubDel6() onSubDelAt(6) end  function onSubDel7() onSubDelAt(7) end
function onSubDel8() onSubDelAt(8) end  function onSubDel9() onSubDelAt(9) end  function onSubDel10() onSubDelAt(10) end  function onSubDel11() onSubDelAt(11) end
function onSubDel12() onSubDelAt(12) end  function onSubDel13() onSubDelAt(13) end  function onSubDel14() onSubDelAt(14) end  function onSubDel15() onSubDelAt(15) end
function onSubDel16() onSubDelAt(16) end  function onSubDel17() onSubDelAt(17) end  function onSubDel18() onSubDelAt(18) end  function onSubDel19() onSubDelAt(19) end
function onSubDel20() onSubDelAt(20) end  function onSubDel21() onSubDelAt(21) end  function onSubDel22() onSubDelAt(22) end  function onSubDel23() onSubDelAt(23) end
function onSubDel24() onSubDelAt(24) end  function onSubDel25() onSubDelAt(25) end  function onSubDel26() onSubDelAt(26) end  function onSubDel27() onSubDelAt(27) end
function onSubDel28() onSubDelAt(28) end  function onSubDel29() onSubDelAt(29) end  function onSubDel30() onSubDelAt(30) end  function onSubDel31() onSubDelAt(31) end
