--!nonstrict
-- service.luau — headless supervisor for the Python VPN backend.
--
-- Responsibilities:
--   * Probe the backend HTTP control port. If a backend is already running
--     (e.g. the user's active proxy), ATTACH to it (poll only, never spawn a
--     duplicate). Otherwise SPAWN it via runStream and consume its stdout
--     event stream.
--   * Bridge: backend stdout events  → noctalia.state.set(...)
--             UI commands (state "cmd") → HTTP POST /rpc
--   * Poll GetStatus / GetHealth / GetTrafficStats on the update() tick, plus
--     GetLogs while attached (an attached backend sends us no events).
--
-- Cross-VM contract (all plain values through noctalia.state):
--   state "status"        : { running, activeServerId, mode, proxyMode, ... }
--   state "health"        : { latency_ms, jitter_ms, down_mbps, ... }
--   state "traffic"       : { bytes_sent, bytes_received, uptime_seconds, ... }
--   state "servers"       : [ { id, name, protocol, host, ... } ]
--   state "rules"         : [ ... ]
--   state "subscriptions" : [ ... ]
--   state "presets"       : [ { key, name, flag, enabled } ]
--   state "killswitch"    : { enabled, active }
--   state "logs"          : [ { level, message } ]  (ring, last 200)
--   state "backend"       : { ready, owns, error? }
--   state "cmd"           : { method, args, nonce }   (written by UI)
--   state "cmd_result"    : { nonce, method, result, error }

local PORT        = tonumber(noctalia.getConfig("control_port")) or 11090
local PY          = noctalia.getConfig("backend_python") or "python3"
local PROJDIR     = noctalia.pluginDir() or "."
local DATA_DIR    = noctalia.pluginDataDir() or noctalia.expandPath("~/.local/state/ruh-vpn")
local RUNTIME_DIR = DATA_DIR .. "/runtime"
local PIDFILE     = RUNTIME_DIR .. "/ruh-vpn-backend.pid"
local TOKENFILE   = RUNTIME_DIR .. "/ruh-vpn-control.token"
local BASE        = "http://127.0.0.1:" .. tostring(PORT)

local AUTO    = noctalia.getConfig("auto_start") == true
local GEOIP   = noctalia.getConfig("geoip_country") ~= false

local ownsBackend = false
local ready       = false
local autoStarted = false
local lastNonce   = nil
local spawning    = false -- preflight or backend start in flight
local spawnStartedAt = 0  -- os.time() of the last spawn; unblocks a spawn that never reports ready
local probing     = false
local polling     = false
local resetting   = false
local backendGeneration = 0
local backendPid  = nil
local lastSpawnError = nil -- dedupes notifyError across spawn retries
local nextSpawnAt = 0     -- os.time() when the next respawn attempt is allowed
local spawnBackoff = 2    -- seconds, doubles up to 30 on repeated failures

local function shellQuote(value)
  return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

-- ── control token ───────────────────────────────────────────────
-- The backend generates a per-launch token and writes it to TOKENFILE (0600)
-- once its port is bound; every /rpc call must present it. /healthz is open,
-- so the attach probe still works before the token is read.
local TOKEN = nil

local function readToken()
  local contents = noctalia.readFile(TOKENFILE)
  local t = contents and contents:match("%S+") or nil
  if t then TOKEN = t end
  return t ~= nil
end

-- ── RPC helper ──────────────────────────────────────────────────
local function rpc(method, args, cb)
  local headers = { "Content-Type: application/json" }
  if TOKEN then headers[#headers + 1] = "Authorization: Bearer " .. TOKEN end
  return noctalia.http({
    url     = BASE .. "/rpc",
    method  = "POST",
    headers = headers,
    body    = noctalia.json.encode({ method = method, args = args or {} }),
  }, function(resp)
    if not cb then return end
    if resp and resp.ok then
      local d = noctalia.json.decode(resp.body)
      if d then cb(d.result, d.error) else cb(nil, "bad json") end
    else
      cb(nil, resp and ("http " .. tostring(resp.status)) or "no response")
    end
  end)
end

-- ── list refreshers → state ─────────────────────────────────────
local function pub(key) return function(r) if r ~= nil then noctalia.state.set(key, r) end end end
local function refreshServers()  rpc("GetServers", {}, pub("servers")) end
local function refreshRules()    rpc("GetRoutingRules", {}, pub("rules")) end
local function refreshSubs()     rpc("GetSubscriptions", {}, pub("subscriptions")) end
local function refreshPresets()  rpc("GetPresets", {}, pub("presets")) end
local function refreshKill()     rpc("GetKillSwitchStatus", {}, pub("killswitch")) end
local function refreshSettings() rpc("GetSettings", {}, pub("settings")) end

-- ── mass-ping state → state "pings" ─────────────────────────────
-- The backend streams one PingUpdate per server, then a final one with
-- done = true, so the panel can fill latency badges live instead of waiting.
local pingsById = {}
local pingRunning, pingAlive, pingTotal, pingBest = false, 0, 0, -1

local function publishPings()
  local byId = {}
  for id, ms in pairs(pingsById) do byId[id] = ms end
  noctalia.state.set("pings", {
    running = pingRunning, byId = byId,
    alive = pingAlive, total = pingTotal, best = pingBest,
  })
end

-- Mirror the ping-related plugin settings into the backend, which owns the
-- actual probe (it cannot read plugin.toml itself). Keys that are unset are
-- simply omitted by the JSON encoder, so the backend keeps its own value.
local function pushPingSettings()
  if not ready then return end
  rpc("UpdateSettings", { {
    pingMethod            = noctalia.getConfig("ping_method"),
    pingUrl               = noctalia.getConfig("ping_url"),
    pingTimeoutMs         = noctalia.getConfig("ping_timeout_ms"),
    pingCount             = noctalia.getConfig("ping_count"),
    pingConcurrency       = noctalia.getConfig("ping_concurrency"),
    healthCheckIntervalSec = noctalia.getConfig("health_interval"),
    autoFailover          = noctalia.getConfig("auto_failover"),
  } })
end

-- GetLogs returns preformatted lines ("<iso> [level] message"), while state
-- "logs" holds { level, message }. Split them so the panel can colour by level.
local function parseLogLine(line)
  local lvl, msg = tostring(line):match("^%S+%s+%[(%w+)%]%s+(.*)$")
  if not lvl then return { level = "info", message = tostring(line) } end
  return { level = lvl, message = msg }
end

-- Only the SPAWN path sees LogMessage events on stdout. When we attach to a
-- backend that outlived a previous shell there is no event stream at all, so
-- the logs view stayed empty; poll the backend's own ring buffer instead.
local function refreshLogs()
  rpc("GetLogs", {}, function(list)
    if type(list) ~= "table" then return end
    local logs = {}
    for _, line in ipairs(list) do logs[#logs + 1] = parseLogLine(line) end
    noctalia.state.set("logs", logs)
  end)
end

local function refreshLists()
  refreshServers(); refreshRules(); refreshSubs(); refreshPresets(); refreshKill(); refreshSettings(); refreshLogs()
end

-- auto-connect the active server once, if enabled and currently idle
local function maybeAutoStart()
  if not AUTO or autoStarted then return end
  autoStarted = true
  rpc("GetStatus", {}, function(st)
    if st and not st.running and st.activeServerId and st.activeServerId ~= "" then
      rpc("StartProxy", { st.activeServerId, st.mode or "rules", st.proxyMode or "system" })
    end
  end)
end

-- ── fail-open: never leave a dead proxy behind ──────────────────
-- Share the backend's ownership checks; never disable a foreign manual proxy.
local function resetSystemProxy(done)
  local py = PY
  if py:sub(1, 1) == "~" then py = noctalia.expandPath(py) end
  local settings = noctalia.state.get("settings") or {}
  local cmd = shellQuote(py) .. " " .. shellQuote(PROJDIR .. "/backend/service/proxy_guard.py")
  for _, port in ipairs({ settings.transportPort or 11080, settings.rulesPort or 11081, settings.globalPort or 11082 }) do
    cmd = cmd .. " " .. tostring(tonumber(port) or 0)
  end
  local started = noctalia.runAsync(cmd, function(res)
    if done then done(res) end
  end, 5000)
  if not started and done then done(nil) end
end

local function backendGone()
  if resetting then return end
  backendGeneration = backendGeneration + 1
  ready, spawning, polling = false, false, false
  backendPid = nil
  local st = noctalia.state.get("status") or {}
  st.running, st.pids = false, {}
  noctalia.state.set("status", st)
  noctalia.state.set("backend", { ready = false, owns = ownsBackend })
  resetting = true
  resetSystemProxy(function()
    resetting = false
    nextSpawnAt = os.time() + 1
    spawnBackoff = 2
  end)
end

-- ── backend stdout event consumer ───────────────────────────────
local function onEvent(line)
  local ev = noctalia.json.decode(line)
  if type(ev) ~= "table" or ev.event == nil then return end
  local e = ev.event
  if e == "StatusChanged" then
    noctalia.state.set("status", ev.data or {})
  elseif e == "TrafficUpdate" then
    noctalia.state.set("traffic", ev.data or {})
  elseif e == "ServerListChanged" then
    refreshServers()
  elseif e == "LogMessage" then
    local logs = noctalia.state.get("logs") or {}
    table.insert(logs, ev.data or {})
    while #logs > 200 do table.remove(logs, 1) end
    noctalia.state.set("logs", logs)
  elseif e == "PingUpdate" then
    local d = ev.data or {}
    if d.running then
      pingsById = {}
      pingRunning = true
      pingAlive, pingTotal, pingBest = 0, tonumber(d.total) or 0, -1
    elseif d.done then
      pingRunning = false
      pingAlive = tonumber(d.alive) or 0
      pingTotal = tonumber(d.total) or pingTotal
      pingBest  = tonumber(d.best) or -1
    elseif d.id then
      pingsById[d.id] = tonumber(d.latency_ms) or -1
    end
    publishPings()
  elseif e == "Notice" then
    local d = ev.data or {}
    if d.level == "error" then
      noctalia.notifyError(d.title or "Ruh VPN", d.body or "")
    else
      noctalia.notify(d.title or "Ruh VPN", d.body or "")
    end
  elseif e == "ready" then
    ready = true
    spawning = false
    spawnBackoff = 2
    nextSpawnAt = 0
    local pidfile = noctalia.readFile(PIDFILE)
    backendPid = pidfile and tonumber(pidfile:match("^(%d+)%s")) or nil
    readToken() -- written before "ready" is emitted, so it is there by now
    noctalia.state.set("backend", { ready = true, owns = ownsBackend })
    refreshLists()
    pushPingSettings()
    maybeAutoStart()
  elseif e == "error" then
    ready, spawning, ownsBackend = false, false, false
    noctalia.state.set("backend", { ready = false, error = (ev.data and ev.data.message) or "error" })
  elseif e == "exit" then
    if ownsBackend then backendGone() end
  end
end

-- ── spawn vs attach ─────────────────────────────────────────────
-- The backend needs third-party Python packages the plugin may not install
-- itself (community rules forbid fetching and running code automatically).
-- Probe the configured interpreter first, so a missing package surfaces as a
-- readable panel message instead of a stack trace in the event stream.
local function publishSpawnError(message)
  spawning = false
  noctalia.state.set("backend", { ready = false, error = message })
  if message ~= lastSpawnError then
    lastSpawnError = message
    noctalia.notifyError("Ruh VPN", message)
  end
end

local function doSpawn(py)
  backendGeneration = backendGeneration + 1
  local generation = backendGeneration
  ownsBackend = true
  local cmd = "cd " .. shellQuote(PROJDIR)
             .. " && RUH_VPN_CONTROL_PORT=" .. tostring(PORT)
             .. " RUH_VPN_GEOIP=" .. (GEOIP and "1" or "0")
             .. " RUH_VPN_DATA_DIR=" .. shellQuote(DATA_DIR)
             .. " RUH_VPN_RUNTIME_DIR=" .. shellQuote(RUNTIME_DIR)
             .. " exec " .. shellQuote(py) .. " -m backend.app"
  if not noctalia.runStream(cmd, function(line)
    if generation == backendGeneration then onEvent(line) end
  end) then
    ownsBackend = false
    publishSpawnError("Could not launch the VPN backend")
  end
end

local function spawnBackend()
  spawning = true
  spawnStartedAt = os.time()
  local py = PY
  if py:sub(1, 1) == "~" then py = noctalia.expandPath(py) end
  local probe = "import importlib.util,sys;"
    .. "missing=[m for m in ('pydantic','aiofiles','aiohttp','aiohttp_socks') if importlib.util.find_spec(m) is None];"
    .. "print(','.join(missing));"
    .. "sys.exit(1 if missing else 0)"
  noctalia.runAsync(shellQuote(py) .. " -c " .. shellQuote(probe), function(res)
    if res.exitCode == 0 then
      lastSpawnError = nil
      doSpawn(py)
    elseif res.exitCode == 1 and res.stdout:match("%S") then
      local missing = res.stdout:match("%S+"):gsub(",", ", ")
      publishSpawnError("Python packages missing for " .. py .. ": " .. missing
        .. ". Install them and set backend_python (see README).")
    else
      publishSpawnError("Cannot run " .. py
        .. " (exit " .. tostring(res.exitCode) .. "). Check the backend_python setting.")
    end
  end, 30000)
end

local function attachOrSpawn()
  if spawning or probing or resetting then return end
  probing = true
  local generation = backendGeneration
  noctalia.http({ url = BASE .. "/healthz" }, function(resp)
    probing = false
    if generation ~= backendGeneration or ready then return end
    local d = resp and resp.ok and noctalia.json.decode(resp.body) or nil
    if type(d) == "table" and d.ok then
      if d.ready == false then
        -- A bound socket is not readiness; don't race bootstrap or spawn twice.
        nextSpawnAt = os.time() + 1
        spawnBackoff = 2
        return
      end
      -- Attach: a backend outlived a previous shell, and its proxy with it.
      ownsBackend = false
      ready = true
      backendPid = nil
      backendGeneration = backendGeneration + 1
      spawnBackoff = 2
      nextSpawnAt = 0
      readToken() -- the running backend published its token at startup
      noctalia.state.set("backend", { ready = true, owns = false })
      refreshLists()
      maybeAutoStart()
    else
      resetting = true
      resetSystemProxy(function()
        resetting = false
        if generation == backendGeneration and not ready then spawnBackend() end
      end)
    end
  end)
end

attachOrSpawn()

-- ── periodic polling ────────────────────────────────────────────
function update()
  if not ready then
    -- runStream delivers stdout lines only, never a process-exit event, so a
    -- backend that dies during bootstrap would leave `spawning` stuck forever
    -- and block every respawn. Time it out.
    if spawning and os.time() - spawnStartedAt > 45 then spawning = false end
    -- Retry with exponential backoff instead of staying dead until the shell
    -- is restarted.
    if not spawning and not probing and not resetting and os.time() >= nextSpawnAt then
      nextSpawnAt = os.time() + spawnBackoff
      spawnBackoff = math.min(spawnBackoff * 2, 30)
      attachOrSpawn()
    end
    return
  end
  if polling then return end
  polling = true
  local generation = backendGeneration
  -- Confirm liveness separately: an RPC error must not disable a healthy VPN.
  rpc("GetStatus", {}, function(st, err)
    if generation ~= backendGeneration then return end
    if err then
      local started = noctalia.runAsync(
        "curl --noproxy '*' -fsS -m 2 " .. shellQuote(BASE .. "/healthz"),
        function(res)
          if generation ~= backendGeneration then return end
          polling = false
          local d = res and res.exitCode == 0 and noctalia.json.decode(res.stdout or "") or nil
          if type(d) == "table" and d.ok then
            readToken() -- a surviving/restarted backend may have rotated its token
            if d.ready == false then
              ready = false
              nextSpawnAt = os.time() + 1
            end
            return
          end
          backendGone()
        end, 5000)
      if not started then polling = false end
      return
    end
    polling = false
    if st ~= nil then noctalia.state.set("status", st) end
  end)
  rpc("GetHealth", {}, pub("health"))
  local st = noctalia.state.get("status")
  if st and st.running then
    rpc("GetTrafficStats", {}, pub("traffic"))
  end
  -- Attached: no stdout stream to feed logs, so keep pulling the ring buffer.
  -- When we own the backend, LogMessage events already deliver them live.
  if not ownsBackend then refreshLogs() end
end

-- ── UI command channel ──────────────────────────────────────────
noctalia.state.watch("cmd", function(c)
  if type(c) ~= "table" or c.nonce == nil or c.nonce == lastNonce then return end
  lastNonce = c.nonce
  local method = c.method
  rpc(method, c.args or {}, function(result, err)
    noctalia.state.set("cmd_result", { nonce = c.nonce, method = method, result = result, error = err })
    if err then noctalia.notifyError("VPN", tostring(err)) end
    if method == "RunSpeedTest" and result then noctalia.state.set("speedtest", result) end
    if method == "CheckDnsLeak" and result then noctalia.state.set("dnsleak", result) end
    if method == "ParseShareLink" and not err then refreshServers() end
    -- refresh affected lists after mutations
    if method == "AddServer" or method == "UpdateServer" or method == "RemoveServer" or method == "SwitchServer" then
      refreshServers()
    elseif method == "UpdateSettings" and result then
      noctalia.state.set("settings", result)
    elseif method == "PingAll" or method == "ConnectFastest" then
      -- progress and completion arrive as PingUpdate / Notice events
    elseif method == "AddRoutingRule" or method == "RemoveRoutingRule" then
      refreshRules()
    elseif method == "TogglePreset" then
      refreshPresets()
    elseif method == "SetKillSwitch" then
      refreshKill()
    elseif method == "AddSubscription" or method == "RemoveSubscription" or method == "UpdateSubscription" then
      refreshSubs(); refreshServers()
    end
  end)
end)

-- ── settings changes ────────────────────────────────────────────
-- The interesting case: the user just pointed backend_python at an
-- interpreter that has the packages. Retry the spawn without a reload.
function onConfigChanged()
  PY    = noctalia.getConfig("backend_python") or "python3"
  AUTO  = noctalia.getConfig("auto_start") == true
  GEOIP = noctalia.getConfig("geoip_country") ~= false
  if not ready then attachOrSpawn() end
  pushPingSettings()
end

-- ── IPC / keybind entry ─────────────────────────────────────────
-- Drive the VPN from outside the panel, e.g.
--   noctalia msg plugin vlad-dev/ruh-vpn:vpn_service all connect-fastest
--   noctalia msg plugin vlad-dev/ruh-vpn:vpn_service all ping-all
function onIpc(event, payload)
  local e = tostring(event or ""):lower()
  local st = noctalia.state.get("status") or {}
  if e == "connect-fastest" or e == "connect_fastest" then
    rpc("ConnectFastest", { st.mode or "rules", st.proxyMode or "system" })
  elseif e == "ping-all" or e == "ping_all" then
    rpc("PingAll", {})
  elseif e == "toggle" then
    if st.running then
      rpc("StopProxy", {})
    elseif st.activeServerId and st.activeServerId ~= "" then
      rpc("StartProxy", { st.activeServerId, st.mode or "rules", st.proxyMode or "system" })
    end
  end
end

-- ── teardown: only kill the backend WE spawned ──────────────────
function onExit(sig)
  if ownsBackend and backendPid then
    -- SIGTERM lets the backend tear down its proxy processes cleanly.
    -- The pidfile holds "<pid> <port>". Read and validate the first field
    -- before signalling it so the port can never be mistaken for a PID.
    local cmd = "if read pid rest < " .. shellQuote(PIDFILE)
                .. "; then if [ \"$pid\" = " .. tostring(backendPid)
                .. " ]; then kill \"$pid\" 2>/dev/null; fi; fi"
    noctalia.runAsync(cmd)
  end
end

noctalia.setUpdateInterval(1000)
