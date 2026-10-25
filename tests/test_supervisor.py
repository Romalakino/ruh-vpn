import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("luau") is None, reason="Luau CLI not installed")
def test_supervisor_serializes_cleanup_and_ignores_old_backend_events(tmp_path):
    source = (Path(__file__).parent.parent / "service.luau").read_text()
    stub = r'''
local now = 0
local os = { time = function() return now end }
local state = { settings = { transportPort = 12080, rulesPort = 12081, globalPort = 12082 } }
local http, async, streams = {}, {}, {}
local noctalia = {
  getConfig = function() return nil end,
  pluginDir = function() return "/plugin" end,
  pluginDataDir = function() return "/data" end,
  expandPath = function(path) return path end,
  readFile = function(path) return path:find(".pid", 1, true) and "1234 11090\n" or "token" end,
  state = {
    get = function(key) return state[key] end,
    set = function(key, value) state[key] = value end,
    watch = function() end,
  },
  json = { encode = function(value) return value end, decode = function(value) return value end },
  http = function(request, callback) table.insert(http, { request, callback }); return true end,
  runAsync = function(command, callback) table.insert(async, { command, callback }); return true end,
  runStream = function(command, callback) table.insert(streams, { command, callback }); return true end,
  notify = function() end,
  notifyError = function() end,
  setUpdateInterval = function(ms) assert(ms == 1000) end,
}
local function finishHttp(method, response)
  for i, entry in ipairs(http) do
    local request = entry[1]
    if (request.body and request.body.method == method) or request.url:find(method, 1, true) then
      table.remove(http, i)
      entry[2](response)
      return
    end
  end
  error("missing HTTP request: " .. method)
end
local function finishAsync(response)
  local entry = table.remove(async, 1)
  assert(entry, "missing async command")
  entry[2](response)
  return entry[1]
end
'''
    checks = r'''
assert(#http == 1)
update(); update()
assert(#http == 1, "concurrent probes must not spawn duplicates")
finishHttp("/healthz", { ok = true, body = { ok = true, ready = false } })
assert(#streams == 0 and #async == 0, "bootstrap is not readiness")
now = 2; update()
finishHttp("/healthz", { ok = false })
assert(#streams == 0 and #async == 1, "cleanup must precede respawn")
local command = finishAsync({ exitCode = 0 })
assert(command:find("proxy_guard.py", 1, true) and command:find("12081", 1, true))
finishAsync({ exitCode = 0 })
assert(#streams == 1)
local old = streams[1][2]
old({ event = "ready" })
assert(state.backend.ready)
now = 3; update()
finishHttp("GetStatus", { ok = false, status = 401 })
finishAsync({ exitCode = 0, stdout = { ok = true, ready = true } })
assert(state.backend.ready and #async == 0, "a live backend must keep its proxy")
now = 4; update()
finishHttp("GetStatus", { ok = false, status = 0 })
finishAsync({ exitCode = 7, stdout = "" })
assert(not state.backend.ready and not state.status.running)
old({ event = "ready" })
assert(not state.backend.ready, "late events from a dead backend must be ignored")
now = 5; update()
assert(#streams == 1, "must not respawn while proxy cleanup is pending")
finishAsync({ exitCode = 0 })
now = 6; update()
finishHttp("/healthz", { ok = false })
finishAsync({ exitCode = 0 }); finishAsync({ exitCode = 0 })
assert(#streams == 2)
streams[2][2]({ event = "ready" })
assert(state.backend.ready)
old({ event = "exit" })
assert(state.backend.ready, "an old exit must not tear down the new backend")
print("supervisor OK")
'''
    script = tmp_path / "supervisor.luau"
    script.write_text(stub + source + checks)
    result = subprocess.run(["luau", str(script)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "supervisor OK" in result.stdout
