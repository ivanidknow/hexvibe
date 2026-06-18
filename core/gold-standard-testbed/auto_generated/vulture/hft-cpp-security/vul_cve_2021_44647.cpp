// Vulnerable: VUL-CVE-2021-44647
-- create a piece of garbage with a finalizer
  setmetatable({}, {__gc = function ()
    local t = debug.getinfo(2)   -- get callee information
    assert(t.namewhat == "metamethod")
    name = t.name
// --- gc.lua ---
  warn("@on"); warn("@store")
  collectgarbage()
  assert(string.find(_WARN, "error in __gc metamethod"))
  assert(string.match(_WARN, "@(.-)@") == "expected"); _WARN = false
  for i = 8, 10 do assert(s[i]) end
...
      luaE_warnerror(L, "__gc metamethod");
      L->top--;  /* pops error object */
    }
