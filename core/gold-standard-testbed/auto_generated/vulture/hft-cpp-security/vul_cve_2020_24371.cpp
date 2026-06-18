// Vulnerable: VUL-CVE-2020-24371
collectgarbage("step", 0)   -- make it a survival
  assert(not T or T.gcage(obj) == "survival")
  setmetatable(obj, {__gc = gcf, x = "ok"})   -- create its metatable
  assert(not T or T.gcage(getmetatable(obj)) == "new")
  obj = nil   -- clear object
...
  obj = nil   -- clear object
  collectgarbage("step", 0)   -- will call obj's finalizer
end
// --- lgc.c ---
/*
...
  /* sweep all elements making them old */
  sweep2old(L, &g->allgc);
  /* everything alive now is old */
