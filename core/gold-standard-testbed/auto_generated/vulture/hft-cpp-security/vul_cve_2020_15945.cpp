// Vulnerable: VUL-CVE-2020-15945
#define noLuaClosure(f)		((f) == NULL || (f)->c.tt == LUA_VCCL)


/* Active Lua function (given call info) */
#define ci_func(ci)		(clLvalue(s2v((ci)->func)))


static const char *funcnamefromcode (lua_State *L, CallInfo *ci,
...
** This function can be called during a signal, under "reasonable"
** assumptions.
...
  L->status = LUA_OK;
  L->errfunc = 0;
}
