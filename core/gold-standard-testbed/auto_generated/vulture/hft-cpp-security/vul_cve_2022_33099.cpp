// Vulnerable: VUL-CVE-2022-33099
msg = luaO_pushvfstring(L, fmt, argp);  /* format message */
  va_end(argp);
  if (isLua(ci))  /* if Lua function, add source:line information */
    luaG_addinfo(L, msg, ci_func(ci)->p->source, getcurrentline(ci));
  luaG_errormsg(L);
...
  if (isLua(ci))  /* if Lua function, add source:line information */
    luaG_addinfo(L, msg, ci_func(ci)->p->source, getcurrentline(ci));
  luaG_errormsg(L);
}
// --- lvm.c ---
...
    L->top -= n-1;  /* popped 'n' strings and pushed one */
  } while (total > 1);  /* repeat until only 1 result left */
}
