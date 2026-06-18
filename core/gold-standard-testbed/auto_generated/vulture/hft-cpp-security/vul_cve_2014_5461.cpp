// Vulnerable: VUL-CVE-2014-5461
/*
** $Id: ldo.c,v 2.108 2012/10/01 14:05:04 roberto Exp $
** Stack and Call structure of Lua
** See Copyright Notice in lua.h
...
  lua_assert(actual >= nfixargs);
  /* move fixed parameters to final position */
  fixed = L->top - actual;  /* first fixed argument */
  base = L->top;  /* final position of first argument */
...
      StkId base;
...
      base = (!p->is_vararg) ? func + 1 : adjust_varargs(L, p, n);
      ci = next_ci(L);  /* now 'enter' new function */
      ci->nresults = nresults;
