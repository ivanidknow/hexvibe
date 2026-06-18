// Vulnerable: VUL-CVE-2021-45985
int nfixparams = p->numparams;
      int i;
      ci->func -= delta;  /* restore 'func' (if vararg) */
      for (i = 0; i < narg1; i++)  /* move down function and arguments */
...
      for (i = 0; i < narg1; i++)  /* move down function and arguments */
        setobjs2s(L, ci->func + i, func + i);
      checkstackGC(L, fsize);
      func = ci->func;  /* moved-down function */
      for (; narg1 <= nfixparams; narg1++)
