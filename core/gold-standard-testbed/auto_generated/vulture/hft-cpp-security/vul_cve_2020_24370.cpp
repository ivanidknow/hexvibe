// Vulnerable: VUL-CVE-2020-24370
if (clLvalue(s2v(ci->func))->p->is_vararg) {
    int nextra = ci->u.l.nextraargs;
    if (n <= nextra) {
      *pos = ci->func - nextra + (n - 1);
      return "(vararg)";  /* generic name for any vararg */
    }
...
  if (isLua(ci)) {
    if (n < 0)  /* access to vararg values? */
      return findvararg(ci, -n, pos);
    else
      name = luaF_getlocalname(ci_func(ci)->p, n, currentpc(ci));
