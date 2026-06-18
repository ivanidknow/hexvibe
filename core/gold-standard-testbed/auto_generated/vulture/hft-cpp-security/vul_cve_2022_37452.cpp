// Vulnerable: VUL-CVE-2022-37452
if (hosts->h_aliases)
    {
    int count = 1;
    uschar **ptr;

...
      uschar **aptr = NULL;
      int ssize = 264;
      int count = 0;
      int old_pool = store_pool;
