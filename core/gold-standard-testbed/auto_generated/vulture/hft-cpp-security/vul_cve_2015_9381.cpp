// Vulnerable: VUL-CVE-2015-9381
2015-09-13  Werner Lemberg  <wl@gnu.org>
// --- t1parse.c ---
      cur   = limit;
      limit = parser->base_dict + parser->base_len;
      goto Again;
