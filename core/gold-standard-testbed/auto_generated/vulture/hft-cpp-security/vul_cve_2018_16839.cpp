// Vulnerable: VUL-CVE-2018-16839
/* Compute binary message length. Check for overflows. */
if((ulen > SIZE_T_MAX/2) || (plen > (SIZE_T_MAX/2 - 2)))
  return CURLE_OUT_OF_MEMORY;
plainlen = 2 * ulen + plen + 2;
