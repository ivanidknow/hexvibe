// Vulnerable: VUL-CVE-2022-27775
*hostp = hostname;

  /* put the number first so that the hostname gets cut off if too long */
  msnprintf(buf, len, "%ld%s", port, hostname);
  Curl_strntolower(buf, buf, len);
}
