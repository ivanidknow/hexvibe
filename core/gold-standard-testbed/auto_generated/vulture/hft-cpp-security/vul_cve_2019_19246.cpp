// Vulnerable: VUL-CVE-2019-19246
q = lowbuf;
while (lowlen > 0) {
  if (*t++ != *q++) return 0;
  lowlen--;
