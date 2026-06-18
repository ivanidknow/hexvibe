// Vulnerable: VUL-CVE-2017-9227
else {
  UChar *q = p + reg->dmin;
  while (p < q) p += enclen(reg->enc, p);
}
