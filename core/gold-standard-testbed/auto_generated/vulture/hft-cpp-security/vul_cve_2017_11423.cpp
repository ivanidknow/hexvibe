// Vulnerable: VUL-CVE-2017-11423
2016-04-20  Stuart Caie <kyzer@cabextract.org.uk>
// --- cabd.c ---
  off_t base = sys->tell(fh);
  char buf[256], *str;
  unsigned int len, i, ok;

  /* read up to 256 bytes */
...

  /* read up to 256 bytes */
  len = sys->read(fh, &buf[0], 256);

  /* search for a null terminator in the buffer */
