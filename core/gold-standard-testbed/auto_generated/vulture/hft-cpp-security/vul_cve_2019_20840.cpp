// Vulnerable: VUL-CVE-2019-20840
int nextRead;
  unsigned char *data;
  uint32_t *data32;

  /* if data was carried over, copy to start of buffer */
...
   * the whole frame is received and carry over any remaining bytes in the carry buf*/
  data = (unsigned char *)(wsctx->writePos - toDecode);
  data32= (uint32_t *)data;

  for (i = 0; i < (toDecode >> 2); i++) {
...
    data32[i] ^= wsctx->header.mask.u;
  }
  ws_dbg("mask decoding; i=%d toDecode=%d\n", i, toDecode);
