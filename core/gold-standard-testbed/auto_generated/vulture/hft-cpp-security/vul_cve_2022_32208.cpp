// Vulnerable: VUL-CVE-2022-32208
enc.length = len;
  maj = gss_unwrap(&min, *context, &enc, &dec, NULL, NULL);
  if(maj != GSS_S_COMPLETE) {
    if(len >= 4)
      strcpy(buf, "599 ");
    return -1;
  }

  memcpy(buf, dec.value, dec.length);
...
  int len;
...
                                 conn->data_prot, conn);
  buf->index = 0;
  return CURLE_OK;
