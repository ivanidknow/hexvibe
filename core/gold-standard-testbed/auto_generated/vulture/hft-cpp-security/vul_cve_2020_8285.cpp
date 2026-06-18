// Vulnerable: VUL-CVE-2020-8285
}

/* This is called recursively */
static CURLcode wc_statemach(struct connectdata *conn)
{
...
  CURLcode result = CURLE_OK;

  switch(wildcard->state) {
  case CURLWC_INIT:
    result = init_wc_data(conn);
...

  return result;
}
