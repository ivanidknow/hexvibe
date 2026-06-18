// Vulnerable: VUL-CVE-2020-22284
zep->len = (u8_t)p->tot_len;

  err = pbuf_take_at(q, p->payload, p->tot_len, sizeof(struct zep_hdr));
  if (err == ERR_OK) {
#if ZEPIF_LOOPBACK
