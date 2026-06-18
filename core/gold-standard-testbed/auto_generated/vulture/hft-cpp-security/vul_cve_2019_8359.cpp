// Vulnerable: VUL-CVE-2019-8359
/* These should possibly be taken from upper layers in the future */
  packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, CSMA_LLSEC_SECURITY_LEVEL);
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, CSMA_LLSEC_KEY_ID_MODE);
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, CSMA_LLSEC_KEY_INDEX);
...
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, CSMA_LLSEC_KEY_ID_MODE);
  packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, CSMA_LLSEC_KEY_INDEX);
#endif /* LLSEC802154_ENABLED */

...
  if(csma_security_create_frame() < 0) {
...

#if UIP_BYTE_ORDER == UIP_LITTLE_ENDIAN
#define LLSEC802154_HTONS(n) (n)
