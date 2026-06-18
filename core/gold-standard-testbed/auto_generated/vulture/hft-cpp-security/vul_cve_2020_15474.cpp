// Vulnerable: VUL-CVE-2020-15474
u_int len, j;

  // packet is truncated... further inspection is not needed
  if((offset+4+str_len) >= packet->payload_packet_len)
...
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int num_found = 0, i;
  char buffer[64] = { '\0' }, rdnSeqBuf[1024] = { '\0' };
  u_int rdn_len = 0;
