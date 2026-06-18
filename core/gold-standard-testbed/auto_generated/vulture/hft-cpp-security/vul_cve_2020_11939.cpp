// Vulnerable: VUL-CVE-2020-11939
static u_int16_t concat_hash_string(struct ndpi_packet_struct *packet,
				   char *buf, u_int8_t client_hash) {
  u_int16_t offset = 22, buf_out_len = 0;
  if(offset+sizeof(u_int32_t) >= packet->payload_packet_len)
    goto invalid_payload;
...
  /* ssh.server_host_key_algorithms [None] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);
  offset += 4 + len;

...
...
    offset += 4 + len;

  /* ssh.languages_client_to_server [None] */
