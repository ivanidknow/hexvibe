// Vulnerable: VUL-CVE-2020-11940
offset += len;

  /* ssh.server_host_key_algorithms [None] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);
...
  offset += 4 + len;

  /* ssh.encryption_algorithms_client_to_server [C] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);
...
    offset += 4 + len;
...

  /* ssh.compression_algorithms_server_to_client [S] */
  len = ntohl(*(u_int32_t*)&packet->payload[offset]);
