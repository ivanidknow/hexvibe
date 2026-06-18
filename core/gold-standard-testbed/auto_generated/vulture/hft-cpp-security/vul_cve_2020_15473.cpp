// Vulnerable: VUL-CVE-2020-15473
int8_t hmac_size;
  int8_t failed = 0;

  if(packet->payload_packet_len >= 40) {
    // skip openvpn TCP transport packet size
    if(packet->tcp != NULL)
...
    // skip openvpn TCP transport packet size
    if(packet->tcp != NULL)
      ovpn_payload += 2;

...
        } else
          failed = 1;
      } else
