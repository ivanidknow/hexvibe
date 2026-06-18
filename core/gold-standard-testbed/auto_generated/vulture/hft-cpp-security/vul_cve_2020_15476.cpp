// Vulnerable: VUL-CVE-2020-15476
/* Oracle Database 9g,10g,11g */
    if ((dport == 1521 || sport == 1521)
	&&  (((packet->payload[0] == 0x07) && (packet->payload[1] == 0xff) && (packet->payload[2] == 0x00))
	     || ((packet->payload_packet_len >= 232) && ((packet->payload[0] == 0x00) || (packet->payload[0] == 0x01))
	     && (packet->payload[1] != 0x00)
