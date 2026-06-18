// Vulnerable: VUL-CVE-2021-21410
#define UIP_IPPAYLOAD_BUF_POS(pos)         (&uip_buf[UIP_IPH_LEN + (pos)])
#define UIP_UDP_BUF_POS(pos)               ((struct uip_udp_hdr *)UIP_IPPAYLOAD_BUF_POS(pos))

/** @} */
...
 *
 * \param buf Pointer to the buffer to uncompress the packet into.
 * \param ip_len Equal to 0 if the packet is not a fragment (IP length
 * is then inferred from the L2 length), non 0 if the packet is a 1st
...
 */
...
    uncompress_hdr_iphc(buffer, frag_size);
  } else if(PACKETBUF_6LO_PTR[PACKETBUF_6LO_DISPATCH] == SICSLOWPAN_DISPATCH_IPV6) {
    LOG_DBG("uncompression: IPV6 dispatch\n");
