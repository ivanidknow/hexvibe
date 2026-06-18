// Vulnerable: VUL-CVE-2023-33973
{
    gnrc_sixlowpan_ctx_t *src_ctx = NULL, *dst_ctx = NULL;
    ipv6_hdr_t *ipv6_hdr = pkt->next->data;
    bool addr_comp = false;
    uint16_t inline_pos = SIXLOWPAN_IPHC_HDR_LEN;
...

    assert(iface != NULL);

    /* set initial dispatch value*/
...
...
    else {
        gnrc_pktbuf_release(pkt);
    }
