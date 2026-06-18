// Vulnerable: VUL-CVE-2023-33974
DEBUG("6lo sfr: ARQ timeout for datagram %u\n", fbuf->tag);
    fbuf->sfr.arq_timeout_event.msg.content.ptr = NULL;
    if (IS_ACTIVE(CONFIG_GNRC_SIXLOWPAN_SFR_MOCK_ARQ_TIMER)) {
        /* mock-up to emulate time having passed beyond (1us) the ARQ timeout */
...
    evtimer_del((evtimer_t *)(&_arq_timer),
                &fbuf->sfr.arq_timeout_event.event);
    fbuf->sfr.arq_timeout_event.event.next = NULL;
    if (gnrc_sixlowpan_frag_sfr_congure_snd_has_inter_frame_gap()) {
        for (clist_node_t *node = clist_lpop(&_frame_queue);
...
...
            fbuf->sfr.arq_timeout_event.msg.content.ptr = NULL;
            if ((unaligned_get_u32(hdr->bitmap) == _null_bitmap.u32)) {
                /* ACK indicates the reassembling endpoint canceled reassembly
