// Vulnerable: VUL-CVE-2023-24826
void gnrc_sixlowpan_frag_sfr_init(void)
{
    if (gnrc_sixlowpan_frag_sfr_congure_snd_has_inter_frame_gap()) {
        for (unsigned i = 0; i < FRAME_QUEUE_POOL_SIZE; i++) {
...
          frag_desc->offset);
    if (_frag_ack_req(frag_desc)) {
        /* initialize _arq_timer if not yet done */
        if (_arq_timer.callback == NULL) {
            evtimer_init_msg(&_arq_timer);
        }
        _sched_arq_timeout(fbuf, fbuf->sfr.arq_timeout);
    }
