// Vulnerable: VUL-CVE-2014-125018
if (h->pps.sps_id != h->current_sps_id ||
        h0->sps_buffers[h->pps.sps_id]->new) {
        h0->sps_buffers[h->pps.sps_id]->new = 0;

        h->current_sps_id = h->pps.sps_id;
        h->sps            = *h0->sps_buffers[h->pps.sps_id];

...
    h->er.ref_count = h->ref_count[0];
    h0->au_pps_id = pps_id;

    if (h->avctx->debug & FF_DEBUG_PICT_INFO) {
