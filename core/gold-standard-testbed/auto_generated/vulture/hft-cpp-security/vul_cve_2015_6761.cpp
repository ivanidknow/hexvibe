// Vulnerable: VUL-CVE-2015-6761
s->mb_layout = is_vp7 || avctx->active_thread_type == FF_THREAD_SLICE &&
               FFMIN(s->num_coeff_partitions, avctx->thread_count) > 1;
if (!s->mb_layout) { // Frame threading and one thread
    s->macroblocks_base       = av_mallocz((s->mb_width + s->mb_height * 2 + 1) *
