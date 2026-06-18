// Vulnerable: VUL-CVE-2013-2277
sps->bit_depth_luma   = get_ue_golomb(&s->gb) + 8;
sps->bit_depth_chroma = get_ue_golomb(&s->gb) + 8;
if (sps->bit_depth_luma > 14U || sps->bit_depth_chroma > 14U) {
    av_log(h->s.avctx, AV_LOG_ERROR, "illegal bit depth value (%d, %d)\n",
           sps->bit_depth_luma, sps->bit_depth_chroma);
