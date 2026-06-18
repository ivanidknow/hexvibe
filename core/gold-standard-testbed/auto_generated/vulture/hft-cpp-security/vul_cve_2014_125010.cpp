// Vulnerable: VUL-CVE-2014-125010
h->slice_alpha_c0_offset += get_se_golomb(&h->gb) << 1;
h->slice_beta_offset     += get_se_golomb(&h->gb) << 1;
if (h->slice_alpha_c0_offset > 104U ||
    h->slice_beta_offset     > 104U) {
    av_log(h->avctx, AV_LOG_ERROR,
           "deblocking filter parameters %d %d out of range\n",
