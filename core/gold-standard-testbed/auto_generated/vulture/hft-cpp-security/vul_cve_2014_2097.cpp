// Vulnerable: VUL-CVE-2014-2097
}

if (s->ti.bps != avctx->bits_per_raw_sample) {
    avctx->bits_per_raw_sample = s->ti.bps;
    if ((ret = set_bps_params(avctx)) < 0)
        return ret;
}
if (s->ti.sample_rate != avctx->sample_rate) {
    avctx->sample_rate = s->ti.sample_rate;
