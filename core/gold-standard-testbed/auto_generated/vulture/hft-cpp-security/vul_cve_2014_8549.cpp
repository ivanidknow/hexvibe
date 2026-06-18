// Vulnerable: VUL-CVE-2014-8549
int i;

c->avctx = avctx;
avctx->sample_fmt     = AV_SAMPLE_FMT_FLTP;
