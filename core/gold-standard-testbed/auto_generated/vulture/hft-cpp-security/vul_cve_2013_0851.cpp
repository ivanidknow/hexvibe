// Vulnerable: VUL-CVE-2013-0851
int inter;

if (buf_size < 17) {
    av_log(avctx, AV_LOG_ERROR, "Input buffer too small\n");
    *data_size = 0;
