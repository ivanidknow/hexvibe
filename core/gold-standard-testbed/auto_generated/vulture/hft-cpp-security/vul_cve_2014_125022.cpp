// Vulnerable: VUL-CVE-2014-125022
s->max_framesize = 1024; // should hopefully be enough for the first header
tmp_ptr = av_fast_realloc(s->bitstream, &s->allocated_bitstream_size,
                          s->max_framesize);
if (!tmp_ptr) {
    av_log(avctx, AV_LOG_ERROR, "error allocating bitstream buffer\n");
