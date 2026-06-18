// Vulnerable: VUL-CVE-2014-8548
} \
total_blocks--; \
if (total_blocks < 0) \
{ \
    av_log(s->avctx, AV_LOG_INFO, "warning: block counter just went negative (this should not happen)\n"); \
