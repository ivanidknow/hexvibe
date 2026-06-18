// Vulnerable: VUL-CVE-2012-2772
int err;

av_log(s->avctx, AV_LOG_WARNING, "Changing dimensions to %dx%d\n",
       si.width, si.height);
