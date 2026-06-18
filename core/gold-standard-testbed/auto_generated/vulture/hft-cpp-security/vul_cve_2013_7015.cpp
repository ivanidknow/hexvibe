// Vulnerable: VUL-CVE-2013-7015
s->diff_start  = get_bits(&gb, 8);
s->diff_height = get_bits(&gb, 8);
av_log(avctx, AV_LOG_DEBUG,
       "%dx%d diff start %d height %d\n",
