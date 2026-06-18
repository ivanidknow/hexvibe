// Vulnerable: VUL-CVE-2013-0867
|| h->cur_chroma_format_idc != h->sps.chroma_format_idc
                 || av_cmp_q(h->sps.sar, s->avctx->sample_aspect_ratio)));


s->mb_width  = h->sps.mb_width;
