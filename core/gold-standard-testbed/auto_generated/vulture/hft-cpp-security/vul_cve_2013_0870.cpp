// Vulnerable: VUL-CVE-2013-0870
skip_bits_long(&gb, 6*8); /* "theora" */

        if (type == 0) {
            if (s->avctx->active_thread_type&FF_THREAD_FRAME) {
...

        if (type == 0) {
            if (s->avctx->active_thread_type&FF_THREAD_FRAME) {
                av_log(avctx, AV_LOG_ERROR, "midstream reconfiguration with multithreading is unsupported, try -threads 1\n");
                return AVERROR_PATCHWELCOME;
            }
            vp3_decode_end(avctx);
            ret = theora_decode_header(avctx, &gb);
