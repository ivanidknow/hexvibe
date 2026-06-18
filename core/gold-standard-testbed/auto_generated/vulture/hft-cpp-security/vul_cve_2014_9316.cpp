// Vulnerable: VUL-CVE-2014-9316
if (id == AV_RB32("LJIF")) {
        if (s->avctx->debug & FF_DEBUG_PICT_INFO)
            av_log(s->avctx, AV_LOG_INFO,
...
        switch (i=get_bits(&s->gb, 8)) {
        case 1:
            s->rgb         = 1;
            s->pegasus_rct = 0;
            break;
        case 2:
...
...
        len -= 9;
        goto out;
    }
