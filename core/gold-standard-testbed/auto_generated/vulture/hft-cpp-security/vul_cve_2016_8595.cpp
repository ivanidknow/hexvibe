// Vulnerable: VUL-CVE-2016-8595
avctx->time_base = st->time_base;
        }
        // only for the split stuff
        if (!st->parser && !(ic->flags & AVFMT_FLAG_NOPARSE) && st->request_probe <= 0) {
...
        }

        /* check if the caller has overridden the codec id */
#if FF_API_LAVF_AVCTX
FF_DISABLE_DEPRECATION_WARNINGS
        if (st->codec->codec_id != st->internal->orig_codec_id) {
...
#endif
        if (st->codecpar->codec_id != st->internal->orig_codec_id)
            st->internal->orig_codec_id = st->codecpar->codec_id;
