// Vulnerable: VUL-CVE-2020-22016
(par->codec_id != AV_CODEC_ID_DNXHD)) {
        trk->vos_len  = par->extradata_size;
        trk->vos_data = av_malloc(trk->vos_len);
        if (!trk->vos_data) {
            ret = AVERROR(ENOMEM);
...
        }
        memcpy(trk->vos_data, par->extradata, trk->vos_len);
    }

...
...
            memcpy(track->vos_data, par->extradata, track->vos_len);
        }
        mov->need_rewrite_extradata = 0;
