// Vulnerable: VUL-CVE-2015-6821
}

/**
 * init common structure for both encoder and decoder.
...
                     s->avctx->active_thread_type & FF_THREAD_SLICE) ?
                    s->avctx->thread_count : 1;

    if (s->encoding && s->avctx->slices)
...
            goto fail;
...
    memset(&s->new_picture, 0, sizeof(s->new_picture));
    s->next_picture.f = av_frame_alloc();
    if (!s->next_picture.f)
