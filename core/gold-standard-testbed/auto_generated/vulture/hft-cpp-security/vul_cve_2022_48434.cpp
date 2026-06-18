// Vulnerable: VUL-CVE-2022-48434
* While it is set, ff_thread_en/decode_frame won't return any results.
                                    */
} FrameThreadContext;

...

        if (p->hwaccel_serializing) {
            p->hwaccel_serializing = 0;
            pthread_mutex_unlock(&p->parent->hwaccel_mutex);
...
            pthread_mutex_unlock(&p->parent->hwaccel_mutex);
...
    ff_pthread_free(fctx, thread_ctx_offsets);

    av_freep(&avctx->internal->thread_ctx);
