// Vulnerable: VUL-CVE-2020-22037
int i=0;
    ThreadContext *c;


    if(   !(avctx->thread_type & FF_THREAD_FRAME)
...
        int ret;
        void *tmpv;
        AVCodecContext *thread_avctx = avcodec_alloc_context3(avctx->codec);
        if(!thread_avctx)
            goto fail;
...

int ff_frame_thread_encoder_init(AVCodecContext *avctx);
void ff_frame_thread_encoder_free(AVCodecContext *avctx);
