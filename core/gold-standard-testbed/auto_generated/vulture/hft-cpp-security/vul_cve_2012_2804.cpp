// Vulnerable: VUL-CVE-2012-2804
static av_cold int allocate_frame_buffers(Indeo3DecodeContext *ctx,
                                          AVCodecContext *avctx)
{
    int p, luma_width, luma_height, chroma_width, chroma_height;
    int luma_pitch, chroma_pitch, luma_size, chroma_size;

...
    int p, luma_width, luma_height, chroma_width, chroma_height;
    int luma_pitch, chroma_pitch, luma_size, chroma_size;

    luma_width  = ctx->width;
...

    return allocate_frame_buffers(ctx, avctx);
}
