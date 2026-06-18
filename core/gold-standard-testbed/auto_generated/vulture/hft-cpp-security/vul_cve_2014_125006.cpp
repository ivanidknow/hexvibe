// Vulnerable: VUL-CVE-2014-125006
{
    AVFrame *src = &srcp->f;
    int i;
    int ret = av_frame_ref(dst, src);
...
        return 0;

    for (i = 0; i < 3; i++) {
        int hshift = (i > 0) ? h->chroma_x_shift : 0;
        int vshift = (i > 0) ? h->chroma_y_shift : 0;
        int off    = ((srcp->crop_left >> hshift) << h->pixel_shift) +
                      (srcp->crop_top  >> vshift) * dst->linesize[i];
