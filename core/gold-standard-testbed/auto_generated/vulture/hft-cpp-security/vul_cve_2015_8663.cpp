// Vulnerable: VUL-CVE-2015-8663
{
    int ret = get_buffer_internal(avctx, frame, flags);
    if (ret < 0)
        av_log(avctx, AV_LOG_ERROR, "get_buffer() failed\n");
    return ret;
...
    if (ret < 0)
        av_log(avctx, AV_LOG_ERROR, "get_buffer() failed\n");
    return ret;
}
