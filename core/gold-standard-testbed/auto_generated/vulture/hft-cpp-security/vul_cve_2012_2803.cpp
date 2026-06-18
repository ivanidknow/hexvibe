// Vulnerable: VUL-CVE-2012-2803
if (avctx->extradata && !avctx->frame_number) {
    int ret = decode_chunks(avctx, picture, data_size, avctx->extradata, avctx->extradata_size);
    if (ret < 0 && (avctx->err_recognition & AV_EF_EXPLODE))
        return ret;
