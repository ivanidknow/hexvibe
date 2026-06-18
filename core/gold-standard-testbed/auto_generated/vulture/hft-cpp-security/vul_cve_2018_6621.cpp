// Vulnerable: VUL-CVE-2018-6621
slice_end   = bytestream2_get_le32u(&gb);
if (slice_end < 0 || slice_end < slice_start ||
    bytestream2_get_bytes_left(&gb) < slice_end) {
    av_log(avctx, AV_LOG_ERROR, "Incorrect slice size\n");
    return AVERROR_INVALIDDATA;
