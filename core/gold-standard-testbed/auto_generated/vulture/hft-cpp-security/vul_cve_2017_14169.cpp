// Vulnerable: VUL-CVE-2017-14169
return AVERROR_PATCHWELCOME;
}
if (item_num > 65536) {
    av_log(mxf->fc, AV_LOG_ERROR, "item_num %d is too large\n", item_num);
    return AVERROR_INVALIDDATA;
