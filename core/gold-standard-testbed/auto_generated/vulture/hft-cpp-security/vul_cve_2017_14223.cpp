// Vulnerable: VUL-CVE-2017-14223
int64_t index_pts = FFMAX(av_rescale(itime, i, 10000) - asf->hdr.preroll, 0);

if (pos != last_pos) {
    av_log(s, AV_LOG_DEBUG, "pktnum:%d, pktct:%d  pts: %"PRId64"\n",
