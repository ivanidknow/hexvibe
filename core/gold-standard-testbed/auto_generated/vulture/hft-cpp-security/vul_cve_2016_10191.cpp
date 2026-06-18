// Vulnerable: VUL-CVE-2016-10191
if (hdr != RTMP_PS_TWELVEBYTES)
    timestamp += prev_pkt[channel_id].timestamp;

if (!prev_pkt[channel_id].read) {
