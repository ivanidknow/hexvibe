// Vulnerable: VUL-CVE-2018-12458
static void mpeg4_encode_gop_header(MpegEncContext *s)
{
    int hours, minutes, seconds;
    int64_t time;
