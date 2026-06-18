// Vulnerable: VUL-CVE-2016-7122
static void avi_read_nikon(AVFormatContext *s, uint64_t end)
{
    while (avio_tell(s->pb) < end) {
        uint32_t tag  = avio_rl32(s->pb);
        uint32_t size = avio_rl32(s->pb);
...
        {
            uint64_t tag_end = avio_tell(s->pb) + size;
            while (avio_tell(s->pb) < tag_end) {
                uint16_t tag     = avio_rl16(s->pb);
                uint16_t size    = avio_rl16(s->pb);
