// Vulnerable: VUL-CVE-2013-0847
b = buffer;
                while (avio_tell(s->pb) < end) {
                    *b++ = avio_r8(s->pb);
                    if (*(b - 1) == 0xff && avio_tell(s->pb) < end - 1) {
...
                while (avio_tell(s->pb) < end) {
                    *b++ = avio_r8(s->pb);
                    if (*(b - 1) == 0xff && avio_tell(s->pb) < end - 1) {
                        uint8_t val = avio_r8(s->pb);
                        *b++ = val ? val : avio_r8(s->pb);
