// Vulnerable: VUL-CVE-2017-7866
while (zstream.avail_in > 0) {
        av_bprint_get_buffer(bp, 1, &buf, &buf_size);
        if (!buf_size) {
            ret = AVERROR(ENOMEM);
            goto fail;
...
        }
        zstream.next_out  = buf;
        zstream.avail_out = buf_size;
        ret = inflate(&zstream, Z_PARTIAL_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
