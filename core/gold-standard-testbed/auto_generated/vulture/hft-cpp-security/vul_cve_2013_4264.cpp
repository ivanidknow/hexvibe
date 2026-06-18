// Vulnerable: VUL-CVE-2013-4264
zsize = (src[0] << 8) | src[1]; src += 2;

    if (src_end - src < zsize)
        return AVERROR_INVALIDDATA;

...
        for (j = 0; j < (FFALIGN(width, 16) >> 4); j++) {
            if (!bits) {
                bitbuf = *src++;
                bits   = 8;
