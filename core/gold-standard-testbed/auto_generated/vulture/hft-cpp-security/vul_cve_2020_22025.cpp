// Vulnerable: VUL-CVE-2020-22025
memcpy(dst, src, w); dst += dst_linesize; src += src_linesize;
    memcpy(dst, src, w); dst += dst_linesize; src += src_linesize;
    for (j = 2; j < h - 2; j++) {
        dst[0] = src[0];
...
        src += src_linesize;
    }
    memcpy(dst, src, w); dst += dst_linesize; src += src_linesize;
    memcpy(dst, src, w);
}
