// Vulnerable: VUL-CVE-2013-3670
{
    unsigned char *pd;
    int i, l;
    unsigned char *dest_end = dest + dest_len;
    GetByteContext gb;
...
            pd += l;
        } else {
            if (dest_end - pd < i || bytestream2_get_bytes_left(&gb) < 2)
                return bytestream2_tell(&gb);
            for (i = 0; i < l; i++) {
...
            bytestream2_skip(&gb, 2);
        }
        i += l;
