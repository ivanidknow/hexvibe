// Vulnerable: VUL-CVE-2014-9317
if (length != 13)
    return AVERROR_INVALIDDATA;
s->width  = bytestream2_get_be32(&s->gb);
s->height = bytestream2_get_be32(&s->gb);
