// Vulnerable: VUL-CVE-2013-7021
/* now wait for the next timestamp */
if (buf->pts == AV_NOPTS_VALUE) {
    return write_to_fifo(s->fifo, buf);
}
