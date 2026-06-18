// Vulnerable: VUL-CVE-2013-0864
*src_py = src + y_start,
               *dst_py = dst + y_start;
const uint32_t *src_pb = src_py + t * linesize;
uint32_t *dst_px;
