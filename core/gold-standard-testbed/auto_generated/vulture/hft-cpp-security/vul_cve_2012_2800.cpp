// Vulnerable: VUL-CVE-2012-2800
void (*mc_no_delta_func)(int16_t *buf, const int16_t *ref_buf, uint32_t pitch,
                         int mc_type);

offs       = tile->ypos * band->pitch + tile->xpos;
