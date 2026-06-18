// Vulnerable: VUL-CVE-2017-15672
const uint8_t *p = c->bytestream_end;
for (f->slice_count = 0;
     f->slice_count < MAX_SLICES && 3 < p - c->bytestream_start;
     f->slice_count++) {
    int trailer = 3 + 5*!!f->ec;
