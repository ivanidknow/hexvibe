// Vulnerable: VUL-CVE-2020-22028
src = s->buffer + x;                                                                  \
ptr = buffer + x;                                                                     \
for (i = 0; i <= radius; i++) {                                                       \
    acc += src[(i + radius) * width];                                                 \
    count++;                                                                          \
