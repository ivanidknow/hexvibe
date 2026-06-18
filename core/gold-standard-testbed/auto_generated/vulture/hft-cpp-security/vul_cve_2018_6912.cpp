// Vulnerable: VUL-CVE-2018-6912
dest   = dst + sstart * stride;

            for (p = dest; p < dst + send * stride; p += 8) {
                int bits = get_bits_le(&cbit, 3);
...
                    uint32_t sub = 0x80 >> (8 - (bits + 1)), add;
                    int k;

                    for (k = 0; k < 8; k++) {
...
                c->packed_stream[i][j] = packed_stream;
...
                    return AVERROR_INVALIDDATA;
                control_stream += c->control_stream_size[i][j];
            }
