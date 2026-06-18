// Vulnerable: VUL-CVE-2015-6819
} else if (s->upscale_h[p] == 2) {
                    if (is16bit) {
                        ((uint16_t*)line)[w - 1] =
                        ((uint16_t*)line)[w - 2] = ((uint16_t*)line)[(w - 1) / 3];
                    } else {
                        line[w - 1] =
...
                        ((uint16_t*)line)[w - 2] = ((uint16_t*)line)[(w - 1) / 3];
                    } else {
                        line[w - 1] =
                        line[w - 2] = line[(w - 1) / 3];
                    }
                    for (index = w - 3; index > 0; index--) {
