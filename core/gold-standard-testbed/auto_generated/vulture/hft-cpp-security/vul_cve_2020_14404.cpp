// Vulnerable: VUL-CVE-2020-14404
if (seg[x] != cl) {break;}                                        \
            i = x;                                                            \
            while ((seg[i] == cl) && (i < w)) i += 1;                         \
            i -= 1;                                                           \
            if (j == y) vx = hx = i;                                          \
// --- hextile.c ---
                    if (seg[x] != cl2) {break;}                                 \
                    i = x;                                                      \
                    while ((seg[i] == cl2) && (i < w)) i += 1;                  \
                    i -= 1;                                                     \
                    if (j == y) vx = hx = i;                                    \
...
            while ((seg[i] == cl) && (i < w)) i += 1;                         \
            i -= 1;                                                           \
            if (j == y) vx = hx = i;                                          \
