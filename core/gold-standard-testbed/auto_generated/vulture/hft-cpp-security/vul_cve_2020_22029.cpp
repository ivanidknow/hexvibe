// Vulnerable: VUL-CVE-2020-22029
for (g = 0; g < filtersize; ++g) {
                        dst[INDX2D(r, c, width)] += GAUSS(src, r,                        c + GINDX(filtersize, g),
                                                          in_linesize, height, width, gauss[GINDX(filtersize, g)]);
                    }
                }
...
                    for (g = 0; g < filtersize; ++g) {
                        dst[INDX2D(r, c, width)] += GAUSS(src, r + GINDX(filtersize, g), c,
                                                          width, height, width, gauss[GINDX(filtersize, g)]);
                    }
                }
