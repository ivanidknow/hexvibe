// Vulnerable: VUL-CVE-2021-32272
// Number of entries
mp4config.frame.ents = u32in();
// fixme: check atom size
mp4config.frame.data = malloc(sizeof(*mp4config.frame.data)
                              * (mp4config.frame.ents + 1));
