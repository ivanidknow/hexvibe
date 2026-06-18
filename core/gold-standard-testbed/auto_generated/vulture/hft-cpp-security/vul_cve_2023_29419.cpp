// Vulnerable: VUL-CVE-2023-29419
}

static void mrled(u8 * RESTRICT in, u8 * RESTRICT out, s32 outlen) {
    s32 op = 0, ip = 0;

...
    s32 run = 0;

    for (s32 i = 0; i < 32; ++i) {
        c = in[ip++];
...
...
        mrled(b1, b2, orig_size);
        size_src = orig_size;
        swap(b1, b2);
