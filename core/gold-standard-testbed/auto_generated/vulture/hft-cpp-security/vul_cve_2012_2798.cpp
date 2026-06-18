// Vulnerable: VUL-CVE-2012-2798
mask = 1;
}
if (frame_end - frame < 2)
    return -1;
if (bitbuf & mask) {
