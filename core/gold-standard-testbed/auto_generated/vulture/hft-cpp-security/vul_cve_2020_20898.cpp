// Vulnerable: VUL-CVE-2020-20898
for (x = 0; x < width; x++) {
        int suma = AV_RN16A(&c[0][2 * x]) * -1 + AV_RN16A(&c[1][2 * x]) * -1 + AV_RN16A(&c[2][2 * x]) * -1 +
                   AV_RN16A(&c[6][2 * x]) *  1 + AV_RN16A(&c[7][2 * x]) *  1 + AV_RN16A(&c[8][2 * x]) *  1;
        int sumb = AV_RN16A(&c[0][2 * x]) * -1 + AV_RN16A(&c[2][2 * x]) *  1 + AV_RN16A(&c[3][2 * x]) * -1 +
                   AV_RN16A(&c[5][2 * x]) *  1 + AV_RN16A(&c[6][2 * x]) * -1 + AV_RN16A(&c[8][2 * x]) *  1;

        dst[x] = av_clip(sqrtf(suma*suma + sumb*sumb) * scale + delta, 0, peak);
...

    for (x = 0; x < width; x++) {
        int suma = AV_RN16A(&c[0][2 * x]) *  1 + AV_RN16A(&c[1][2 * x]) * -1;
...
                   c5[x] *  2 + c6[x] * -1 + c8[x] *  1;

        dst[x] = av_clip_uint8(sqrtf(suma*suma + sumb*sumb) * scale + delta);
