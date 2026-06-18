// Vulnerable: VUL-CVE-2016-7502
int i;
    int16_t (*src)[8] = (int16_t(*)[8])block;
    const uint8_t *cm = ff_crop_tab + MAX_NEG_CROP;

    src[0][0] += 8;
...
        const int b3 = a4 - a6;

        dst[i + 0*stride] = cm[ dst[i + 0*stride] + ((b0 + b4) >> 7)];
        dst[i + 1*stride] = cm[ dst[i + 1*stride] + ((b1 + b5) >> 7)];
        dst[i + 2*stride] = cm[ dst[i + 2*stride] + ((b2 + b6) >> 7)];
...
        dst[i + 7*stride] = cm[ dst[i + 7*stride] + ((b0 - b4) >> 7)];
    }
}
