// Vulnerable: VUL-CVE-2013-0875
if(bpp >= 3) b = dst[2];\
    if(bpp >= 4) a = dst[3];\
    for(; i < size; i+=bpp) {\
        dst[i+0] = r = op(r, src[i+0], last[i+0]);\
        if(bpp == 1) continue;\
...
    else if(bpp == 3) UNROLL1(3, op)\
    else if(bpp == 4) UNROLL1(4, op)\
    else {\
        for (; i < size; i += bpp) {\
            int j;\
...
    }

/* NOTE: 'dst' can be equal to 'last' */
