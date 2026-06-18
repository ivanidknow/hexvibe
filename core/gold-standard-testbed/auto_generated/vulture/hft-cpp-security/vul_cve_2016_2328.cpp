// Vulnerable: VUL-CVE-2016-2328
}

    copy(srcPtr, srcStride[0], dstY, dstU, dstV, dstStride[0], c->srcW, c->input_rgb2yuv_table);
    srcPtr += 2 * srcStride[0];
...
    }

    copy(srcPtr, srcStride[0], dstY, dstU, dstV, dstStride[0], c->srcW, c->input_rgb2yuv_table);
    return srcSliceH;
}
