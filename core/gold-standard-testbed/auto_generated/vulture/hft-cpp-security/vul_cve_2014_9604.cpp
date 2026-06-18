// Vulnerable: VUL-CVE-2014-9604
slice_start;

        bsrc = src + slice_start * stride;

...
                         slice_start;
        slice_height >>= 1;

        bsrc = src + slice_start * stride;
