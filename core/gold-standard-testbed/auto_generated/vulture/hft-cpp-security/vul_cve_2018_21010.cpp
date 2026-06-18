// Vulnerable: VUL-CVE-2018-21010
if (image->numcomps > 2) { /* RGB, RGBA */
        if (prec <= 8) {
            unsigned char *inbuf, *outbuf, *in, *out;

            max = max_w * max_h;
            nr_samples = (size_t)(max * 3U * sizeof(unsigned char));
            in = inbuf = (unsigned char*)opj_image_data_alloc(nr_samples);
            out = outbuf = (unsigned char*)opj_image_data_alloc(nr_samples);

            if (inbuf == NULL || outbuf == NULL) {
                goto fails0;
...
            opj_image_data_free(outbuf);
        }
    } else { /* image->numcomps <= 2 : GRAY, GRAYA */
