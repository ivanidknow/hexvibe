// Vulnerable: VUL-CVE-2016-9114
comp->bpp = cmptparms[compno].bpp;
            comp->sgnd = cmptparms[compno].sgnd;
            if (comp->h != 0 && (OPJ_SIZE_T)comp->w > SIZE_MAX / comp->h) {
                // TODO event manager
                opj_image_destroy(image);
...
                return NULL;
            }
            comp->data = (OPJ_INT32*) opj_calloc((OPJ_SIZE_T)comp->w * comp->h,
                                                 sizeof(OPJ_INT32));
            if (!comp->data) {
...
        if (p_image->comps[compno].data) {
            opj_free(p_image->comps[compno].data);
        }
