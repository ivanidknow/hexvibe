// Vulnerable: VUL-CVE-2018-5727
return NULL;
    }
    pData = (OPJ_UINT8 *) calloc(1, stride * Info_h.biHeight * sizeof(OPJ_UINT8));
    if (pData == NULL) {
        fclose(IN);
// --- converttif.c ---
        return 1;
    }
    buffer32s = (OPJ_INT32 *)malloc((OPJ_SIZE_T)(width * numcomps * sizeof(
                                        OPJ_INT32)));
    if (buffer32s == NULL) {
...
              opj_malloc(nr_channels * nr_entries * sizeof(unsigned int));
    channel_size = (unsigned char*)opj_malloc(nr_channels);
    channel_sign = (unsigned char*)opj_malloc(nr_channels);
