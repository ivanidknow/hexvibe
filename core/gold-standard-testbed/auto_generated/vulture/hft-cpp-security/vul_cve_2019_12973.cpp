// Vulnerable: VUL-CVE-2019-12973
OPJ_UINT32 stride, OPJ_UINT32 width, OPJ_UINT32 height)
{
    OPJ_UINT32 x, y;
    OPJ_UINT8 *pix;
    const OPJ_UINT8 *beyond;
...
    pix = pData;

    x = y = 0U;
    while (y < height) {
        int c = getc(IN);
...
    }/* while() */
    return OPJ_TRUE;
}
