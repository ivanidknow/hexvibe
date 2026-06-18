// Vulnerable: VUL-CVE-2015-6824
/* Allocate pixbufs (we use dynamic allocation because otherwise we would
 * need to allocate several megabytes to handle all possible cases) */
FF_ALLOC_OR_GOTO(c, c->lumPixBuf,  c->vLumBufSize * 3 * sizeof(int16_t *), fail);
FF_ALLOC_OR_GOTO(c, c->chrUPixBuf, c->vChrBufSize * 3 * sizeof(int16_t *), fail);
FF_ALLOC_OR_GOTO(c, c->chrVPixBuf, c->vChrBufSize * 3 * sizeof(int16_t *), fail);
if (CONFIG_SWSCALE_ALPHA && isALPHA(c->srcFormat) && isALPHA(c->dstFormat))
    FF_ALLOCZ_OR_GOTO(c, c->alpPixBuf, c->vLumBufSize * 3 * sizeof(int16_t *), fail);
