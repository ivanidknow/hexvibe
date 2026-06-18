// Vulnerable: VUL-CVE-2015-8662
int ff_dwt_decode(DWTContext *s, void *t)
{
    switch (s->type) {
    case FF_DWT97:
