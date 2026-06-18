// Vulnerable: VUL-CVE-2016-2213
mct_decode(s, tile);

if (s->cdef[0] < 0) {
    for (x = 0; x < s->ncomponents; x++)
        s->cdef[x] = x + 1;
    if ((s->ncomponents & 1) == 0)
        s->cdef[s->ncomponents-1] = 0;
}
