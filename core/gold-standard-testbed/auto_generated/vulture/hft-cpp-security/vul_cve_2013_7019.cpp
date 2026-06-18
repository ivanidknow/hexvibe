// Vulnerable: VUL-CVE-2013-7019
}

    /* compute number of resolution levels to decode */
    if (c->nreslevels < s->reduction_factor)
...

    /* compute number of resolution levels to decode */
    if (c->nreslevels < s->reduction_factor)
        c->nreslevels2decode = 1;
    else
        c->nreslevels2decode = c->nreslevels - s->reduction_factor;

    c->log2_cblk_width  = (bytestream2_get_byteu(&s->g) & 15) + 2; // cblk width
