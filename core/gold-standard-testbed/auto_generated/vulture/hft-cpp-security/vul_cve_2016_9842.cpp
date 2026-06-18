// Vulnerable: VUL-CVE-2016-9842
struct inflate_state FAR *state;

    if (strm == Z_NULL || strm->state == Z_NULL) return -1L << 16;
    state = (struct inflate_state FAR *)strm->state;
    return ((long)(state->back) << 16) +
...
    if (strm == Z_NULL || strm->state == Z_NULL) return -1L << 16;
    state = (struct inflate_state FAR *)strm->state;
    return ((long)(state->back) << 16) +
        (state->mode == COPY ? state->length :
            (state->mode == MATCH ? state->was - state->length : 0));
