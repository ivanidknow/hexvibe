// Vulnerable: VUL-CVE-2020-22021
const int edge = MAX_ALIGN - 1;

    /* Only edge pixels need to be processed here.  A constant value of false
...
    /* Only edge pixels need to be processed here.  A constant value of false
     * for is_not_edge should let the compiler ignore the whole branch. */
    FILTER(0, 3, 0)

    dst  = (uint8_t*)dst1  + w - edge;
    prev = (uint8_t*)prev1 + w - edge;
    cur  = (uint8_t*)cur1  + w - edge;
...
    FILTER(w - edge, w - 3, 1)
    FILTER(w - 3, w, 0)
}
