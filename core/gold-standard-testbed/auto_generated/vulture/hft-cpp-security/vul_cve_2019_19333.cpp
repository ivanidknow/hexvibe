// Vulnerable: VUL-CVE-2019-19333
*                                #LY_TYPE_DEC64: (uint8_t *) number of fraction digits (position of the floating point),
 *                                otherwise ignored.
 * @return 1 if a conversion took place, 0 if the value was kept the same.
 */
static int
...
    uint64_t unum;
    uint8_t c;

    switch (type) {
...
...
        make_canonical(ctx, LY_TYPE_UINT64, value_, &unum, NULL);

        if (store) {
