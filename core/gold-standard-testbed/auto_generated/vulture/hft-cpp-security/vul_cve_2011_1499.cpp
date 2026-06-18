// Vulnerable: VUL-CVE-2011-1499
*/
static int
fill_netmask_array (char *bitmask_string, unsigned char array[],
                    size_t len)
{
        unsigned int i;
...
                return -1;

        /* valid range for a bit mask */
        if (mask > (8 * len))
...
                            (p + 1, &(acl.address.ip.mask[0]), IPV6_LEN)
                            < 0)
                                return -1;
