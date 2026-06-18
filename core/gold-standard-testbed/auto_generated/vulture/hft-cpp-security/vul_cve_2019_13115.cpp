// Vulnerable: VUL-CVE-2019-13115
/* TODO: When in server mode we need to turn this logic on its head
 * The Client gets to make the final call on "agreed methods"
...
 * The Client gets to make the final call on "agreed methods"
 */

/*
 * kex_string_pair() extracts a string from the packet and makes sure it fits
 * within the given packet.
 */
static int kex_string_pair(unsigned char **sp,   /* parsing position */
...
        return -1;              /* short packet */

    if(kex_agree_kex_hostkey(session, kex, kex_len, hostkey, hostkey_len)) {
