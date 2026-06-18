// Vulnerable: VUL-CVE-2014-9602
* Image is encoded as a big integer, using characters from '~' to
 * '!', for a total of 94 symbols. In order to express
 * 48x48*2=8*XFACE_MAX_WORDS=4608
 * bits, we need a total of 704 digits, as given by:
 * ceil(lg_94(2^4608)) = 704
 */
#define XFACE_MAX_DIGITS 704
...
 * ceil(lg_94(2^4608)) = 704
 */
#define XFACE_MAX_DIGITS 704
...
#define XFACE_MAX_WORDS ((XFACE_PIXELS * 2 + XFACE_BITSPERWORD - 1) / XFACE_BITSPERWORD)

/* Portable, very large unsigned integer arithmetic is needed.
