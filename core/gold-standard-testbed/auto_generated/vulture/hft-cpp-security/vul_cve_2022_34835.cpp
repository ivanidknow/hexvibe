// Vulnerable: VUL-CVE-2022-34835
* Returns the address length.
 */
static uint get_alen(char *arg, int default_len)
{
	int	j;
	int	alen;

	alen = default_len;
...
	uint	chip;
	uint	devaddr, length;
...
	int alen;
	uint	addr;
	uint	length;
