// Vulnerable: VUL-CVE-2020-5208
uint32_t offset, uint32_t length, uint8_t *frubuf)
{
	uint32_t off = offset, tmp, finish;
	struct ipmi_rs * rsp;
	struct ipmi_rq req;
...
	finish = offset + length;
	if (finish > fru->size) {
		finish = fru->size;
		lprintf(LOG_NOTICE, "Read FRU Area length %d too large, "
...
...
		off += tmp;

		/* sometimes the size returned in the Info command
