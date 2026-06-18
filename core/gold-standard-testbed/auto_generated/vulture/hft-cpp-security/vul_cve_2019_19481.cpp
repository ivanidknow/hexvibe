// Vulnerable: VUL-CVE-2019-19481
size_t size = 0;
	size_t left = 0;
	size_t len, next_len;
	sc_apdu_t apdu;
	int r = SC_SUCCESS;
...
	out_ptr = *out_buf ? *out_buf : buf;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, CAC_INS_GET_CERTIFICATE, 0, 0 );
	next_len = MIN(left, 100);
	for (; left > 0; left -= len, out_ptr += len) {
		len = next_len;
...
	size_t val_len;
	size_t len, cert_len;
	u8 cert_type;
