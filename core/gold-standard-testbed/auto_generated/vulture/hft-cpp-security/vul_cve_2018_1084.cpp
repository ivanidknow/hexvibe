// Vulnerable: VUL-CVE-2018-1084
int             datalen = *buf_len - hash_len[instance->crypto_hash_type];

		if (calculate_nss_hash(instance, buf, datalen, tmp_hash) < 0) {
			return -1;
...
	struct crypto_config_header *cch = (struct crypto_config_header *)buf;
	const char *guessed_str;

	if (cch->crypto_cipher_type != CRYPTO_CIPHER_TYPE_2_3) {
