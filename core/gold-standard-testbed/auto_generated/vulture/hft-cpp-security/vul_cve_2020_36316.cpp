// Vulnerable: VUL-CVE-2020-36316
static int pad_basic(bn_t m, int *p_len, int m_len, int k_len, int operation) {
	uint8_t pad = 0;
	int result = RLC_OK;
	bn_t t;

...
				/* Make room for the real message. */
				bn_lsh(m, m, m_len * 8);
				break;
			case RSA_DEC:
...
...
						result = RLC_ERR;
					}
					bn_read_bin(m, h2, RLC_MD_LEN);
