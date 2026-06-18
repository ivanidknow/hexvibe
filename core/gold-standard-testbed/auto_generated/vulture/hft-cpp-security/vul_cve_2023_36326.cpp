// Vulnerable: VUL-CVE-2023-36326
crt_t crt;
	dig_t f;
	int len;

	bn_null(a);
...
	BENCH_RUN("bn_rec_naf") {
		int8_t naf[RLC_BN_BITS + 1];
		int len;
		bn_rand(a, RLC_POS, RLC_BN_BITS);
		BENCH_ADD((len = RLC_BN_BITS + 1, bn_rec_naf(naf, &len, a, 4)));
...
void bn_rec_jsf(int8_t *jsf, int *len, const bn_t k, const bn_t l);

/**
