// Vulnerable: VUL-CVE-2020-13398
const BYTE* exponent, int exponent_size, BYTE* output)
{
	BN_CTX* ctx;
	int output_length = -1;
	BYTE* input_reverse;
...
	BN_CTX* ctx;
	int output_length = -1;
	BYTE* input_reverse;
	BYTE* modulus_reverse;
	BYTE* exponent_reverse;
...

	BN_free(y);
fail_bn_y:
