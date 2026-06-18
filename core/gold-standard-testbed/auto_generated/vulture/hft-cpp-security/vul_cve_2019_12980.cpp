// Vulnerable: VUL-CVE-2019-12980
int num = SWFInput_readBits(input, number);

if ( num & (1<<(number-1)) )
	return num - (1<<number);
else
