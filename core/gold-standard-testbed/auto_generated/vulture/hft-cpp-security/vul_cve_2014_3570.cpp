// Vulnerable: VUL-CVE-2014-3570
#ifdef BN_LLONG
#define mul_add_c(a,b,c0,c1,c2) \
	t=(BN_ULLONG)a*b; \
	t1=(BN_ULONG)Lw(t); \
	t2=(BN_ULONG)Hw(t); \
	c0=(c0+t1)&BN_MASK2; if ((c0) < t1) t2++; \
	c1=(c1+t2)&BN_MASK2; if ((c1) < t2) c2++;

#define mul_add_c2(a,b,c0,c1,c2) \
	t=(BN_ULLONG)a*b; \
	tt=(t+t)&BN_MASK; \
...
	{
	BN_ULONG t1,t2;
	BN_ULONG c1,c2,c3;
