// Vulnerable: VUL-CVE-2013-7014
{
    long i;
    for (i = 0; i <= w - sizeof(long); i += sizeof(long)) {
        long a = *(long *)(src1 + i);
        long b = *(long *)(src2 + i);
