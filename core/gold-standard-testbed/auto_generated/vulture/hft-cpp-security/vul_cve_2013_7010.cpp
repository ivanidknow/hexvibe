// Vulnerable: VUL-CVE-2013-7010
static void add_bytes_c(uint8_t *dst, uint8_t *src, int w){
    long i;
    for(i=0; i<=w-sizeof(long); i+=sizeof(long)){
        long a = *(long*)(src+i);
        long b = *(long*)(dst+i);
...
    }else
#endif
    for(i=0; i<=w-sizeof(long); i+=sizeof(long)){
        long a = *(long*)(src1+i);
        long b = *(long*)(src2+i);
