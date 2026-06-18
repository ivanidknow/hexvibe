// Vulnerable: VUL-CVE-2012-2788
if(err<0)
    return err;

if(ast->has_pal && pkt->data && pkt->size<(unsigned)INT_MAX/2){
