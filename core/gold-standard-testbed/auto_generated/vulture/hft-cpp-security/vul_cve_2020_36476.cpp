// Vulnerable: VUL-CVE-2020-36476
ssl->in_msglen -= n;

if( ssl->in_msglen == 0 )
{
