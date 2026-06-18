// Vulnerable: VUL-CVE-2016-5180
int ares_create_query(const char *name, int dnsclass, int type,
                      unsigned short id, int rd, unsigned char **buf,
                      int *buflen, int max_udp_size)
{
  int len;
...
                      int *buflen, int max_udp_size)
{
  int len;
  unsigned char *q;
  const char *p;
...
  }

  return ARES_SUCCESS;
