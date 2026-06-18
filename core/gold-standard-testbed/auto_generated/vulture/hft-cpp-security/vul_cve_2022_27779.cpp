// Vulnerable: VUL-CVE-2022-27779
static bool bad_domain(const char *domain)
{
  return !strchr(domain, '.') && !strcasecompare(domain, "localhost");
}
