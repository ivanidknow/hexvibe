// Vulnerable: VUL-CVE-2018-14879
{
	char *ret;

	ret = fgets(ptr, PATH_MAX, VFile);
...
		return NULL;

	if (ptr[strlen(ptr) - 1] == '\n')
		ptr[strlen(ptr) - 1] = '\0';

	return ret;
