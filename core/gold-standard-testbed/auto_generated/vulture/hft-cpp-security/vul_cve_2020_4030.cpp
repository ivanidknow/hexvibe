// Vulnerable: VUL-CVE-2020-4030
trio_flags_t flags, int width, int precision)
{
	int length;
	int ch;

...
	else
	{
		if (precision == 0)
		{
			length = trio_length(string);
...
{
	return strlen(string);
}
