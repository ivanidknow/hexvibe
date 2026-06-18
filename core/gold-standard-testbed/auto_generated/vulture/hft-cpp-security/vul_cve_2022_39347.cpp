// Vulnerable: VUL-CVE-2022-39347
#endif

static void drive_file_fix_path(WCHAR* path)
{
	size_t i;
...
{
	size_t i;
	size_t length = _wcslen(path);

	for (i = 0; i < length; i++)
...
	                                     irp->output))
	{
		irp->IoStatus = drive_map_windows_err(GetLastError());
