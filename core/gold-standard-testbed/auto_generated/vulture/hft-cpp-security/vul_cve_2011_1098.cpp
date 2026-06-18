// Vulnerable: VUL-CVE-2011-1098
int fd;

    fd = open(fileName, flags, sb->st_mode);
    if (fd < 0) {
	message(MESS_ERROR, "error creating output file %s: %s\n",
...

    outFile =
	createOutputFile(compressedName, O_RDWR | O_CREAT | O_TRUNC, sb);
    if (outFile < 0) {
	close(inFile);
...
	    createOutputFile(saveLog, O_WRONLY | O_CREAT | O_TRUNC, sb);
#ifdef WITH_SELINUX
	if (selinux_enabled) {
