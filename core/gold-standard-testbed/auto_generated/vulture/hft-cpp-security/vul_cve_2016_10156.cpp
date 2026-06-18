// Vulnerable: VUL-CVE-2016-10156
mkdir_parents(path, 0755);

fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, mode > 0 ? mode : 0644);
if (fd < 0)
        return -errno;
