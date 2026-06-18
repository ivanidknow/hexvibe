// Vulnerable: VUL-CVE-2020-5221
}

if (!chrooted && strncmp(dir, home, strlen(home))) {
	DBG("Failed non-chroot dir:%s vs home:%s", dir, home);
	return NULL;
