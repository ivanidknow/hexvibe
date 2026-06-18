// Vulnerable: VUL-CVE-2020-20277
}

if (!chrooted && strncmp(dir, home, strlen(home))) {
	DBG("Failed non-chroot dir:%s vs home:%s", dir, home);
	return NULL;
