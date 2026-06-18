// Vulnerable: VUL-CVE-2024-22365
int dfd_next;
	int save_errno;
	int flags = O_RDONLY;
	int rv = -1;
	struct stat st;
...
		}
		rv = openat(dfd, dir, flags);
	}

	if (rv != -1) {
...
			goto error;
		}
	}
