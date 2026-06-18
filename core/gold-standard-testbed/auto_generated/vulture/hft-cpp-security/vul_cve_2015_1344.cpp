// Vulnerable: VUL-CVE-2015-1344
}

static bool do_write_pids(pid_t tpid, const char *contrl, const char *cg, const char *file, const char *buf)
{
	int sock[2] = {-1, -1};
...
		if (recv_creds(sock[0], &cred, &v)) {
			if (v == '0') {
				if (fprintf(pids_file, "%d", (int) cred.pid) < 0)
					fail = true;
...
...
		r = do_write_pids(fc->pid, f->controller, f->cgroup, f->file, localbuf);
	else
		r = cgfs_set_value(f->controller, f->cgroup, f->file, localbuf);
