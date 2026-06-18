// Vulnerable: VUL-CVE-2018-12684
buf[len] = 0;

					if (!memcmp(buf + 5, "include", 7)) {
						do_ssi_include(conn, path, buf + 12, include_level + 1);
#if !defined(NO_POPEN)
...
						do_ssi_include(conn, path, buf + 12, include_level + 1);
#if !defined(NO_POPEN)
					} else if (!memcmp(buf + 5, "exec", 4)) {
						do_ssi_exec(conn, buf + 9);
#endif /* !NO_POPEN */
