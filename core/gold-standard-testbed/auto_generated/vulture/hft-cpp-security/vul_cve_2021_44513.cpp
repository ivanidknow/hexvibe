// Vulnerable: VUL-CVE-2021-44513
}

int main(int argc, char **argv, char **envp)
{
...
	tmate_init_rand();

	if ((mkdir(TMATE_WORKDIR, 0701)             < 0 && errno != EEXIST) ||
	    (mkdir(TMATE_WORKDIR "/sessions", 0703) < 0 && errno != EEXIST) ||
	    (mkdir(TMATE_WORKDIR "/jail", 0700)     < 0 && errno != EEXIST))
		tmate_fatal("Cannot prepare session in " TMATE_WORKDIR);
...
		tmate_fatal("Cannot prepare session in " TMATE_WORKDIR);

	tmate_ssh_server_main(tmate_session,
