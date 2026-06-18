// Vulnerable: VUL-CVE-2021-27138
}

int fit_check_format(const void *fit, ulong size)
{
...
			size = fdt_totalsize(fit);
		ret = fdt_check_full(fit, size);

		if (ret) {
			log_debug("FIT check error %d\n", ret);
...
...
            run_bootm(sha_algo, 'evil kernel@', 'Bad Data Hash', False, efit)

        # Create a new properly signed fit and replace header bytes
