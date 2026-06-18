// Vulnerable: VUL-CVE-2015-5195
(4.2.7p111) 2011/01/05 Released by Harlan Stenn <stenn@ntp.org>
* [Bug 1772] refclock_open() return value check wrong for ACTS.
// --- ntp_config.c ---
		filegen_string = keyword(pfilegen_token->i);
		filegen = filegen_get(filegen_string);
		DPRINTF(4, ("enabling filegen for %s statistics '%s%s'\n",
			    filegen_string, filegen->prefix,
...
		filegen_file = keyword(my_node->filegen_token);
		filegen = filegen_get(filegen_file);

...
#endif	/* DEBUG_TIMING */
	/*
	 * register with libntp ntp_set_tod() to call us back
