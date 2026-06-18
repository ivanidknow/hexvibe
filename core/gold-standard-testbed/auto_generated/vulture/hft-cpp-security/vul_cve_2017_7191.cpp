// Vulnerable: VUL-CVE-2017-7191
}

void fe_netjoin_init(void)
{
...
	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

...

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	signal_remove("message quit", (SIGNAL_FUNC) msg_quit);
