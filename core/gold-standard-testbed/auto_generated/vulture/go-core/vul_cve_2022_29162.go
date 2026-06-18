// Vulnerable: VUL-CVE-2022-29162
"CAP_AUDIT_WRITE",
		},
		Inheritable: []string{
			"CAP_CHOWN",
			"CAP_DAC_OVERRIDE",
			"CAP_FSETID",
			"CAP_FOWNER",
			"CAP_MKNOD",
			"CAP_NET_RAW",
			"CAP_SETGID",
			"CAP_SETUID",
...
	pconfig2.Capabilities.Inheritable = append(config.Capabilities.Inheritable, "CAP_SYS_ADMIN")

	err = container.Run(pconfig2)
