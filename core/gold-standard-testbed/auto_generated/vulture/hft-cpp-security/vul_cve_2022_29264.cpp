// Vulnerable: VUL-CVE-2022-29264
endif

config SMM_LAPIC_REMAP_MITIGATION
	bool
// --- Makefile.inc ---
## SPDX-License-Identifier: GPL-2.0-only

ramstage-y += smm_module_loader.c
ramstage-y += smi_trigger.c
...

...
	printk(BIOS_DEBUG, "Installing SMM handler to 0x%08lx\n", smbase);

	if (smm_load_module((void *)smbase, smsize, &smm_params))
