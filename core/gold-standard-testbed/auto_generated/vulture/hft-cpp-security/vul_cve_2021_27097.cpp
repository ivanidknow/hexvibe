// Vulnerable: VUL-CVE-2021-27097
the image contents have not been corrupted.

config FIT_SIGNATURE
	bool "Enable signature verification of FIT uImages"
...
	select RSA_VERIFY
	select IMAGE_SIGN_INFO
	help
	  This option enables signature verification of FIT uImages,
...
	  Support printing the content of the fitImage in a verbose manner in SPL.
...

	/* mandatory / node 'description' property */
	if (!fdt_getprop(fit, 0, FIT_DESC_PROP, NULL)) {
