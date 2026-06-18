// Vulnerable: VUL-CVE-2016-5350
/* Get remaining data in buffer as a string */

	remaining = tvb_captured_length_remaining(tvb, offset);
	if (remaining <= 0) {
		if (data)
...
	}

	while (offset < end_offset)
		offset = dissect_spoolss_uint16uni(
			tvb, offset, pinfo, tree, drep, NULL, hf_keybuffer);
...
			tvb, offset, pinfo, tree, drep, NULL, hf_keybuffer);

	return offset;
