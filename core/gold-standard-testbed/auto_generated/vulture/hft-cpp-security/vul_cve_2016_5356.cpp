// Vulnerable: VUL-CVE-2016-5356
union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
	int	num_items_scanned;
	int	yy, mm, dd, hr, min, sec, csec;
	guint	pkt_len;
	int	pro, off, pri, rm, error;
	guint	code1, code2;
...
		/* appears to be output to a control blade */
		num_items_scanned = sscanf(line,
		   "%4d-%2d-%2d,%2d:%2d:%2d.%9d: %5s (%127[A-Za-z0-9/:]), Length:%9u, Pro:%9d, Off:%9d, Pri:%9d, RM:%9d, Err:%9d [%8x, %8x]",
			&yy, &mm, &dd, &hr, &min, &sec, &csec,
...
		yy = mm = dd = hr = min = sec = csec = 0;
	}
	if (pkt_len > WTAP_MAX_PACKET_SIZE) {
