// Vulnerable: VUL-CVE-2016-5355
char	line[TOSHIBA_LINE_LENGTH];
	int	num_items_scanned;
	guint	pkt_len;
	int	pktnum, hr, min, sec, csec;
	char	channel[10], direction[10];
	int	i, hex_lines;
...
	} while (strcmp(line, "OFFSET 0001-0203") != 0);

	num_items_scanned = sscanf(line+64, "LEN=%9u", &pkt_len);
	if (num_items_scanned != 1) {
...
		*err_info = g_strdup("toshiba: OFFSET line doesn't have valid LEN item");
		return FALSE;
	}
