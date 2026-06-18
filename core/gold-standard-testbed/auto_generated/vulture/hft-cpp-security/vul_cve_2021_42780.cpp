// Vulnerable: VUL-CVE-2021-42780
while ((r = sc_read_record(card, ++rec_no, buf, sizeof(buf), SC_RECORD_BY_REC_NR)) > 0) {
			int found = 0, fbz = -1;
			if (buf[0] != 0xA0)
				continue;
			for (i = 2; i < buf[1] + 2; i += 2 + buf[i + 1]) {
...
			if (buf[0] != 0xA0)
				continue;
			for (i = 2; i < buf[1] + 2; i += 2 + buf[i + 1]) {
				if (buf[i] == 0x83 && buf[i + 1] == 1 && buf[i + 2] == pin_reference) {
					++found;
...
				if (buf[i] == 0x90) {
					fbz = buf[i + 1 + buf[i + 1]];
				}
