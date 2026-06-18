// Vulnerable: VUL-CVE-2006-2898
}
	if (res < sizeof(struct ast_iax2_mini_hdr)) {
		ast_log(LOG_WARNING, "midget packet received (%d of %d min)\n", res, (int)sizeof(struct ast_iax2_mini_hdr));
		return 1;
	}
...
		return 1;
	}
	if ((vh->zeros == 0) && (ntohs(vh->callno) & 0x8000)) {
		/* This is a video frame, get call number */
		fr->callno = find_callno(ntohs(vh->callno) & ~0x8000, dcallno, &sin, new, 1, fd);
...
			f.data = buf + sizeof(struct ast_iax2_mini_hdr);
		else
			f.data = NULL;
