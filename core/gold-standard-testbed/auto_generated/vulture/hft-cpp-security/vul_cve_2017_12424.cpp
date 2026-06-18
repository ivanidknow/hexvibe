// Vulnerable: VUL-CVE-2017-12424
(NULL != ptr)
#if KEEP_NIS_AT_END
	     && (NULL != ptr->line)
	     && (   ('+' != ptr->line[0])
	         && ('-' != ptr->line[0]))
#endif
	     ;
...
	}
#if KEEP_NIS_AT_END
	if ((NULL != ptr) && (NULL != ptr->line)) {
		nis = ptr;
	}
