// Vulnerable: VUL-CVE-2021-42778
sc_file_t *file = NULL;
	u8 buf[2];
	int r;

...
	sc_file_free(file);

	*tname = malloc(buf[1]);
	if (*tname == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
...
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}
