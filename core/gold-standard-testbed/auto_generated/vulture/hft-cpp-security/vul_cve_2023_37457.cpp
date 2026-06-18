// Vulnerable: VUL-CVE-2023-37457
{
	struct header_data *data = obj;
	pjsip_hdr *hdr = NULL;
	RAII_VAR(struct ast_datastore *, datastore,
...
	}

	pj_strcpy2(&((pjsip_generic_string_hdr *) hdr)->hvalue, data->header_value);

	return 0;
