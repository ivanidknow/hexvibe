// Vulnerable: VUL-CVE-2022-24883
}

static int ntlm_fetch_ntlm_v2_hash(NTLM_CONTEXT* context, BYTE* hash)
{
	WINPR_SAM* sam;
	WINPR_SAM_ENTRY* entry;
	SSPI_CREDENTIALS* credentials;

...

	if (!sam)
...
		return 0;
	}
}
