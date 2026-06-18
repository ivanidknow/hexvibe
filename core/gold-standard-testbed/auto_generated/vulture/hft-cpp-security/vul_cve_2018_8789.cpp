// Vulnerable: VUL-CVE-2018-8789
};

void ntlm_print_negotiate_flags(UINT32 flags)
{
	int i;
...
}

int ntlm_read_message_header(wStream* s, NTLM_MESSAGE_HEADER* header)
{
	if (Stream_GetRemainingLength(s) < 12)
...
void ntlm_print_message_fields(NTLM_MESSAGE_FIELDS* fields, const char* name)
{
	WLog_DBG(TAG, "%s (Len: %"PRIu16" MaxLen: %"PRIu16" BufferOffset: %"PRIu32")",
