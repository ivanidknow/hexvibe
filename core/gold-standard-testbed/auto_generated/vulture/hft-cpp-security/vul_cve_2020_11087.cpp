// Vulnerable: VUL-CVE-2020-11087
SECURITY_STATUS ntlm_read_AuthenticateMessage(NTLM_CONTEXT* context, PSecBuffer buffer)
{
	wStream* s;
	size_t length;
...
	wStream* s;
	size_t length;
	UINT32 flags;
	NTLM_AV_PAIR* AvFlags;
	UINT32 PayloadBufferOffset;
	NTLM_AUTHENTICATE_MESSAGE* message;
...
	context->state = NTLM_STATE_COMPLETION;
	return SEC_I_COMPLETE_NEEDED;
}
