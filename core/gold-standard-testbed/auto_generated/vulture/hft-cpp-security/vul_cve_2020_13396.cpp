// Vulnerable: VUL-CVE-2020-13396
SECURITY_STATUS ntlm_read_ChallengeMessage(NTLM_CONTEXT* context, PSecBuffer buffer)
{
	wStream* s;
	int length;
...
{
	wStream* s;
	int length;
	PBYTE StartOffset;
	PBYTE PayloadOffset;
	NTLM_AV_PAIR* AvTimestamp;
...
	Stream_Free(s, FALSE);
	return SEC_I_CONTINUE_NEEDED;
}
