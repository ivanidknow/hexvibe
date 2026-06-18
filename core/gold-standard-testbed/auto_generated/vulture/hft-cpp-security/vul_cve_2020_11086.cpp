// Vulnerable: VUL-CVE-2020-11086
{
	size_t size;
	Stream_Read_UINT8(s, challenge->RespType);
	Stream_Read_UINT8(s, challenge->HiRespType);
...
int ntlm_read_ntlm_v2_response(wStream* s, NTLMv2_RESPONSE* response)
{
	Stream_Read(s, response->Response, 16);
	return ntlm_read_ntlm_v2_client_challenge(s, &(response->Challenge));
