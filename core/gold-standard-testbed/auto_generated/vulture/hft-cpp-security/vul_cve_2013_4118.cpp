// Vulnerable: VUL-CVE-2013-4118
stream_read(s, wmac, sizeof(wmac));
	length -= sizeof(wmac);
	security_decrypt(s->p, length, rdp);

	if (securityFlags & SEC_SECURE_CHECKSUM)
// --- security.c ---
BOOL security_decrypt(BYTE* data, int length, rdpRdp* rdp)
{
	if (rdp->decrypt_use_count >= 4096)
	{
