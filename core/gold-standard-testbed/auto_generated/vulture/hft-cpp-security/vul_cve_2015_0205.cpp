// Vulnerable: VUL-CVE-2015-0205
{
s->s3->tmp.reuse_message=1;
if ((peer != NULL) && (type & EVP_PKT_SIGN))
	{
	al=SSL_AD_UNEXPECTED_MESSAGE;
