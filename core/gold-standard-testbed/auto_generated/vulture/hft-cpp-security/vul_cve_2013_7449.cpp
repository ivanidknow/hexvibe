// Vulnerable: VUL-CVE-2013-7449
{
		case X509_V_OK:
			/* snprintf (buf, sizeof (buf), "* Verify OK (?)"); */
			/* EMIT_SIGNAL (XP_TE_SSLMESSAGE, serv->server_session, buf, NULL, NULL, NULL, 0); */
...
			/* snprintf (buf, sizeof (buf), "* Verify OK (?)"); */
			/* EMIT_SIGNAL (XP_TE_SSLMESSAGE, serv->server_session, buf, NULL, NULL, NULL, 0); */
			break;
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
...
...

int _SSL_get_cert_info (struct cert_info *cert_info, SSL * ssl);
struct chiper_info *_SSL_get_cipher_info (SSL * ssl);
