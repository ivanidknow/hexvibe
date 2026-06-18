// Vulnerable: VUL-CVE-2015-0204
Thanks to Karthikeyan Bhargavan for reporting this issue.
     (CVE-2014-3572)
     [Steve Henson]
// --- SSL_CTX_set_options.pod ---
=item SSL_OP_EPHEMERAL_RSA

Always use ephemeral (temporary) RSA key when doing RSA operations
(see L<SSL_CTX_set_tmp_rsa_callback(3)|SSL_CTX_set_tmp_rsa_callback(3)>).
According to the specifications this is only done, when a RSA key
can only be used for signature operations (namely under export ciphers
with restricted RSA keylength). By setting this option, ephemeral
...
			if (s->s3->tmp.use_rsa_tmp
			/* PSK: send ServerKeyExchange if PSK identity
			 * hint if provided */
