// Vulnerable: VUL-CVE-2014-8275
Changes between 1.0.1j and 1.0.1k [xx XXX xxxx]

   *) Do not resume sessions on the server if the negotiated protocol
// --- a_verify.c ---
		goto err;
		}

	inl=i2d(data,NULL);
...
		}

...
err:
	ECDSA_SIG_free(s);
	return(ret);
