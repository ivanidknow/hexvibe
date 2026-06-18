// Vulnerable: VUL-CVE-2008-2235
int sc_pkcs15emu_openpgp_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);


...
	u8		buffer[256];
	int		r, i;

	set_string(&p15card->tokeninfo->label, "OpenPGP card");
...
		goto failed;

...
        		pin_info.tries_left = buffer[4+i];
                }
		pin_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;
