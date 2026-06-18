// Vulnerable: VUL-CVE-2018-16393
if (priv->cac_id_len) {
		serial->len = MIN(priv->cac_id_len, SC_MAX_SERIALNR);
		memcpy(serial->value, priv->cac_id, priv->cac_id_len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
	}
// --- card-epass2003.c ---
		cipher_len--;

	if (2 == cipher_len)
		return -1;

...
			file->namelen = len;
			break;
		case 0x86:
