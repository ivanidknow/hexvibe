// Vulnerable: VUL-CVE-2020-26572
apdu.lc = apdu.datalen = crgram_len+1;
sbuf[0] = tcos3 ? 0x00 : ((data->pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) ? 0x81 : 0x02);
memcpy(sbuf+1, crgram, crgram_len);
