// Vulnerable: VUL-CVE-2019-15165
*/
#define BT_SHB			0x0A0D0D0A

struct section_header_block {
	bpf_u_int32	byte_order_magic;
...
				return (0);	/* EOF */
			pcap_snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "truncated dump file; tried to read %" PRIsize " bytes, only got %" PRIsize,
			    bytes_to_read, amt_read);
		}
...
	}

	/*
