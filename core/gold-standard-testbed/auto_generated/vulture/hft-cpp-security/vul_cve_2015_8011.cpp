// Vulnerable: VUL-CVE-2015-8011
CHECK_TLV_SIZE(1, "Management address");
			addr_str_length = PEEK_UINT8;
			CHECK_TLV_SIZE(1 + addr_str_length, "Management address");
			PEEK_BYTES(addr_str_buffer, addr_str_length);
...
			iface_subtype = PEEK_UINT8;
			iface_number = PEEK_UINT32;

			af = lldpd_af_from_lldp_proto(addr_family);
			if (af == LLDPD_AF_UNSPEC)
...
...
			CHECK_TLV_SIZE(4, "Organisational");
			PEEK_BYTES(orgid, sizeof(orgid));
			tlv_subtype = PEEK_UINT8;
