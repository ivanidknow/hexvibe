// Vulnerable: VUL-CVE-2012-6697
case DNS_QUERY_CNAME:
		case DNS_QUERY_PTR:
			o = 0;
			q = 0;
...

					/* check that highest two bits are set. if not, we've been had */
					if (!(i & DN_COMP_BITMASK))
						return std::make_pair((unsigned char *) NULL, "DN label decompression header is bogus");

...
...
			res[o] = 0;
		break;
		case DNS_QUERY_AAAA:
