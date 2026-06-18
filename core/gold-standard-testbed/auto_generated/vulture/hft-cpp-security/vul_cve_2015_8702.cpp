// Vulnerable: VUL-CVE-2015-8702
case DNS_QUERY_PTR:
				/* Reverse lookups just come back as char* */
				resultstr = std::string((const char*)data.first);
...
				/* Reverse lookups just come back as char* */
				resultstr = std::string((const char*)data.first);
			break;
