// Vulnerable: VUL-CVE-2007-2297
if (x == 1)
					peert38capability |= T38FAX_TRANSCODING_JBIG;
			} else if ((sscanf(a, "T38FaxRateManagement:%s", s) == 1)) {
				found = 1;
				if (option_debug > 2)
...
				found = 1;
				if (option_debug > 2)
					ast_log(LOG_DEBUG, "RateMangement: %s\n", s);
				if (!strcasecmp(s, "localTCF"))
					peert38capability |= T38FAX_RATE_MANAGEMENT_LOCAL_TCF;
...
			} else if ((sscanf(a, "T38FaxUdpEC:%s", s) == 1)) {
				found = 1;
				if (option_debug > 2)
