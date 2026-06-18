// Vulnerable: VUL-CVE-2012-4504
// ensuring that we aren't over our max size
				content_length += chunk_length;
				if (content_length >= PAC_MAX_SIZE) break;
			}

...
				if (content_length >= PAC_MAX_SIZE) break;
			}

			while (recvd != content_length) {
