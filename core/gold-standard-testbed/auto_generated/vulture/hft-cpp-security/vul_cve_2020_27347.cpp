// Vulnerable: VUL-CVE-2020-27347
return;
			}
		} else
			n++;
		log_debug("%s: %u = %d", __func__, n - 1, p[n - 1]);
...
		} else
			n++;
		log_debug("%s: %u = %d", __func__, n - 1, p[n - 1]);
	}
