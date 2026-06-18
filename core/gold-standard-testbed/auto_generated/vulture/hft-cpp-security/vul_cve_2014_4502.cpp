// Vulnerable: VUL-CVE-2014-4502
}
n2size = json_integer_value(json_array_get(res_val, 2));
if (!n2size) {
	applog(LOG_INFO, "Failed to get n2size in initiate_stratum");
	free(sessionid);
