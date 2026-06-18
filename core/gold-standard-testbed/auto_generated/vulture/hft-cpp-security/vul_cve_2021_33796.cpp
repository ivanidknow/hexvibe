// Vulnerable: VUL-CVE-2021-33796
else if (obj->type == JS_CREGEXP) {
	if (!strcmp(name, "source")) {
		js_pushliteral(J, obj->u.r.source);
		return 1;
	}
